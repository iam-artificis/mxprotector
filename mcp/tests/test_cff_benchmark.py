"""Unit tests for benchmarks.cff_benchmark.

Tests instantiate ``CffMicrocodeBenchmark`` directly and monkey-patch
``build_protected`` + ``run_ida_script`` at the benchmark module to
bypass the real builder and IDA. The benchmark's registration with
the global registry is a side effect of import and not under test
here — the shared registry is covered in ``test_benchmark_base.py``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import cff_benchmark as cb
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.static.ida.runner import IdaNotFoundError, IdaRunResult


# ============================================================================
# Corpus helper
# ============================================================================


def _make_corpus(tmp_path: Path, entries: list[tuple[str, list[str]]]) -> Corpus:
    """``entries`` is a list of (name, tags)."""
    corpus_root = tmp_path / "corpus"
    bin_dir = corpus_root / "bin"
    bin_dir.mkdir(parents=True)
    manifest_entries = []
    for name, tags in entries:
        (bin_dir / f"{name}.exe").write_bytes(b"\x4d\x5a")
        manifest_entries.append({
            "name": name,
            "binary": f"bin/{name}.exe",
            "tags": tags,
        })
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": manifest_entries}),
        encoding="utf-8",
    )
    return Corpus.load(corpus_root)


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


# ============================================================================
# Mock factories
# ============================================================================


# Default synthetic sidecar data. ``cff.states[].source_bb_rva`` is
# what the benchmark filter matches against — a function survives if
# its byte range contains at least one of these. Defaults here align
# with ``_fn_metrics``'s default RVAs so the happy path keeps passing
# without per-test configuration.
_DEFAULT_CFF_RVA = 0x28000
_DEFAULT_CFF_SIZE = 0x1000
_DEFAULT_SOURCE_BB_RVAS: tuple[int, ...] = (0x1000, 0x2000)


def _ida_output(
    *,
    hexrays: bool = True,
    functions: list[dict] | None = None,
    errors: list[str] | None = None,
    image_base: int = 0,
) -> dict:
    return {
        "schema_version": 1,
        "hexrays_available": hexrays,
        "image_base": image_base,
        "functions": functions or [],
        "errors": errors or [],
    }


def _fn_metrics(name: str, ea: int, **kwargs) -> dict:
    # ``rva`` defaults to ``ea`` — when image_base is 0 (tests default)
    # they match and the function lands inside the wide default cff
    # range. Explicit override lets filter tests place functions
    # outside the window.
    defaults = {
        "ea": ea,
        "rva": ea,
        "name": name,
        "size": 64,
        "mba_maturity": "MMAT_GLBOPT3",
        "mc_blocks": 10,
        "mc_gotos": 2,
        "mc_edges": 15,
        "mc_backedges": 3,
        "mc_cyclomatic": 7,
        "mc_backedge_ratio": 0.2,
    }
    defaults.update(kwargs)
    return defaults


def _write_synthetic_sidecar(
    sidecar_path: Path,
    *,
    cff_rva: int = _DEFAULT_CFF_RVA,
    cff_size: int = _DEFAULT_CFF_SIZE,
    source_bb_rvas: tuple[int, ...] | list[int] | None = None,
    include_cff: bool = True,
) -> None:
    """Write a minimal pydantic-valid sidecar next to a protected output.

    ``include_cff=False`` omits the cff section entirely — exercises
    the "CFF disabled" error path when the builder ran without CFG
    flattening.

    ``source_bb_rvas`` populates ``cff.states[].source_bb_rva``. The
    benchmark filter keeps only IDA functions whose byte range covers
    at least one of these. ``None`` uses ``_DEFAULT_SOURCE_BB_RVAS``
    (matches default ``_fn_metrics`` RVAs). Pass an explicit empty
    list to simulate a partially-emitted sidecar with no states.
    """
    if source_bb_rvas is None:
        source_bb_rvas = _DEFAULT_SOURCE_BB_RVAS

    sections: dict = {}
    states: list[dict] = []
    if include_cff:
        sections["cff"] = {
            "name": ".cff_test",
            "rva": cff_rva,
            "size": cff_size,
            "characteristics": 0x60000020,
        }
        for i, rva in enumerate(source_bb_rvas):
            states.append({
                "id": i,
                "dispatcher_entry_rva": cff_rva + (i * 0x10),
                "source_bb_rva": int(rva),
                "kind": "original",
            })

    payload = {
        "schema_version": 1,
        "build": {
            "input": "in", "output": "out", "level": "strong",
            "timestamp": "2026-04-20T00:00:00Z",
        },
        "sections": sections,
        "cff": {"dispatcher_rva": cff_rva if include_cff else 0,
                "state_var_rva": 0,
                "states": states, "predicates": []},
        "vm":  {"dispatcher_rva": 0, "handler_table_rva": 0, "handlers": []},
        "guard":   {"regions": []},
        "strings": {"slots": []},
        "iat":     {"rva": 0, "size": 0},
    }
    sidecar_path.write_text(json.dumps(payload), encoding="utf-8")


def _install_mocks(
    monkeypatch,
    *,
    build_map: dict[str, ProtectedBuild | Exception] | None = None,
    ida_map: dict[str, IdaRunResult | Exception] | None = None,
    sidecar_cff_rva: int = _DEFAULT_CFF_RVA,
    sidecar_cff_size: int = _DEFAULT_CFF_SIZE,
    sidecar_source_bb_rvas: tuple[int, ...] | list[int] | None = None,
    sidecar_has_cff: bool = True,
    sidecar_omit: bool = False,
) -> dict:
    """Install monkey-patches keyed by corpus-entry name.

    Sidecar knobs:
      * ``sidecar_has_cff=False`` → omits the cff section (triggers
        the "CFF disabled" error path).
      * ``sidecar_source_bb_rvas=[]`` → section present but
        ``cff.states`` empty (triggers the "no flattened blocks" error).
      * ``sidecar_omit=True`` → ``ProtectedBuild.sidecar_path=None``
        (simulates a trace-hints-off build).
    """
    build_calls: list[Path] = []
    ida_calls: list[Path] = []

    async def fake_build(**kw):
        unprotected: Path = kw["unprotected"]
        output: Path = kw["output"]
        build_calls.append(unprotected)

        behaviour = (build_map or {}).get(unprotected.stem)
        if isinstance(behaviour, Exception):
            raise behaviour
        # Default: write a stub output file and return a ProtectedBuild.
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"\x4d\x5a")

        if behaviour is not None:
            return behaviour

        sidecar_path: Path | None = None
        if not sidecar_omit:
            sidecar_path = output.parent / f"{output.name}.mxtrace.json"
            _write_synthetic_sidecar(
                sidecar_path,
                cff_rva=sidecar_cff_rva,
                cff_size=sidecar_cff_size,
                source_bb_rvas=sidecar_source_bb_rvas,
                include_cff=sidecar_has_cff,
            )
        return ProtectedBuild(
            unprotected_binary=unprotected,
            protected_binary=output,
            sidecar_path=sidecar_path,
            duration_ms=1,
            stdout_tail="", stderr_tail="",
        )

    ida_env_calls: list[dict] = []

    async def fake_ida(*, binary, script, **kw):
        ida_calls.append(binary)
        # Capture the env var payload so tests can assert the benchmark
        # handed IDA the right CFF region.
        ida_env_calls.append(dict(kw.get("extra_env") or {}))
        # Map by the original entry name, recovered from the
        # protected path stem: "<entry>.mx".
        key = binary.stem.removesuffix(".mx")
        behaviour = (ida_map or {}).get(key)
        if isinstance(behaviour, Exception):
            raise behaviour
        if behaviour is not None:
            return behaviour
        # Default: one region record per call (what the production
        # ``cff_metrics.py`` emits in region mode).
        return IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _fn_metrics(
                    "cff_section",
                    ea=_DEFAULT_CFF_RVA, rva=_DEFAULT_CFF_RVA, size=_DEFAULT_CFF_SIZE,
                    mc_blocks=50, mc_gotos=12, mc_cyclomatic=18,
                    mc_backedge_ratio=0.25,
                ),
            ]),
            error=None,
        )

    monkeypatch.setattr(cb, "build_protected", fake_build)
    monkeypatch.setattr(cb, "run_ida_script", fake_ida)
    monkeypatch.setattr(cb, "resolve_builder_path", lambda root: root / "fake_builder.exe")

    return {
        "build_calls": build_calls,
        "ida_calls": ida_calls,
        "ida_env_calls": ida_env_calls,
    }


# ============================================================================
# Tests
# ============================================================================


def test_happy_path_emits_one_sample_per_corpus_entry(tmp_path: Path, monkeypatch):
    """Region mode: one CFF-section record per entry → one sample per
    metric per entry. Two cff-tagged entries → two samples per metric."""
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("beta",  ["cff"]),
    ])
    _install_mocks(monkeypatch)
    bench = cb.CffMicrocodeBenchmark()

    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.benchmark == "cff_microcode"
    assert result.category == "cff"
    assert result.tier == "fast"
    assert result.errors == []

    assert len(result.metrics) == 4
    for m in result.metrics:
        assert m.direction is MetricDirection.HIGHER_BETTER
        assert len(m.samples) == 2

    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"alpha::cff_section", "beta::cff_section"}


def test_untagged_entry_skipped(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("gamma", ["vm"]),   # not cff-tagged → filtered out.
    ])
    mocks = _install_mocks(monkeypatch)
    bench = cb.CffMicrocodeBenchmark()
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    # Only 'alpha' went through build + IDA.
    assert len(mocks["build_calls"]) == 1
    assert len(mocks["ida_calls"]) == 1


def test_no_cff_tagged_entries_reports_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("gamma", ["vm"])])
    _install_mocks(monkeypatch)
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no corpus entries tagged 'cff'" in e for e in result.errors)
    assert len(result.metrics) == 4
    for m in result.metrics:
        assert m.samples == []


def test_build_failure_propagates_as_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("beta",  ["cff"]),
    ])
    _install_mocks(
        monkeypatch,
        build_map={"alpha": BuilderError("exit=1: bad PE")},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    # alpha failed at build → no alpha samples; beta succeeded.
    assert any("alpha" in e and "build failed" in e for e in result.errors)
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert all(not n.startswith("alpha::") for n in sample_names)
    assert any(n.startswith("beta::") for n in sample_names)


def test_ida_failure_propagates_as_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=False, duration_ms=1, stdout_tail="", stderr_tail="",
            output=None, error="IDA exit=2",
        )},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("alpha" in e and "IDA" in e for e in result.errors)
    # No samples emitted.
    for m in result.metrics:
        assert m.samples == []


def test_ida_not_installed_surfaces_clean_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaNotFoundError("no idat64.exe")},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("IDA missing" in e for e in result.errors)


def test_hexrays_unavailable_flagged(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(hexrays=False),
            error=None,
        )},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("Hex-Rays not available" in e for e in result.errors)


def test_metric_values_match_ida_output(tmp_path: Path, monkeypatch):
    """The benchmark passes every ``mc_*`` field through unchanged
    and attaches ``ea`` / ``rva`` / ``mba_maturity`` evidence for
    post-mortem."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _fn_metrics(
                    "cff_section",
                    ea=_DEFAULT_CFF_RVA, rva=_DEFAULT_CFF_RVA,
                    size=_DEFAULT_CFF_SIZE,
                    mc_blocks=42, mc_gotos=7, mc_cyclomatic=19,
                    mc_backedge_ratio=0.33,
                ),
            ]),
            error=None,
        )},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert by_name["mc_blocks"].samples[0].value == 42
    assert by_name["mc_gotos"].samples[0].value == 7
    assert by_name["mc_cyclomatic"].samples[0].value == 19
    assert abs(by_name["mc_backedge_ratio"].samples[0].value - 0.33) < 1e-9

    ev = by_name["mc_blocks"].samples[0].evidence
    assert ev["ea"] == _DEFAULT_CFF_RVA
    assert ev["mba_maturity"] == "MMAT_GLBOPT3"


# ============================================================================
# Region-mode integration — CFF section handed to IDA via env var, and
# every error path surfaces cleanly.
# ============================================================================


def test_cff_region_passed_to_ida_via_env(tmp_path: Path, monkeypatch):
    """The benchmark hands IDA exactly one region — the sidecar's
    ``sections.cff`` entry, JSON-encoded in ``MX_MCP_IDA_REGIONS``.
    This is the single explicit contract between the benchmark and the
    IDAPython script; regressions here silently break the signal, so
    the test is direct."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    mocks = _install_mocks(
        monkeypatch,
        sidecar_cff_rva=0x28000, sidecar_cff_size=0xDB0,
    )
    bench = cb.CffMicrocodeBenchmark()
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert len(mocks["ida_env_calls"]) == 1
    env = mocks["ida_env_calls"][0]
    assert "MX_MCP_IDA_REGIONS" in env
    regions = json.loads(env["MX_MCP_IDA_REGIONS"])
    assert regions == [{"name": "cff_section", "rva": 0x28000, "size": 0xDB0}]


def test_sidecar_missing_cff_section_errors_entry(tmp_path: Path, monkeypatch):
    """Builder ran with ``--no-cfg-flattening`` — no cff section in
    sidecar. Entry errored rather than silently producing nonsense."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_has_cff=False)
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no (non-empty) 'cff' section" in e or "CFF disabled" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_zero_size_cff_section_errors_entry(tmp_path: Path, monkeypatch):
    """``sections.cff`` with ``size == 0`` is effectively CFF-disabled —
    an empty section carries no dispatcher code to measure."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_cff_size=0)
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("non-empty" in e or "CFF disabled" in e for e in result.errors)


def test_missing_sidecar_errors_entry(tmp_path: Path, monkeypatch):
    """Build emitted no sidecar (trace_hints off, or a regression).
    The benchmark cannot determine the CFF section without it."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_omit=True)
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("no sidecar" in e.lower() or "trace-hints" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_ida_returns_no_records_errors_entry(tmp_path: Path, monkeypatch):
    """IDA ran cleanly but produced zero region records — typical
    smell for encrypted bytes (packer still enabled upstream) or an
    invalid range. Reported loudly rather than falling to zero samples."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[]),  # empty
            error=None,
        )},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no blocks" in e or "encrypted" in e or "invalid" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_ida_region_level_errors_surfaced(tmp_path: Path, monkeypatch):
    """IDA can report per-region errors (e.g. ``gen_microcode``
    failed on some range). The benchmark forwards these with an
    ``ida-region:`` prefix while still aggregating any successful
    records."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(
                functions=[_fn_metrics(
                    "cff_section",
                    ea=_DEFAULT_CFF_RVA, rva=_DEFAULT_CFF_RVA,
                    size=_DEFAULT_CFF_SIZE, mc_blocks=40,
                )],
                errors=["region cff_section: partial decoding failure"],
            ),
            error=None,
        )},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("ida-region" in e for e in result.errors)
    # Successful record still produces a sample.
    assert len(result.metrics[0].samples) == 1
