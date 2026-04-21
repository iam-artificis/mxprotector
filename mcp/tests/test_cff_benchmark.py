"""Unit tests for benchmarks.cff_benchmark.

The benchmark now depends on three backends that would each hit
real tooling without mocks:

* ``ensure_protected``  — builds a protected artefact.
* ``run_ida_script``    — runs IDA on the protected artefact.
* baseline cache        — runs IDA on the unprotected source.

All three are replaced with stubs: the first two via
``monkeypatch`` on the benchmark module, and the baseline cache via
constructor injection of a :class:`CfgBaselineCache` wrapping a
local stub provider. The resulting tests are hermetic and run on
hosts without IDA installed.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import cff_benchmark as cb
from mx_mcp.common.baseline import (
    BaselineError,
    CfgBaseline,
    CfgBaselineCache,
)
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.static.ida.runner import IdaNotFoundError, IdaRunResult


# ============================================================================
# Corpus + session helpers
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
# Baseline stub
# ============================================================================


# Default baseline totals — chosen so the default protected values
# (mc_blocks=50 / mc_cyclomatic=18 / mc_gotos=12 emitted by the
# default fake IDA mock) produce ratios that sit visibly below 1.0.
# That matches the real-world shape where a single CFF region's
# microcode is smaller than the aggregate of every unprotected
# function — the benchmark asserts the *direction* of change, not
# a fixed absolute.
_DEFAULT_BASELINE_BLOCKS = 200
_DEFAULT_BASELINE_CYC = 100
_DEFAULT_BASELINE_GOTOS = 20
_DEFAULT_BASELINE_FNS = 30
_DEFAULT_BASELINE_BYTES = 2048
_DEFAULT_BASELINE_TEXT = 4096


class _StubBaselineProvider:
    """Returns the configured :class:`CfgBaseline` per binary.

    ``overrides`` lets tests raise a :class:`BaselineError` or
    customise totals for a specific corpus entry — keyed by the
    unprotected binary's stem.
    """

    def __init__(
        self,
        *,
        blocks: int = _DEFAULT_BASELINE_BLOCKS,
        cyc: int = _DEFAULT_BASELINE_CYC,
        gotos: int = _DEFAULT_BASELINE_GOTOS,
        fn_count: int = _DEFAULT_BASELINE_FNS,
        fn_bytes: int = _DEFAULT_BASELINE_BYTES,
        text_size: int = _DEFAULT_BASELINE_TEXT,
        overrides: dict[str, CfgBaseline | Exception] | None = None,
    ) -> None:
        self.calls: list[tuple[Path, frozenset[int] | None]] = []
        self._blocks = blocks
        self._cyc = cyc
        self._gotos = gotos
        self._fn_count = fn_count
        self._fn_bytes = fn_bytes
        self._text_size = text_size
        self._overrides = overrides or {}

    async def measure(
        self,
        binary: Path,
        *,
        filter_rvas: frozenset[int] | None = None,
    ) -> CfgBaseline:
        self.calls.append((binary, filter_rvas))
        override = self._overrides.get(binary.stem)
        if isinstance(override, Exception):
            raise override
        if isinstance(override, CfgBaseline):
            return override
        return CfgBaseline(
            binary_path=binary,
            function_count=self._fn_count,
            total_blocks=self._blocks,
            total_cyclomatic=self._cyc,
            total_gotos=self._gotos,
            functions_total_bytes=self._fn_bytes,
            text_section_size=self._text_size,
            filter_rvas=filter_rvas,
        )


def _build_stub_cache(
    **kwargs,
) -> tuple[CfgBaselineCache, _StubBaselineProvider]:
    provider = _StubBaselineProvider(**kwargs)
    return CfgBaselineCache(provider), provider


# ============================================================================
# Mock factories (protected build + IDA on protected)
# ============================================================================


_DEFAULT_CFF_RVA = 0x28000
_DEFAULT_CFF_SIZE = 0x1000


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


def _region_record(
    name: str = "cff_section",
    *,
    ea: int = _DEFAULT_CFF_RVA,
    rva: int = _DEFAULT_CFF_RVA,
    size: int = _DEFAULT_CFF_SIZE,
    mc_blocks: int = 50,
    mc_gotos: int = 12,
    mc_edges: int = 80,
    mc_backedges: int = 20,
    mc_cyclomatic: int = 18,
    mba_maturity: str = "MMAT_GLBOPT3",
) -> dict:
    return {
        "ea": ea, "rva": rva, "name": name, "size": size,
        "mba_maturity": mba_maturity,
        "record_type": "region",
        "mc_blocks": mc_blocks, "mc_gotos": mc_gotos,
        "mc_edges": mc_edges, "mc_backedges": mc_backedges,
        "mc_cyclomatic": mc_cyclomatic,
        "mc_backedge_ratio": (mc_backedges / mc_edges) if mc_edges else 0.0,
    }


def _function_record(
    name: str = "stub",
    *,
    ea: int = 0x1500,
    rva: int = 0x1500,
    size: int = 16,
    mc_blocks: int = 2,
    mc_gotos: int = 1,
    mc_edges: int = 2,
    mc_backedges: int = 0,
    mc_cyclomatic: int = 2,
    mba_maturity: str = "MMAT_GLBOPT3",
) -> dict:
    """Protected-side per-function record — small trampoline stub or
    in-place flattened body. Defaults model a trivial trampoline (1
    jmp block)."""
    return {
        "ea": ea, "rva": rva, "name": name, "size": size,
        "mba_maturity": mba_maturity,
        "record_type": "function",
        "mc_blocks": mc_blocks, "mc_gotos": mc_gotos,
        "mc_edges": mc_edges, "mc_backedges": mc_backedges,
        "mc_cyclomatic": mc_cyclomatic,
        "mc_backedge_ratio": (mc_backedges / mc_edges) if mc_edges else 0.0,
    }


_DEFAULT_PROTECTED_RVAS: tuple[int, ...] = (0x1500, 0x1800)


def _write_synthetic_sidecar(
    sidecar_path: Path,
    *,
    cff_rva: int = _DEFAULT_CFF_RVA,
    cff_size: int = _DEFAULT_CFF_SIZE,
    include_cff: bool = True,
    protected_rvas: tuple[int, ...] | list[int] | None = None,
    protected_kind: str = "cff",
) -> None:
    """Write a pydantic-valid sidecar.

    ``protected_rvas=None`` uses the default tuple ``(0x1500, 0x1800)``;
    pass an explicit empty tuple to simulate a build with no protected
    functions emitted (exercises the "no filter source" error path).
    """
    sections: dict = {}
    if include_cff:
        sections["cff"] = {
            "name": ".cff_test",
            "rva": cff_rva,
            "size": cff_size,
            "characteristics": 0x60000020,
        }

    if protected_rvas is None:
        protected_rvas = _DEFAULT_PROTECTED_RVAS
    protected_entries = [
        {"rva": int(r), "size": 256, "kind": protected_kind}
        for r in protected_rvas
    ]

    payload = {
        "schema_version": 1,
        "build": {
            "input": "in", "output": "out", "level": "strong",
            "timestamp": "2026-04-20T00:00:00Z",
        },
        "sections": sections,
        "cff": {"dispatcher_rva": cff_rva if include_cff else 0,
                "state_var_rva": 0,
                "states": [], "predicates": []},
        "vm":  {"dispatcher_rva": 0, "handler_table_rva": 0, "handlers": []},
        "guard":   {"regions": []},
        "strings": {"slots": []},
        "iat":     {"rva": 0, "size": 0},
        "protected_functions": protected_entries,
    }
    sidecar_path.write_text(json.dumps(payload), encoding="utf-8")


def _install_mocks(
    monkeypatch,
    *,
    build_map: dict[str, ProtectedBuild | Exception] | None = None,
    ida_map: dict[str, IdaRunResult | Exception] | None = None,
    sidecar_cff_rva: int = _DEFAULT_CFF_RVA,
    sidecar_cff_size: int = _DEFAULT_CFF_SIZE,
    sidecar_has_cff: bool = True,
    sidecar_omit: bool = False,
    sidecar_protected_rvas: tuple[int, ...] | list[int] | None = None,
) -> dict:
    build_calls: list[Path] = []
    ida_calls: list[Path] = []
    ida_env_calls: list[dict] = []

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        output = output_dir / f"{entry.name}.mx.exe"
        source_binary = entry.unprotected_binary or entry.pre_protected_binary
        build_calls.append(source_binary)

        behaviour = (build_map or {}).get(entry.name)
        if isinstance(behaviour, Exception):
            raise behaviour
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
                include_cff=sidecar_has_cff,
                protected_rvas=sidecar_protected_rvas,
            )
        return ProtectedBuild(
            unprotected_binary=source_binary,
            protected_binary=output,
            sidecar_path=sidecar_path,
            duration_ms=1,
            stdout_tail="", stderr_tail="",
        )

    async def fake_ida(*, binary, script, **kw):
        ida_calls.append(binary)
        ida_env_calls.append(dict(kw.get("extra_env") or {}))
        key = binary.stem.removesuffix(".mx")
        behaviour = (ida_map or {}).get(key)
        if isinstance(behaviour, Exception):
            raise behaviour
        if behaviour is not None:
            return behaviour
        # Default: dual-mode output — region record (the .cff section
        # dispatcher) plus one per-function trampoline record for each
        # protected RVA. Mirrors the production script's behaviour when
        # both MX_MCP_IDA_REGIONS and MX_MCP_IDA_FUNCTION_FILTER are
        # set (see cff_metrics.py dual-mode branch).
        records: list[dict] = [_region_record()]
        for i, rva in enumerate(_DEFAULT_PROTECTED_RVAS):
            records.append(_function_record(
                name=f"stub_{i}", ea=rva, rva=rva,
            ))
        return IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=records),
            error=None,
        )

    monkeypatch.setattr(cb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(cb, "run_ida_script", fake_ida)
    monkeypatch.setattr(cb, "resolve_builder_path", lambda root: root / "fake_builder.exe")

    return {
        "build_calls": build_calls,
        "ida_calls": ida_calls,
        "ida_env_calls": ida_env_calls,
    }


# ============================================================================
# Happy-path shape
# ============================================================================


def test_happy_path_emits_one_sample_per_corpus_entry(tmp_path, monkeypatch):
    """Dual-mode IDA (per-function + region) on protected side +
    filtered baseline → one sample per metric per entry. Five metrics:
    three amplifications, one absolute backedge ratio, one coverage."""
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("beta",  ["cff"]),
    ])
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)

    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.benchmark == "cff_microcode"
    assert result.category == "cff"
    assert result.tier == "fast"
    assert result.errors == []

    assert len(result.metrics) == 5
    metric_names = {m.name for m in result.metrics}
    assert metric_names == {
        "mc_blocks_amplification",
        "mc_cyclomatic_amplification",
        "mc_gotos_amplification",
        "mc_backedge_ratio",
        "cff_coverage",
    }
    for m in result.metrics:
        assert m.direction is MetricDirection.HIGHER_BETTER
        assert len(m.samples) == 2

    first_metric_samples = {s.sample_name for s in result.metrics[0].samples}
    assert first_metric_samples == {"alpha", "beta"}


def test_amplification_ratios_match_protected_over_filtered_baseline(
    tmp_path, monkeypatch,
):
    """Protected total (region + function records) divided by filtered
    baseline must produce the declared amplification.

    Setup:
      * baseline_filtered (stub default): blocks=200, cyc=100, gotos=20
      * baseline_total    (stub default): same numbers (stub doesn't
        vary by filter — tests assert the ratio math, not the
        filtering mechanics)
      * protected region: blocks=380, cyc=90, gotos=76
      * protected function stub: blocks=20, cyc=10, gotos=4
      → protected total: blocks=400, cyc=100, gotos=80
      → mc_blocks_amplification   = 400/200 = 2.0
      → mc_cyclomatic_amplification = 100/100 = 1.0
      → mc_gotos_amplification      = 80/20  = 4.0
      → mc_backedge_ratio = 18/60 = 0.30 (region only, edge-weighted)
      → cff_coverage = 200/200 = 1.0
    """
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _region_record(
                    mc_blocks=380, mc_cyclomatic=90, mc_gotos=76,
                    mc_edges=60, mc_backedges=18,
                ),
                _function_record(
                    name="stub_0", ea=0x1500, rva=0x1500,
                    mc_blocks=20, mc_cyclomatic=10, mc_gotos=4,
                    mc_edges=4, mc_backedges=0,
                ),
            ]),
            error=None,
        )},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert by_name["mc_blocks_amplification"].samples[0].value == 2.0
    assert by_name["mc_cyclomatic_amplification"].samples[0].value == 1.0
    assert by_name["mc_gotos_amplification"].samples[0].value == 4.0
    # Backedge ratio uses region records only (dispatcher IS the CFG
    # that matters for irreducibility). Stub function trivially 0/4.
    assert abs(
        by_name["mc_backedge_ratio"].samples[0].value - 0.30
    ) < 1e-9
    # Coverage: filtered baseline / total baseline. Stub returns same
    # values regardless of filter → 1.0.
    assert by_name["cff_coverage"].samples[0].value == 1.0


def test_evidence_carries_raw_numerator_and_denominator(tmp_path, monkeypatch):
    """Evidence must preserve raw counts on both sides plus the split
    between .text (function records) and .cff (region records)."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _region_record(mc_blocks=77, mc_cyclomatic=33, mc_gotos=11),
                _function_record(
                    name="stub", ea=0x1500, rva=0x1500,
                    mc_blocks=3, mc_cyclomatic=2, mc_gotos=1,
                ),
            ]),
            error=None,
        )},
    )
    cache, _ = _build_stub_cache(blocks=150, cyc=60, gotos=10, fn_count=7)
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    ev = result.metrics[0].samples[0].evidence
    # Totals = region + function sums.
    assert ev["protected_blocks_total"] == 80        # 77 + 3
    assert ev["protected_blocks_in_cff"] == 77
    assert ev["protected_blocks_in_text"] == 3
    assert ev["protected_cyclomatic_total"] == 35    # 33 + 2
    assert ev["protected_gotos_total"] == 12         # 11 + 1
    # Filtered baseline totals (stub returns configured values).
    assert ev["baseline_filtered_blocks"] == 150
    assert ev["baseline_filtered_cyclomatic"] == 60
    assert ev["baseline_filtered_gotos"] == 10
    assert ev["baseline_filtered_functions"] == 7
    # Record counts describe the IDA output shape.
    assert ev["protected_region_records"] == 1
    assert ev["protected_function_records"] == 1
    # Filter RVA count = number of protected_functions entries emitted
    # by the synthetic sidecar (default: 2 entries).
    assert ev["filter_rva_count"] == 2


def test_multi_region_records_aggregate_into_one_sample(tmp_path, monkeypatch):
    """Future-proofing: multi-region output (rare today but plausible
    if a dispatcher splits across sections) sums all numerators into
    one amplification per entry."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _region_record(mc_blocks=100, mc_cyclomatic=40, mc_gotos=8,
                               mc_edges=30, mc_backedges=6),
                _region_record(name="cff_section_b",
                               mc_blocks=50, mc_cyclomatic=20, mc_gotos=4,
                               mc_edges=20, mc_backedges=4),
            ]),
            error=None,
        )},
    )
    cache, _ = _build_stub_cache(blocks=100, cyc=60, gotos=6)
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    # Total protected: 150 blocks, 60 cyc, 12 gotos, 50 edges, 10 backedges.
    # No function records → protected total = region total.
    assert by_name["mc_blocks_amplification"].samples[0].value == 1.5
    assert by_name["mc_cyclomatic_amplification"].samples[0].value == 1.0
    assert by_name["mc_gotos_amplification"].samples[0].value == 2.0
    assert abs(
        by_name["mc_backedge_ratio"].samples[0].value - (10 / 50)
    ) < 1e-9
    assert result.metrics[0].samples[0].evidence[
        "protected_region_records"
    ] == 2
    assert result.metrics[0].samples[0].evidence[
        "protected_function_records"
    ] == 0


# ============================================================================
# Corpus filtering
# ============================================================================


def test_untagged_entry_skipped(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("gamma", ["vm"]),  # not cff-tagged → filtered out
    ])
    mocks = _install_mocks(monkeypatch)
    cache, provider = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert len(mocks["build_calls"]) == 1
    assert len(mocks["ida_calls"]) == 1
    # Two baseline calls per processed entry (filtered + total).
    assert len(provider.calls) == 2


def test_no_cff_tagged_entries_reports_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("gamma", ["vm"])])
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("no corpus entries tagged 'cff'" in e for e in result.errors)
    assert len(result.metrics) == 5
    for m in result.metrics:
        assert m.samples == []


# ============================================================================
# Failure modes — each terminal path reports exactly one error + no samples
# ============================================================================


def test_build_failure_propagates_as_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("beta",  ["cff"]),
    ])
    _install_mocks(
        monkeypatch,
        build_map={"alpha": BuilderError("exit=1: bad PE")},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("alpha" in e and "build failed" in e for e in result.errors)
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert "alpha" not in sample_names
    assert "beta" in sample_names


def test_ida_failure_propagates_as_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=False, duration_ms=1, stdout_tail="", stderr_tail="",
            output=None, error="IDA exit=2",
        )},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("alpha" in e and "IDA" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_ida_not_installed_surfaces_clean_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaNotFoundError("no idat64.exe")},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("IDA missing" in e for e in result.errors)


def test_hexrays_unavailable_flagged(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(hexrays=False),
            error=None,
        )},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("Hex-Rays not available" in e for e in result.errors)


def test_baseline_measurement_failure_aborts_entry(tmp_path, monkeypatch):
    """A baseline that fails measurement cannot produce amplification
    ratios — the entry must error, not silently emit ``None`` samples."""
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("beta",  ["cff"]),
    ])
    _install_mocks(monkeypatch)

    cache, _ = _build_stub_cache(overrides={
        "alpha": BaselineError("IDA died on baseline"),
    })
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "alpha" in e and "baseline measurement failed" in e
        for e in result.errors
    )
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"beta"}


def test_pre_protected_entry_errors_with_no_baseline_explanation(
    tmp_path, monkeypatch,
):
    """Pre-protected (legacy) entries have no unprotected source — the
    benchmark explicitly refuses to score them rather than producing
    meaningless absolute values."""
    corpus_root = tmp_path / "corpus"
    bin_dir = corpus_root / "bin"
    bin_dir.mkdir(parents=True)
    pre = bin_dir / "legacy.exe"
    pre.write_bytes(b"\x4d\x5a")

    (corpus_root / "corpus.json").write_text(json.dumps({
        "schema_version": 1,
        "entries": [{
            "name": "legacy",
            "pre_protected": "bin/legacy.exe",
            "tags": ["cff"],
        }],
    }), encoding="utf-8")

    corpus = Corpus.load(corpus_root)
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "legacy" in e and "pre-protected" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


# ============================================================================
# Sidecar / section contracts
# ============================================================================


def test_cff_region_and_function_filter_passed_to_ida_via_env(
    tmp_path, monkeypatch,
):
    """Dual-mode IDA contract: both ``MX_MCP_IDA_REGIONS`` (for the
    .cff dispatcher) and ``MX_MCP_IDA_FUNCTION_FILTER`` (for the
    filtered per-function records) must be set in one call."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    mocks = _install_mocks(
        monkeypatch,
        sidecar_cff_rva=0x28000, sidecar_cff_size=0xDB0,
        sidecar_protected_rvas=(0x1500, 0x1800, 0x2000),
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert len(mocks["ida_env_calls"]) == 1
    env = mocks["ida_env_calls"][0]
    assert "MX_MCP_IDA_REGIONS" in env
    regions = json.loads(env["MX_MCP_IDA_REGIONS"])
    assert regions == [{"name": "cff_section", "rva": 0x28000, "size": 0xDB0}]
    # Function filter — sorted RVAs from sidecar protected_functions.
    assert "MX_MCP_IDA_FUNCTION_FILTER" in env
    filter_payload = json.loads(env["MX_MCP_IDA_FUNCTION_FILTER"])
    assert filter_payload == [0x1500, 0x1800, 0x2000]


def test_sidecar_missing_cff_section_errors_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_has_cff=False)
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no (non-empty) 'cff' section" in e or "CFF disabled" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_zero_size_cff_section_errors_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_cff_size=0)
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("non-empty" in e or "CFF disabled" in e for e in result.errors)


def test_missing_sidecar_errors_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_omit=True)
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("no sidecar" in e.lower() or "trace-hints" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_ida_returns_no_region_records_errors_entry(tmp_path, monkeypatch):
    """Region records are mandatory — they measure the .cff dispatcher
    which is the whole point. Empty region output means IDA couldn't
    lift the section (encrypted bytes, invalid range)."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _function_record(name="stub", ea=0x1500, rva=0x1500),
            ]),  # function records but no region records
            error=None,
        )},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no blocks" in e or "encrypted" in e or "invalid" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_ida_region_level_errors_surfaced(tmp_path, monkeypatch):
    """IDA can report per-region errors alongside successful records.
    The benchmark forwards these with an ``ida-region:`` prefix while
    still aggregating any successful records."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(
                functions=[_region_record(mc_blocks=40)],
                errors=["region cff_section: partial decoding failure"],
            ),
            error=None,
        )},
    )
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("ida-region" in e for e in result.errors)
    assert len(result.metrics[0].samples) == 1


# ============================================================================
# Cache behaviour at the integration level
# ============================================================================


def test_empty_protected_functions_errors_entry(tmp_path, monkeypatch):
    """A sidecar with no cff-kind entries in ``protected_functions``
    has no filter source — the benchmark cannot compute amplification
    against unknowns. Errors cleanly."""
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(monkeypatch, sidecar_protected_rvas=())
    cache, _ = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no cff-kind entries in protected_functions" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_baseline_cache_reused_across_entries_in_one_run(tmp_path, monkeypatch):
    """Two distinct corpus entries share one baseline cache — the
    provider sees each unprotected binary exactly once."""
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["cff"]),
        ("beta",  ["cff"]),
    ])
    _install_mocks(monkeypatch)
    cache, provider = _build_stub_cache()
    bench = cb.CffMicrocodeBenchmark(baseline_cache=cache)
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    # Two entries × two calls each (filtered + total) = 4 calls.
    assert len(provider.calls) == 4
    # Each baseline is one of the two distinct binaries.
    assert len({call[0].stem for call in provider.calls}) == 2


def test_default_baseline_cache_created_when_none_injected():
    """The registry calls ``cls()`` without kwargs — a real cache
    must be lazy-created on first ``run`` without crashing."""
    bench = cb.CffMicrocodeBenchmark()
    cache = bench._resolve_baseline_cache()
    # Second call returns the same instance (lazy-cached).
    assert bench._resolve_baseline_cache() is cache
