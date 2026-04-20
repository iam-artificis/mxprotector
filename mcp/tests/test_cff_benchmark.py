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


def _ida_output(
    *,
    hexrays: bool = True,
    functions: list[dict] | None = None,
    errors: list[str] | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "hexrays_available": hexrays,
        "functions": functions or [],
        "errors": errors or [],
    }


def _fn_metrics(name: str, ea: int, **kwargs) -> dict:
    defaults = {
        "ea": ea,
        "name": name,
        "size": 64,
        "mc_blocks": 10,
        "mc_gotos": 2,
        "mc_edges": 15,
        "mc_backedges": 3,
        "mc_cyclomatic": 7,
        "mc_backedge_ratio": 0.2,
    }
    defaults.update(kwargs)
    return defaults


def _install_mocks(
    monkeypatch,
    *,
    build_map: dict[str, ProtectedBuild | Exception] | None = None,
    ida_map: dict[str, IdaRunResult | Exception] | None = None,
) -> dict:
    """Install monkey-patches keyed by corpus-entry name.

    Keeps the per-entry behaviour explicit — happy-path for one entry,
    failure for another — which matches how error paths matter here.
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
        return behaviour or ProtectedBuild(
            unprotected_binary=unprotected,
            protected_binary=output,
            sidecar_path=None,
            duration_ms=1,
            stdout_tail="", stderr_tail="",
        )

    async def fake_ida(*, binary, script, **kw):
        ida_calls.append(binary)
        # Map by the original entry name, recovered from the
        # protected path stem: "<entry>.mx".
        key = binary.stem.removesuffix(".mx")
        behaviour = (ida_map or {}).get(key)
        if isinstance(behaviour, Exception):
            raise behaviour
        if behaviour is not None:
            return behaviour
        return IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _fn_metrics("main", 0x1000),
                _fn_metrics("core", 0x2000, mc_blocks=20, mc_gotos=5),
            ]),
            error=None,
        )

    monkeypatch.setattr(cb, "build_protected", fake_build)
    monkeypatch.setattr(cb, "run_ida_script", fake_ida)
    monkeypatch.setattr(cb, "resolve_builder_path", lambda root: root / "fake_builder.exe")

    return {"build_calls": build_calls, "ida_calls": ida_calls}


# ============================================================================
# Tests
# ============================================================================


def test_happy_path_emits_per_function_samples(tmp_path: Path, monkeypatch):
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

    # 4 metrics × 4 samples (2 entries × 2 functions each).
    assert len(result.metrics) == 4
    for m in result.metrics:
        assert m.direction is MetricDirection.HIGHER_BETTER
        assert len(m.samples) == 4

    # Sample names look like "{entry}::{fn_name}".
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {
        "alpha::main", "alpha::core", "beta::main", "beta::core",
    }


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


def test_ida_function_level_errors_surfaced(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(
                functions=[_fn_metrics("main", 0x1000)],
                errors=["sub_DEAD: DecompilationFailure: stack broken"],
            ),
            error=None,
        )},
    )
    bench = cb.CffMicrocodeBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("DecompilationFailure" in e for e in result.errors)
    # Successful functions still counted.
    assert len(result.metrics[0].samples) == 1


def test_metric_values_match_ida_output(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["cff"])])
    _install_mocks(
        monkeypatch,
        ida_map={"alpha": IdaRunResult(
            ok=True, duration_ms=1, stdout_tail="", stderr_tail="",
            output=_ida_output(functions=[
                _fn_metrics(
                    "main", 0x1000,
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

    # Evidence carries the EA + function size for post-mortem.
    ev = by_name["mc_blocks"].samples[0].evidence
    assert ev["ea"] == 0x1000
