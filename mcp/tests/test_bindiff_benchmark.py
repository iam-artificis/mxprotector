"""Unit tests for benchmarks.bindiff_benchmark.

Mocks every external dependency (``ensure_protected``, ``run_binexport``,
``run_bindiff``) at the benchmark module level so tests are hermetic.
Covers the full matrix of per-entry failure modes the runner can
produce plus the happy path and tag-filter semantics.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import bindiff_benchmark as bb
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.diffing.bindiff.binexport_runner import BinExportResult
from mx_mcp.diffing.bindiff.bindiff_runner import BinDiffRunResult
from mx_mcp.diffing.bindiff.report import (
    BinDiffReport,
    ResultsStats,
    StdoutSummary,
)


# ============================================================================
# Helpers
# ============================================================================


def _make_corpus(tmp_path: Path, entries: list[dict]) -> Corpus:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    for spec in entries:
        for key in ("binary", "pre_protected", "pre_sidecar"):
            if key in spec:
                p = corpus_root / spec[key]
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_bytes(b"\x4d\x5a")
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return Corpus.load(corpus_root)


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


def _make_report(
    *, similarity: float = 0.6,
    confidence: float = 0.9,
    matched: int = 100, primary: int = 120, secondary: int = 130,
) -> BinDiffReport:
    """Fabricate a parsed BinDiffReport for the mock to return."""
    return BinDiffReport(
        stdout=StdoutSummary(
            similarity=similarity,
            confidence=confidence,
            matched_functions=matched,
            primary_functions=primary,
            secondary_functions=secondary,
        ),
        results=ResultsStats(),
    )


def _ok_bindiff_result(**kwargs) -> BinDiffRunResult:
    return BinDiffRunResult(
        ok=True, duration_ms=100,
        report=_make_report(**kwargs),
    )


def _ok_binexport_result(path: Path) -> BinExportResult:
    return BinExportResult(
        ok=True, duration_ms=50, output_path=path,
    )


def _ok_protected_build(path: Path) -> ProtectedBuild:
    return ProtectedBuild(
        unprotected_binary=path,
        protected_binary=path,
        sidecar_path=None,
        duration_ms=1,
        stdout_tail="", stderr_tail="",
    )


def _install_mocks(
    monkeypatch,
    *,
    build_fail_on: set[str] | None = None,
    binexport_fail_on: set[str] | None = None,
    bindiff_fail_on: set[str] | None = None,
    bindiff_result_factory=None,
) -> dict:
    """Install full-pipeline mocks for ensure_protected, run_binexport,
    run_bindiff.

    ``build_fail_on`` is keyed by ``{entry.name}_a|b`` — specifies
    that a particular label's build should fail. Same idea for the
    other two maps. ``bindiff_result_factory`` is a callable
    ``(entry_name) -> BinDiffRunResult`` used when the pair is
    expected to succeed; defaults to similarity=0.6.
    """
    build_fail_on = build_fail_on or set()
    binexport_fail_on = binexport_fail_on or set()
    bindiff_fail_on = bindiff_fail_on or set()
    build_calls: list[tuple[str, str]] = []
    binexport_calls: list[Path] = []
    bindiff_calls: list[tuple[Path, Path]] = []

    async def fake_ensure(entry, *, output_dir: Path, **kw):
        # Each invocation of ensure_protected is for one label — we
        # derive the label from which output_dir we got ("build_a" /
        # "build_b" inside the benchmark's temp).
        label = output_dir.name.removeprefix("build_")
        build_calls.append((entry.name, label))
        key = f"{entry.name}_{label}"
        if key in build_fail_on:
            raise BuilderError(f"inject fail on {key}")
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / f"{entry.name}.mx.exe"
        out.write_bytes(b"MZ")
        return _ok_protected_build(out)

    async def fake_binexport(binary: Path, output_path: Path, **kw):
        binexport_calls.append(binary)
        # Label from binary stem: "{entry.name}.mx"
        entry_name = binary.stem.removesuffix(".mx")
        # Actually, the benchmark uses ``output_dir / "build_a" /
        # "<entry>.mx.exe"`` — derive label from the parent dir.
        label = binary.parent.name.removeprefix("build_")
        key = f"{entry_name}_{label}"
        if key in binexport_fail_on:
            return BinExportResult(
                ok=False, duration_ms=1, output_path=None,
                error=f"inject binexport fail on {key}",
            )
        # Fabricate the output file so the benchmark's
        # ok_binexport_result.output_path returns a real path.
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"binexport stub")
        return _ok_binexport_result(output_path)

    async def fake_bindiff(*, primary: Path, secondary: Path, output_dir: Path, **kw):
        bindiff_calls.append((primary, secondary))
        # Determine entry name from primary stem: "<entry>_a"
        entry_name = primary.stem.rsplit("_", 1)[0]
        if entry_name in bindiff_fail_on:
            return BinDiffRunResult(
                ok=False, duration_ms=1, report=None,
                error=f"inject bindiff fail on {entry_name}",
            )
        if bindiff_result_factory is not None:
            return bindiff_result_factory(entry_name)
        return _ok_bindiff_result()

    monkeypatch.setattr(bb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(bb, "run_binexport", fake_binexport)
    monkeypatch.setattr(bb, "run_bindiff", fake_bindiff)
    monkeypatch.setattr(
        bb, "resolve_builder_path",
        lambda root: root / "fake_builder.exe",
    )
    return {
        "build_calls": build_calls,
        "binexport_calls": binexport_calls,
        "bindiff_calls": bindiff_calls,
    }


# ============================================================================
# Happy path
# ============================================================================


def test_happy_path_single_entry_emits_both_metrics(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch)
    bench = bb.BinDiffBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.benchmark == "bindiff_resistance"
    assert result.category == "diffing"
    assert result.tier == "slow"
    assert result.errors == []

    # Two metrics, both LOWER_BETTER.
    assert len(result.metrics) == 2
    for m in result.metrics:
        assert m.direction is MetricDirection.LOWER_BETTER
        assert len(m.samples) == 1
    by_name = {m.name: m for m in result.metrics}
    assert by_name["bindiff_similarity"].samples[0].value == 0.6
    # 100 / ((120 + 130) / 2) = 100 / 125 = 0.8
    assert by_name["bindiff_function_match_ratio"].samples[0].value == 0.8

    # Pipeline fired as expected: two builds, two binexports, one bindiff.
    assert sorted(mocks["build_calls"]) == [("alpha", "a"), ("alpha", "b")]
    assert len(mocks["binexport_calls"]) == 2
    assert len(mocks["bindiff_calls"]) == 1


def test_multiple_entries_produce_one_sample_each(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
        {"name": "beta",  "binary": "bin/beta.exe",
         "tags": ["diffing", "exe"]},
    ])

    def factory(name):
        # Different similarity per entry to prove the plumbing
        # tracks them separately.
        sims = {"alpha": 0.4, "beta": 0.7}
        return _ok_bindiff_result(similarity=sims[name])

    _install_mocks(monkeypatch, bindiff_result_factory=factory)
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))

    sims = {s.sample_name: s.value for s in result.metrics[0].samples}
    assert sims == {"alpha": 0.4, "beta": 0.7}


# ============================================================================
# Filter semantics
# ============================================================================


def test_only_diffing_exe_tagged_entries_run(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "diffable", "binary": "bin/d.exe",
         "tags": ["diffing", "exe"]},
        # Not diffing-tagged — must be skipped.
        {"name": "other", "binary": "bin/o.exe", "tags": ["vm", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch)
    asyncio.run(bb.BinDiffBenchmark().run(corpus, _fake_session(tmp_path)))
    names = {name for name, _ in mocks["build_calls"]}
    assert names == {"diffable"}


def test_pre_protected_entries_filtered_out(tmp_path: Path, monkeypatch):
    """Even if a pre-protected entry somehow got the ``diffing`` tag
    in the manifest (a typo), the runtime filter rejects it because
    the two-build pipeline cannot apply."""
    corpus = _make_corpus(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe",
         "tags": ["diffing", "exe"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("no buildable corpus entries" in e for e in result.errors)


def test_empty_filter_returns_empty_result(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "other", "binary": "bin/o.exe", "tags": ["vm"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert len(result.metrics) == 2
    for m in result.metrics:
        assert m.samples == []
    assert any("no buildable corpus entries" in e for e in result.errors)


# ============================================================================
# Per-step failure modes
# ============================================================================


def test_build_a_failure_aborts_entry(tmp_path: Path, monkeypatch):
    """The first build failing short-circuits the rest of the
    pipeline — no BinExport / BinDiff attempt for that entry."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch, build_fail_on={"alpha_a"})
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("alpha" in e and "seeded build 'a' failed" in e
               for e in result.errors)
    assert mocks["binexport_calls"] == []
    assert mocks["bindiff_calls"] == []
    # No sample recorded for alpha.
    assert result.metrics[0].samples == []


def test_build_b_failure_aborts_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch, build_fail_on={"alpha_b"})
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("seeded build 'b' failed" in e for e in result.errors)
    assert mocks["binexport_calls"] == []


def test_binexport_failure_aborts_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch, binexport_fail_on={"alpha_a"})
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("BinExport 'a' failed" in e for e in result.errors)
    assert mocks["bindiff_calls"] == []


def test_bindiff_failure_aborts_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
    ])
    _install_mocks(monkeypatch, bindiff_fail_on={"alpha"})
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("bindiff failed" in e for e in result.errors)
    # No samples recorded.
    for m in result.metrics:
        assert m.samples == []


def test_one_entry_fails_others_continue(tmp_path: Path, monkeypatch):
    """Per-entry failures do not derail the whole run."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
        {"name": "beta",  "binary": "bin/beta.exe",
         "tags": ["diffing", "exe"]},
    ])
    _install_mocks(monkeypatch, bindiff_fail_on={"alpha"})
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("alpha" in e for e in result.errors)
    # Beta still produced samples.
    names = {s.sample_name for s in result.metrics[0].samples}
    assert names == {"beta"}


# ============================================================================
# Evidence content
# ============================================================================


def test_evidence_carries_bindiff_diagnostics(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["diffing", "exe"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(bb.BinDiffBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    ev = result.metrics[0].samples[0].evidence
    assert ev["confidence"] == 0.9
    assert ev["matched_functions"] == 100
    assert ev["primary_functions"] == 120
    assert ev["secondary_functions"] == 130
    assert "results_stats" in ev
    assert "bindiff_duration_ms" in ev
