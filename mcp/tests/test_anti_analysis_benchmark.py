"""Unit tests for ``benchmarks.anti_analysis_benchmark``.

Mocks both ``ensure_protected`` (no real builder) and the detector
list (no real PE / pattern scanning needed). Asserts on the metric
shape, the per-entry sample, and the fail-closed paths.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

from mx_mcp.anti_analysis.detector_base import (
    DetectionResult,
    IDetector,
)
from mx_mcp.benchmarks import anti_analysis_benchmark as aa
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import ProtectedBuild
from mx_mcp.common.corpus import Corpus


# ============================================================================
# Fixtures
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


def _fake_session(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=tmp_path)


def _install_fake_build(monkeypatch):
    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        output = output_dir / f"{entry.name}.mx.exe"
        output.write_bytes(b"\x4d\x5a")
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=output,
            sidecar_path=None,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    monkeypatch.setattr(aa, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        aa, "resolve_builder_path", lambda root: root / "fake.exe",
    )


def _make_detector(name: str, *, detected: bool = False,
                   skipped: bool = False, raises: type[BaseException] | None = None,
                   ) -> type[IDetector]:
    """Build a stub detector class for injection."""

    class _Stub(IDetector):
        description: ClassVar[str] = "stub"

        async def detect(self, binary_path: Path) -> DetectionResult:
            if raises is not None:
                raise raises("boom")
            return DetectionResult(
                tool=self.name, detected=detected, skipped=skipped,
            )

    _Stub.name = name  # type: ignore[misc]
    _Stub.targets = (name,)  # type: ignore[misc]
    return _Stub


# ============================================================================
# Tests
# ============================================================================


def test_metric_metadata_is_well_formed():
    bench = aa.AntiAnalysisCoverageBenchmark()
    assert bench.name == "anti_analysis_coverage"
    assert bench.category == "anti_analysis"
    assert bench.tier == "slow"
    assert bench.corpus_tags == frozenset({"exe"})


def test_no_corpus_emits_error_and_empty_metric(tmp_path):
    corpus = _make_corpus(tmp_path, [])
    bench = aa.AntiAnalysisCoverageBenchmark(detectors_factory=lambda: [])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no corpus" in e for e in result.errors)
    assert result.metrics[0].samples == []


def test_one_entry_one_detector_yields_rate(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["exe"]},
    ])
    _install_fake_build(monkeypatch)
    bench = aa.AntiAnalysisCoverageBenchmark(
        detectors_factory=lambda: [
            _make_detector("d1", detected=True),
            _make_detector("d2", detected=False),
        ],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert isinstance(result, BenchmarkResult)
    assert result.errors == []

    metric = result.metrics[0]
    assert metric.name == "anti_analysis_coverage_rate"
    assert metric.direction is MetricDirection.HIGHER_BETTER
    assert len(metric.samples) == 1
    assert metric.samples[0].value == 0.5
    cov = metric.samples[0].evidence["coverage"]
    assert cov["detected"] == 1
    assert cov["detectors_informative"] == 2


def test_skipped_detector_does_not_deflate_rate(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["exe"]},
    ])
    _install_fake_build(monkeypatch)
    bench = aa.AntiAnalysisCoverageBenchmark(
        detectors_factory=lambda: [
            _make_detector("d_yes", detected=True),
            _make_detector("d_no",  detected=False),
            _make_detector("d_skip", detected=False, skipped=True),
        ],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    sample = result.metrics[0].samples[0]
    # informative = 2 (skip excluded); rate = 1/2.
    assert sample.value == 0.5
    assert sample.evidence["coverage"]["skipped"] == 1


def test_detector_exception_is_fail_closed(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["exe"]},
    ])
    _install_fake_build(monkeypatch)
    bench = aa.AntiAnalysisCoverageBenchmark(
        detectors_factory=lambda: [
            _make_detector("ouch", raises=RuntimeError),
        ],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    sample = result.metrics[0].samples[0]
    # The crashed detector counts as informative (not skipped) and as
    # not-detected, so rate=0.0.
    assert sample.value == 0.0
    detectors = sample.evidence["detectors"]
    assert detectors[0]["error"] is not None


def test_build_failure_skips_entry_with_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["exe"]},
    ])

    async def failing_build(entry, **kw):
        from mx_mcp.common.builder import BuilderError
        raise BuilderError("builder did not run")

    monkeypatch.setattr(aa, "ensure_protected", failing_build)
    monkeypatch.setattr(
        aa, "resolve_builder_path", lambda root: root / "fake.exe",
    )

    bench = aa.AntiAnalysisCoverageBenchmark(
        detectors_factory=lambda: [_make_detector("d", detected=True)],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert result.metrics[0].samples == []
    assert any("build failed" in e for e in result.errors)


def test_aggregate_distribution_over_two_entries(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "weak", "binary": "bin/w.exe", "tags": ["exe"]},
        {"name": "strong", "binary": "bin/s.exe", "tags": ["exe"]},
    ])
    _install_fake_build(monkeypatch)

    # First detector says detected on both. Second detector says
    # detected on weak only — so weak rate=1.0, strong rate=0.5.
    call_index = {"n": 0}

    class _SwitchingDetector(IDetector):
        name: ClassVar[str] = "switching"
        description: ClassVar[str] = "stub"
        targets: ClassVar[tuple[str, ...]] = ("x",)

        async def detect(self, binary_path: Path) -> DetectionResult:
            i = call_index["n"]
            call_index["n"] += 1
            return DetectionResult(tool=self.name, detected=(i % 2 == 0))

    bench = aa.AntiAnalysisCoverageBenchmark(
        detectors_factory=lambda: [
            _make_detector("steady", detected=True),
            _SwitchingDetector,
        ],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    samples = result.metrics[0].samples
    assert {s.sample_name for s in samples} == {"weak", "strong"}
    rates = sorted(s.value for s in samples)
    # 1/2 and 2/2 (or vice versa depending on iteration order). Both
    # values must be valid coverage rates.
    assert rates == [0.5, 1.0]


def test_async_iterates_through_event_loop(tmp_path, monkeypatch):
    """Sanity: detector batch is awaitable and produces results."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["exe"]},
    ])
    _install_fake_build(monkeypatch)
    bench = aa.AntiAnalysisCoverageBenchmark(
        detectors_factory=lambda: [_make_detector("d", detected=False)],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert len(result.metrics[0].samples) == 1
