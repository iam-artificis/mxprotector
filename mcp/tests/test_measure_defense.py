"""Unit tests for tools.measure_defense.

The production tool reads the global benchmark registry; tests inject
a custom ``benchmarks_source`` to keep themselves hermetic (no
dependency on whichever benchmarks are currently wired).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Iterable

import pytest

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
)
from mx_mcp.common.corpus import Corpus
from mx_mcp.tools.measure_defense import (
    MeasureDefenseInput,
    MeasureDefenseOutput,
    MeasureDefenseTool,
)


# ============================================================================
# Synthetic corpus + helpers
# ============================================================================


def _make_corpus(tmp_path: Path, names: Iterable[str] = ("alpha",)) -> Path:
    corpus_root = tmp_path / "corpus"
    (corpus_root / "bin").mkdir(parents=True)
    entries = []
    for n in names:
        bin_path = corpus_root / "bin" / f"{n}.exe"
        bin_path.write_bytes(b"\x4d\x5a")
        entries.append({"name": n, "binary": f"bin/{n}.exe", "tags": ["vm"]})
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return corpus_root


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


# ============================================================================
# Mock benchmark classes
# ============================================================================


class _OkBench(IBenchmark):
    name = "ok_bench"
    description = "stub"
    category = "cff"
    tier = "fast"

    async def run(self, corpus: Corpus, session) -> BenchmarkResult:
        return BenchmarkResult(
            benchmark=self.name,
            category=self.category,
            tier=self.tier,
            duration_ms=7,
            metrics=[MetricResult(
                name="score",
                direction=MetricDirection.HIGHER_BETTER,
                samples=[
                    MetricSample(sample_name=e.name, value=0.5)
                    for e in corpus.entries()
                ],
                aggregate=AggregateStats(
                    p10=0.5, p50=0.5, p90=0.5, mean=0.5, stddev=None,
                    n_samples=len(corpus), n_errors=0,
                ),
            )],
        )


class _RaisingBench(IBenchmark):
    name = "raises"
    description = "intentional failure"
    category = "vm"
    tier = "slow"

    async def run(self, corpus, session):
        raise RuntimeError("backend blew up")


# ============================================================================
# Empty-registry paths (the P1 steady state)
# ============================================================================


def test_empty_registry_returns_empty_result(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert isinstance(out, MeasureDefenseOutput)
    assert out.benchmark_count == 0
    assert out.benchmarks == []
    assert any("no benchmarks registered" in n for n in out.notes)


def test_filter_that_matches_nothing_returns_empty(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        categories=["no_such_category"],
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 0
    assert any("no benchmarks match filter" in n for n in out.notes)


# ============================================================================
# Corpus load failures
# ============================================================================


def test_missing_corpus_surfaces_note_when_benchmarks_present(tmp_path: Path):
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(corpus_path=str(tmp_path / "no_such_dir"))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 0
    assert any("corpus load failed" in n for n in out.notes)


def test_missing_corpus_ignored_when_no_benchmarks(tmp_path: Path):
    # Empty registry path short-circuits before corpus load.
    tool = MeasureDefenseTool(benchmarks_source=lambda: [])
    args = MeasureDefenseInput(corpus_path=str(tmp_path / "no_such_dir"))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmarks == []


# ============================================================================
# Execution paths
# ============================================================================


def test_runs_registered_benchmark_on_corpus(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path, names=("alpha", "beta"))
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 1
    assert out.corpus_size == 2
    bench_result = out.benchmarks[0]
    assert bench_result.benchmark == "ok_bench"
    assert len(bench_result.metrics[0].samples) == 2


def test_category_filter_respected(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench, _RaisingBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root), categories=["cff"],
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 1
    assert out.benchmarks[0].benchmark == "ok_bench"


def test_tier_filter_respected(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench, _RaisingBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root), tier="slow")
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    # Only the slow one runs; and it raises, so it's captured as an error
    # result rather than propagated (fail-closed).
    assert out.benchmark_count == 1
    assert out.benchmarks[0].benchmark == "raises"
    assert out.benchmarks[0].errors


def test_invalid_tier_raises(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root), tier="ultra")
    with pytest.raises(ValueError, match="unknown tier"):
        asyncio.run(tool.run(args, _fake_session(tmp_path)))


def test_benchmark_raising_is_fail_closed(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_RaisingBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    # A backend exception is captured, not re-raised (MCP.md principle).
    assert out.benchmark_count == 1
    result = out.benchmarks[0]
    assert result.metrics == []
    assert any("RuntimeError" in e for e in result.errors)
