"""Unit tests for tools.diff_defense_baseline.

Exercises the full measure+diff pipeline with injected dependencies
(mock benchmark + tmp filesystem store) so tests are hermetic and do
not require a real corpus build or prior baseline.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mx_mcp.common.baselines import BaselineNotFoundError, JsonFileStore
from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
)
from mx_mcp.tools.diff_defense_baseline import (
    DiffDefenseBaselineInput,
    DiffDefenseBaselineOutput,
    DiffDefenseBaselineTool,
)
from mx_mcp.tools.measure_defense import MeasureDefenseTool
from mx_mcp.tools.record_baseline import (
    RecordBaselineInput,
    RecordBaselineTool,
)


def _make_corpus(tmp_path: Path) -> Path:
    corpus_root = tmp_path / "corpus"
    (corpus_root / "bin").mkdir(parents=True)
    (corpus_root / "bin" / "a.exe").write_bytes(b"\x4d\x5a")
    (corpus_root / "corpus.json").write_text(
        json.dumps({
            "schema_version": 1,
            "entries": [{"name": "a", "binary": "bin/a.exe", "tags": ["vm"]}],
        }),
        encoding="utf-8",
    )
    return corpus_root


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


class _ParametrisedBench(IBenchmark):
    """Benchmark that always reports one metric with a fixed value; the
    value is set via a class attribute so tests can mutate it between
    two 'runs' to simulate regressions / improvements."""

    name = "parametric"
    description = "stub"
    category = "cff"
    tier = "fast"
    fixed_value: float = 1.0

    async def run(self, corpus, session):
        return BenchmarkResult(
            benchmark=self.name,
            category=self.category,
            tier=self.tier,
            duration_ms=0,
            metrics=[MetricResult(
                name="score",
                direction=MetricDirection.HIGHER_BETTER,
                samples=[MetricSample(sample_name=e.name, value=self.fixed_value)
                         for e in corpus.entries()],
                aggregate=AggregateStats(
                    p10=self.fixed_value, p50=self.fixed_value,
                    p90=self.fixed_value, mean=self.fixed_value,
                    stddev=None, n_samples=len(corpus), n_errors=0,
                ),
            )],
        )


def _record(tmp_path: Path, corpus_root: Path, baselines_root: Path, name: str, value: float):
    _ParametrisedBench.fixed_value = value
    measure = MeasureDefenseTool(benchmarks_source=lambda: [_ParametrisedBench])
    record = RecordBaselineTool(measure_tool=measure)
    args = RecordBaselineInput(
        baseline_name=name,
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    asyncio.run(record.run(args, _fake_session(tmp_path)))


# ============================================================================
# Missing baseline
# ============================================================================


def test_missing_baseline_raises_with_listing(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"
    baselines_root.mkdir()

    measure = MeasureDefenseTool(benchmarks_source=lambda: [])
    diff_tool = DiffDefenseBaselineTool(measure_tool=measure)
    args = DiffDefenseBaselineInput(
        baseline_name="does_not_exist",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    with pytest.raises(BaselineNotFoundError, match="does_not_exist"):
        asyncio.run(diff_tool.run(args, _fake_session(tmp_path)))


# ============================================================================
# End-to-end: record + diff
# ============================================================================


def test_diff_reports_improvement_vs_lower_baseline(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"

    _record(tmp_path, corpus_root, baselines_root, "v1", value=1.0)

    # Second call with a higher value should report improvement.
    _ParametrisedBench.fixed_value = 2.0
    measure = MeasureDefenseTool(benchmarks_source=lambda: [_ParametrisedBench])
    diff_tool = DiffDefenseBaselineTool(measure_tool=measure)
    args = DiffDefenseBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    out = asyncio.run(diff_tool.run(args, _fake_session(tmp_path)))
    assert isinstance(out, DiffDefenseBaselineOutput)
    assert out.diff.gate_passed is True
    assert len(out.diff.improvements) == 1
    assert out.diff.regressions == []


def test_diff_reports_regression_fails_gate(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"

    _record(tmp_path, corpus_root, baselines_root, "v1", value=2.0)

    _ParametrisedBench.fixed_value = 1.0  # -50%
    measure = MeasureDefenseTool(benchmarks_source=lambda: [_ParametrisedBench])
    diff_tool = DiffDefenseBaselineTool(measure_tool=measure)
    args = DiffDefenseBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    out = asyncio.run(diff_tool.run(args, _fake_session(tmp_path)))
    assert out.diff.gate_passed is False
    assert len(out.diff.regressions) == 1


def test_diff_within_tolerance_is_unchanged(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"

    _record(tmp_path, corpus_root, baselines_root, "v1", value=1.0)

    _ParametrisedBench.fixed_value = 1.02  # +2%, within default 5% tolerance
    measure = MeasureDefenseTool(benchmarks_source=lambda: [_ParametrisedBench])
    diff_tool = DiffDefenseBaselineTool(measure_tool=measure)
    args = DiffDefenseBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    out = asyncio.run(diff_tool.run(args, _fake_session(tmp_path)))
    assert out.diff.gate_passed is True
    assert len(out.diff.unchanged) == 1
    assert out.diff.improvements == []
    assert out.diff.regressions == []


def test_diff_zero_benchmarks_on_both_sides(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"

    # Record a baseline with no benchmarks.
    measure = MeasureDefenseTool(benchmarks_source=lambda: [])
    record_tool = RecordBaselineTool(measure_tool=measure)
    asyncio.run(record_tool.run(
        RecordBaselineInput(
            baseline_name="empty",
            baselines_root=str(baselines_root),
            corpus_path=str(corpus_root),
        ),
        _fake_session(tmp_path),
    ))

    # Diff also runs zero benchmarks — nothing to compare.
    diff_tool = DiffDefenseBaselineTool(measure_tool=measure)
    out = asyncio.run(diff_tool.run(
        DiffDefenseBaselineInput(
            baseline_name="empty",
            baselines_root=str(baselines_root),
            corpus_path=str(corpus_root),
        ),
        _fake_session(tmp_path),
    ))
    assert out.diff.gate_passed is True
    assert out.diff.improvements == []
    assert out.diff.regressions == []
    assert out.diff.unchanged == []
