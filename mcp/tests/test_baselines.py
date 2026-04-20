"""Unit tests for common.baselines: store + diff."""

from __future__ import annotations

from pathlib import Path

import pytest

from mx_mcp.common.baselines import (
    BASELINE_SCHEMA_VERSION,
    BaselineDoc,
    BaselineExistsError,
    BaselineNotFoundError,
    DiffVerdict,
    JsonFileStore,
    diff_baselines,
)
from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
    MetricSample,
)


# ============================================================================
# Fixtures
# ============================================================================


def _bench(
    name: str,
    metric_name: str,
    direction: MetricDirection,
    *,
    p90: float | None = 0.5,
    mean: float | None = 0.5,
) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark=name,
        category="cff",
        tier="fast",
        duration_ms=0,
        metrics=[MetricResult(
            name=metric_name,
            direction=direction,
            samples=[MetricSample(sample_name="x", value=0.5)],
            aggregate=AggregateStats(
                p10=p90, p50=p90, p90=p90, mean=mean, stddev=None,
                n_samples=1, n_errors=0,
            ),
        )],
    )


def _doc(name: str, benchmarks: list[BenchmarkResult]) -> BaselineDoc:
    return BaselineDoc(
        schema_version=BASELINE_SCHEMA_VERSION,
        name=name,
        timestamp="2026-04-20T00:00:00Z",
        builder_level="strong",
        builder_args=[],
        benchmarks=benchmarks,
    )


# ============================================================================
# BaselineDoc schema
# ============================================================================


def test_baseline_doc_rejects_unsupported_version():
    with pytest.raises(ValueError, match="unsupported baseline schema"):
        BaselineDoc(
            schema_version=999,
            name="bad",
            timestamp="t",
            builder_level="strong",
            benchmarks=[],
        )


def test_baseline_doc_round_trips():
    doc = _doc("v1", [_bench("b", "m", MetricDirection.LOWER_BETTER)])
    as_json = doc.model_dump_json()
    restored = BaselineDoc.model_validate_json(as_json)
    assert restored == doc


# ============================================================================
# JsonFileStore
# ============================================================================


def test_store_rejects_invalid_name(tmp_path: Path):
    store = JsonFileStore(tmp_path)
    with pytest.raises(ValueError, match="non-empty"):
        store._path_for("")
    with pytest.raises(ValueError, match="disallowed characters"):
        store._path_for("a/b")
    with pytest.raises(ValueError, match="disallowed characters"):
        store._path_for("bad name")


def test_store_round_trip(tmp_path: Path):
    store = JsonFileStore(tmp_path)
    doc = _doc("v1", [_bench("b", "m", MetricDirection.LOWER_BETTER)])
    path = store.save(doc)
    assert path.exists()
    restored = store.load("v1")
    assert restored == doc


def test_store_raises_on_missing(tmp_path: Path):
    store = JsonFileStore(tmp_path)
    with pytest.raises(BaselineNotFoundError, match="baseline 'nope' not found"):
        store.load("nope")


def test_store_blocks_overwrite_by_default(tmp_path: Path):
    store = JsonFileStore(tmp_path)
    doc = _doc("v1", [])
    store.save(doc)
    with pytest.raises(BaselineExistsError, match="already exists"):
        store.save(doc)


def test_store_overwrite_replaces(tmp_path: Path):
    store = JsonFileStore(tmp_path)
    store.save(_doc("v1", [_bench("a", "m", MetricDirection.LOWER_BETTER)]))
    new_doc = _doc("v1", [_bench("b", "m", MetricDirection.LOWER_BETTER)])
    store.save(new_doc, overwrite=True)
    restored = store.load("v1")
    assert restored.benchmarks[0].benchmark == "b"


def test_store_lists_baselines_sorted(tmp_path: Path):
    store = JsonFileStore(tmp_path)
    store.save(_doc("gamma", []))
    store.save(_doc("alpha", []))
    store.save(_doc("beta", []))
    assert store.list_baselines() == ["alpha", "beta", "gamma"]


# ============================================================================
# diff_baselines
# ============================================================================


def test_diff_higher_better_improvement():
    baseline = _doc("b", [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=1.0)])
    current = [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=1.2)]  # +20%
    diff = diff_baselines(current, baseline, tolerance_pct=5.0)
    assert len(diff.improvements) == 1
    assert diff.improvements[0].verdict is DiffVerdict.IMPROVED
    assert diff.gate_passed is True


def test_diff_higher_better_regression():
    baseline = _doc("b", [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=1.0)])
    current = [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=0.8)]  # -20%
    diff = diff_baselines(current, baseline, tolerance_pct=5.0)
    assert len(diff.regressions) == 1
    assert diff.gate_passed is False


def test_diff_within_tolerance_is_unchanged():
    baseline = _doc("b", [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=1.0)])
    current = [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=1.02)]  # +2%, within 5%
    diff = diff_baselines(current, baseline, tolerance_pct=5.0)
    assert len(diff.unchanged) == 1
    assert diff.improvements == []
    assert diff.regressions == []


def test_diff_lower_better_sign_flip():
    # Lower-better: current < baseline → improvement.
    baseline = _doc("b", [_bench("b", "m", MetricDirection.LOWER_BETTER, p90=0.8)])
    current = [_bench("b", "m", MetricDirection.LOWER_BETTER, p90=0.5)]  # improved
    diff = diff_baselines(current, baseline, tolerance_pct=5.0)
    assert len(diff.improvements) == 1


def test_diff_false_best_uses_absolute_tolerance():
    # false_best compares mean as a failure rate; tolerance_pct is
    # ABSOLUTE (5.0 → ±0.05 in the rate).
    baseline = _doc("b", [_bench("b", "m", MetricDirection.FALSE_BEST, mean=0.30)])
    current = [_bench("b", "m", MetricDirection.FALSE_BEST, mean=0.40)]  # +0.10 > 0.05
    diff = diff_baselines(current, baseline, tolerance_pct=5.0)
    assert len(diff.regressions) == 1


def test_diff_zero_baseline_unchanged_when_current_zero():
    baseline = _doc("b", [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=0.0)])
    current = [_bench("b", "m", MetricDirection.HIGHER_BETTER, p90=0.0)]
    diff = diff_baselines(current, baseline)
    assert len(diff.unchanged) == 1


def test_diff_skipped_when_aggregate_none():
    baseline = _doc("b", [_bench("b", "m", MetricDirection.LOWER_BETTER, p90=None)])
    current = [_bench("b", "m", MetricDirection.LOWER_BETTER, p90=0.3)]
    diff = diff_baselines(current, baseline)
    assert len(diff.skipped) == 1
    assert diff.skipped[0].verdict is DiffVerdict.SKIPPED


def test_diff_reports_added_metric():
    baseline = _doc("b", [])
    current = [_bench("b", "m", MetricDirection.LOWER_BETTER)]
    diff = diff_baselines(current, baseline)
    assert len(diff.added) == 1
    assert diff.added[0].verdict is DiffVerdict.ADDED


def test_diff_reports_removed_metric():
    baseline = _doc("b", [_bench("b", "m", MetricDirection.LOWER_BETTER)])
    current: list[BenchmarkResult] = []
    diff = diff_baselines(current, baseline)
    assert len(diff.removed) == 1
    assert diff.removed[0].verdict is DiffVerdict.REMOVED
