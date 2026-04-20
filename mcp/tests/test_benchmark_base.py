"""Unit tests for common.benchmark_base: ABC, registry, statistics."""

from __future__ import annotations

import math

import pytest

from mx_mcp.common import benchmark_base as bb
from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
    MetricScale,
    _linear_percentile,
    aggregate_numeric,
    all_benchmarks,
    register_benchmark,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Isolate each test from others that register benchmarks."""
    saved = list(bb._REGISTRY)
    bb._REGISTRY.clear()
    try:
        yield
    finally:
        bb._REGISTRY.clear()
        bb._REGISTRY.extend(saved)


# ============================================================================
# Percentile helper
# ============================================================================


def test_percentile_single_value():
    assert _linear_percentile([5.0], 10) == 5.0
    assert _linear_percentile([5.0], 50) == 5.0
    assert _linear_percentile([5.0], 90) == 5.0


def test_percentile_pair_linear():
    # Linear interpolation between two values.
    values = [0.0, 10.0]
    assert _linear_percentile(values, 0) == 0.0
    assert _linear_percentile(values, 50) == 5.0
    assert _linear_percentile(values, 100) == 10.0


def test_percentile_sorted_distribution():
    # Linear interpolation over 5 sorted samples: idx = (p/100)*(n-1) = (p/100)*4.
    # p=10 → idx=0.4 → 10*0.6 + 20*0.4 = 14.0
    # p=50 → idx=2.0 → 30.0 exactly
    # p=90 → idx=3.6 → 40*0.4 + 50*0.6 = 46.0
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert math.isclose(_linear_percentile(values, 10), 14.0)
    assert math.isclose(_linear_percentile(values, 50), 30.0)
    assert math.isclose(_linear_percentile(values, 90), 46.0)


# ============================================================================
# aggregate_numeric
# ============================================================================


def test_aggregate_numeric_empty():
    stats = aggregate_numeric([])
    assert stats.p10 is None
    assert stats.p50 is None
    assert stats.p90 is None
    assert stats.mean is None
    assert stats.stddev is None
    assert stats.n_samples == 0
    assert stats.n_errors == 0


def test_aggregate_numeric_all_none():
    stats = aggregate_numeric([None, None, None])
    assert stats.p10 is None
    assert stats.mean is None
    assert stats.n_samples == 3
    assert stats.n_errors == 3


def test_aggregate_numeric_mixed_none():
    stats = aggregate_numeric([None, 1.0, 2.0, 3.0, None])
    assert stats.n_samples == 5
    assert stats.n_errors == 2
    assert stats.mean == 2.0
    assert stats.p50 == 2.0


def test_aggregate_numeric_single_value():
    stats = aggregate_numeric([42.0])
    assert stats.p10 == stats.p50 == stats.p90 == 42.0
    assert stats.mean == 42.0
    # stddev requires >= 2 samples.
    assert stats.stddev is None


def test_aggregate_numeric_booleans_as_rate():
    # false_best metrics surface booleans that aggregate as failure rates.
    stats = aggregate_numeric([True, False, True, False, True])
    assert stats.n_samples == 5
    assert stats.n_errors == 0
    assert math.isclose(stats.mean, 0.6)


def test_aggregate_numeric_stddev_computed_for_two_plus():
    stats = aggregate_numeric([1.0, 3.0])
    assert stats.stddev is not None
    assert math.isclose(stats.stddev, math.sqrt(2.0))


# ============================================================================
# Registry contract
# ============================================================================


class _ValidBench(IBenchmark):
    name = "valid_bench"
    description = "stub"
    category = "cff"
    tier = "fast"

    async def run(self, corpus, session):  # pragma: no cover — ABC test only
        raise NotImplementedError


def test_register_benchmark_adds_to_registry():
    assert all_benchmarks() == []
    register_benchmark(_ValidBench)
    assert all_benchmarks() == [_ValidBench]


def test_register_benchmark_duplicate_name_rejected():
    register_benchmark(_ValidBench)

    class Dup(IBenchmark):
        name = "valid_bench"
        description = "collision"
        category = "vm"
        tier = "fast"

        async def run(self, corpus, session):  # pragma: no cover
            raise NotImplementedError

    with pytest.raises(ValueError, match="name collision"):
        register_benchmark(Dup)


def test_register_benchmark_rejects_non_subclass():
    class NotBench:  # not IBenchmark
        name = "nope"
        description = "x"
        category = "vm"
        tier = "fast"

    with pytest.raises(TypeError, match="must subclass IBenchmark"):
        register_benchmark(NotBench)  # type: ignore[arg-type]


def test_register_benchmark_rejects_missing_attrs():
    class MissingAttr(IBenchmark):
        # missing ``category``
        name = "no_category"
        description = "x"
        tier = "fast"

        async def run(self, corpus, session):  # pragma: no cover
            raise NotImplementedError

    with pytest.raises(TypeError, match="missing required class attr"):
        register_benchmark(MissingAttr)  # type: ignore[misc]


# ============================================================================
# Pydantic round-trip for shared types
# ============================================================================


def test_benchmark_result_serialises_and_round_trips():
    result = BenchmarkResult(
        benchmark="b",
        category="vm",
        tier="fast",
        duration_ms=123,
        metrics=[
            MetricResult(
                name="m",
                direction=MetricDirection.LOWER_BETTER,
                samples=[
                    MetricSample(sample_name="s1", value=0.1),
                    MetricSample(sample_name="s2", value=None, evidence={"err": "x"}),
                ],
                aggregate=AggregateStats(
                    p10=0.1, p50=0.1, p90=0.1, mean=0.1, stddev=None,
                    n_samples=2, n_errors=1,
                ),
                scale=MetricScale(weak_value=1.0, strong_value=0.0),
            )
        ],
    )
    as_json = result.model_dump_json()
    round_trip = BenchmarkResult.model_validate_json(as_json)
    assert round_trip == result


# ============================================================================
# MetricScale — normalisation
# ============================================================================


def test_metric_scale_higher_better_endpoints():
    # ``weak < strong`` mode — values rising from weak to strong improve.
    scale = MetricScale(weak_value=1.0, strong_value=30.0)
    assert scale.normalize(1.0) == 0.0
    assert scale.normalize(30.0) == 1.0
    # Interior value — linear interpolation.
    assert math.isclose(scale.normalize(15.5), 0.5, abs_tol=0.01)


def test_metric_scale_lower_better_endpoints():
    # ``weak > strong`` mode — values falling from weak to strong improve.
    scale = MetricScale(weak_value=1.0, strong_value=0.0)
    assert scale.normalize(1.0) == 0.0
    assert scale.normalize(0.0) == 1.0
    assert math.isclose(scale.normalize(0.5), 0.5, abs_tol=0.01)


def test_metric_scale_false_best_inverts_boolean_rate():
    # Classical FALSE_BEST case: mean of a bool sample.
    scale = MetricScale(weak_value=1.0, strong_value=0.0)
    assert scale.normalize(1.0) == 0.0   # always fails → worst
    assert scale.normalize(0.0) == 1.0   # never fails → best
    assert math.isclose(scale.normalize(0.3), 0.7, abs_tol=0.01)


def test_metric_scale_clamps_out_of_range():
    scale = MetricScale(weak_value=1.0, strong_value=30.0)
    assert scale.normalize(-5.0) == 0.0
    assert scale.normalize(100.0) == 1.0


def test_metric_scale_zero_span_returns_neutral():
    scale = MetricScale(weak_value=5.0, strong_value=5.0)
    assert scale.normalize(5.0) == 0.5
    assert scale.normalize(1.0) == 0.5
    assert scale.normalize(100.0) == 0.5


def test_metric_result_without_scale_defaults_to_none():
    r = MetricResult(
        name="m",
        direction=MetricDirection.HIGHER_BETTER,
        samples=[],
        aggregate=AggregateStats(
            p10=None, p50=None, p90=None, mean=None, stddev=None,
            n_samples=0, n_errors=0,
        ),
    )
    assert r.scale is None
