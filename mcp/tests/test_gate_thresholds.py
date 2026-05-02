"""Unit tests for ``gates._thresholds``.

Covers ``select_observed`` (aggregate dispatch), ``upper_bound_outcome``,
and ``lower_bound_outcome``. The two outcome helpers carry every
gate's actual threshold logic, so coverage here is the foundation
for the per-gate tests.
"""

from __future__ import annotations

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    MetricDirection,
    MetricResult,
    MetricSample,
)
from mx_mcp.common.gate_base import GateLevel, GateScope
from mx_mcp.gates._thresholds import (
    lower_bound_outcome,
    select_observed,
    skipped_outcome,
    upper_bound_outcome,
)


# ============================================================================
# Helpers
# ============================================================================


def _metric(
    *,
    direction: MetricDirection,
    p90: float | None = None,
    mean: float | None = None,
    n_samples: int = 1,
    n_errors: int = 0,
) -> MetricResult:
    return MetricResult(
        name="m", direction=direction,
        samples=[MetricSample(sample_name="s", value=p90 or mean or 0.0)],
        aggregate=AggregateStats(
            p10=None, p50=None, p90=p90, mean=mean,
            stddev=None,
            n_samples=n_samples, n_errors=n_errors,
        ),
    )


# ============================================================================
# select_observed
# ============================================================================


def test_select_observed_uses_p90_for_higher_better():
    m = _metric(direction=MetricDirection.HIGHER_BETTER, p90=0.42, mean=0.5)
    assert select_observed(m) == 0.42


def test_select_observed_uses_p90_for_lower_better():
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=0.7, mean=0.4)
    assert select_observed(m) == 0.7


def test_select_observed_uses_mean_for_false_best():
    m = _metric(direction=MetricDirection.FALSE_BEST, p90=1.0, mean=0.25)
    assert select_observed(m) == 0.25


def test_select_observed_returns_none_when_aggregate_missing():
    m = _metric(direction=MetricDirection.HIGHER_BETTER, p90=None, mean=None)
    assert select_observed(m) is None


# ============================================================================
# upper_bound_outcome
# ============================================================================


_UB = dict(
    gate="g", benchmark="b", metric="m", scope=GateScope.FAST,
    fail_at=0.7, warn_at=0.5,
    fail_message="bad", warn_message="warn", pass_message="ok",
)


def test_upper_bound_pass_below_warn():
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=0.2)
    out = upper_bound_outcome(metric_result=m, **_UB)
    assert out.level is GateLevel.PASS
    assert out.observed == 0.2
    assert out.message == "ok"


def test_upper_bound_warn_in_band():
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=0.55)
    out = upper_bound_outcome(metric_result=m, **_UB)
    assert out.level is GateLevel.WARN
    assert out.observed == 0.55
    assert out.message == "warn"


def test_upper_bound_fail_at_threshold_inclusive():
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=0.7)
    out = upper_bound_outcome(metric_result=m, **_UB)
    assert out.level is GateLevel.FAIL
    assert out.observed == 0.7


def test_upper_bound_fail_above_threshold():
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=0.95)
    out = upper_bound_outcome(metric_result=m, **_UB)
    assert out.level is GateLevel.FAIL


def test_upper_bound_skipped_when_aggregate_missing():
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=None)
    out = upper_bound_outcome(metric_result=m, **_UB)
    assert out.level is GateLevel.SKIPPED
    assert out.observed is None
    assert "unavailable" in out.message


def test_upper_bound_no_warn_band():
    """warn_at=None disables the warn band entirely."""
    args = {**_UB, "warn_at": None}
    m = _metric(direction=MetricDirection.LOWER_BETTER, p90=0.55)
    out = upper_bound_outcome(metric_result=m, **args)
    assert out.level is GateLevel.PASS  # 0.55 < fail_at=0.7, no warn band
    assert "warn" not in out.threshold_repr


def test_upper_bound_uses_mean_for_false_best():
    """A FALSE_BEST metric should compare mean, not p90."""
    m = _metric(
        direction=MetricDirection.FALSE_BEST, p90=1.0, mean=0.0001,
    )
    args = {**_UB, "fail_at": 0.0001, "warn_at": None}
    out = upper_bound_outcome(metric_result=m, **args)
    assert out.observed == 0.0001
    assert out.level is GateLevel.FAIL  # mean >= fail_at (inclusive)


# ============================================================================
# lower_bound_outcome
# ============================================================================


_LB = dict(
    gate="g", benchmark="b", metric="m", scope=GateScope.SLOW,
    fail_below=100.0, warn_below=300.0,
    fail_message="bad", warn_message="warn", pass_message="ok",
)


def test_lower_bound_pass_above_warn():
    m = _metric(direction=MetricDirection.HIGHER_BETTER, p90=500.0)
    out = lower_bound_outcome(metric_result=m, **_LB)
    assert out.level is GateLevel.PASS


def test_lower_bound_warn_in_band():
    m = _metric(direction=MetricDirection.HIGHER_BETTER, p90=200.0)
    out = lower_bound_outcome(metric_result=m, **_LB)
    assert out.level is GateLevel.WARN


def test_lower_bound_fail_at_threshold_inclusive():
    m = _metric(direction=MetricDirection.HIGHER_BETTER, p90=100.0)
    out = lower_bound_outcome(metric_result=m, **_LB)
    assert out.level is GateLevel.FAIL


def test_lower_bound_skipped_when_aggregate_missing():
    m = _metric(direction=MetricDirection.HIGHER_BETTER, p90=None)
    out = lower_bound_outcome(metric_result=m, **_LB)
    assert out.level is GateLevel.SKIPPED


# ============================================================================
# skipped_outcome
# ============================================================================


def test_skipped_outcome_is_well_formed():
    out = skipped_outcome(
        gate="g", benchmark="b", metric="m", scope=GateScope.SLOW,
        threshold_repr="< 0.5", reason="metric not in tier output",
    )
    assert out.level is GateLevel.SKIPPED
    assert out.observed is None
    assert out.threshold_repr == "< 0.5"
    assert "not in tier" in out.message
