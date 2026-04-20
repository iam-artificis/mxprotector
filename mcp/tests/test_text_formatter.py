"""Unit tests for reporting.text_formatter."""

from __future__ import annotations

from mx_mcp.common.baselines import (
    BaselineDiff,
    DiffVerdict,
    MetricDiff,
)
from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
    MetricSample,
    MetricScale,
)
from mx_mcp.reporting.text_formatter import format_diff, format_measurement
from mx_mcp.tools.measure_defense import MeasureDefenseOutput


def _metric(
    *, name: str, direction: MetricDirection, p90: float | None, scale: MetricScale | None,
    n_samples: int = 3, n_errors: int = 0,
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=[MetricSample(sample_name="x", value=p90)] if p90 is not None else [],
        aggregate=AggregateStats(
            p10=p90, p50=p90, p90=p90, mean=p90, stddev=None,
            n_samples=n_samples, n_errors=n_errors,
        ),
        scale=scale,
    )


def _bench(name: str, metrics: list[MetricResult]) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark=name, category="cff", tier="fast",
        duration_ms=1, metrics=metrics,
    )


def _measurement(benchmarks: list[BenchmarkResult]) -> MeasureDefenseOutput:
    return MeasureDefenseOutput(
        corpus_path="corpus/",
        corpus_size=len(benchmarks),
        benchmark_count=len(benchmarks),
        duration_ms=10,
        benchmarks=benchmarks,
    )


# ============================================================================
# format_measurement
# ============================================================================


def test_format_measurement_empty_has_placeholder():
    out = format_measurement(_measurement([]))
    assert "no benchmark results" in out
    assert "corpus/" in out


def test_format_measurement_with_scale_shows_score():
    bench = _bench("b1", [
        _metric(
            name="m1",
            direction=MetricDirection.HIGHER_BETTER,
            p90=15.0,
            scale=MetricScale(weak_value=1.0, strong_value=30.0),
        ),
    ])
    out = format_measurement(_measurement([bench]))
    assert "m1" in out
    # score for p90=15 on scale [1,30] is ~0.48.
    assert "score=0.48" in out or "score=0.4" in out
    assert "p90=15" in out


def test_format_measurement_without_scale_flags_no_scale():
    bench = _bench("b1", [
        _metric(
            name="m1",
            direction=MetricDirection.HIGHER_BETTER,
            p90=7.0,
            scale=None,
        ),
    ])
    out = format_measurement(_measurement([bench]))
    assert "(no scale)" in out


def test_format_measurement_includes_errors():
    br = _bench("b1", [
        _metric(
            name="m1", direction=MetricDirection.HIGHER_BETTER,
            p90=1.0, scale=MetricScale(weak_value=0.0, strong_value=10.0),
        ),
    ])
    br = br.model_copy(update={"errors": ["alpha: build failed: exit=1"]})
    out = format_measurement(_measurement([br]))
    assert "errors:" in out
    assert "alpha" in out


def test_format_measurement_no_data_metric_shows_placeholder():
    bench = _bench("b1", [
        _metric(
            name="m_empty", direction=MetricDirection.HIGHER_BETTER,
            p90=None, scale=MetricScale(weak_value=0.0, strong_value=1.0),
        ),
    ])
    out = format_measurement(_measurement([bench]))
    assert "(no data)" in out


# ============================================================================
# format_diff
# ============================================================================


def _diff(
    *, gate_passed: bool,
    improvements: list[MetricDiff] | None = None,
    regressions: list[MetricDiff] | None = None,
) -> BaselineDiff:
    return BaselineDiff(
        baseline_name="v1",
        baseline_timestamp="2026-04-20T00:00:00Z",
        current_timestamp="2026-04-20T12:00:00Z",
        gate_passed=gate_passed,
        improvements=improvements or [],
        regressions=regressions or [],
    )


def _mdiff(
    *, name: str = "m1", benchmark: str = "b1", verdict: DiffVerdict,
    cur: float | None = 1.0, base: float | None = 1.0, delta: float | None = 0.0,
) -> MetricDiff:
    return MetricDiff(
        benchmark=benchmark, metric=name,
        direction=MetricDirection.HIGHER_BETTER,
        verdict=verdict,
        current_value=cur, baseline_value=base, delta_pct=delta,
    )


def test_format_diff_pass_shows_pass_gate():
    out = format_diff(_diff(gate_passed=True))
    assert "gate: PASS" in out


def test_format_diff_fail_shows_fail_gate_and_regression_section():
    diff = _diff(
        gate_passed=False,
        regressions=[_mdiff(verdict=DiffVerdict.REGRESSED, cur=0.5, base=1.0, delta=-50.0)],
    )
    out = format_diff(diff)
    assert "gate: FAIL" in out
    assert "regressions" in out
    assert "-50.0%" in out


def test_format_diff_orders_regressions_before_improvements():
    diff = _diff(
        gate_passed=False,
        regressions=[_mdiff(name="r", verdict=DiffVerdict.REGRESSED, delta=-10.0)],
        improvements=[_mdiff(name="i", verdict=DiffVerdict.IMPROVED, delta=+10.0)],
    )
    out = format_diff(diff)
    assert out.index("regressions") < out.index("improvements")


def test_format_diff_handles_missing_values():
    diff = _diff(
        gate_passed=True,
        improvements=[_mdiff(verdict=DiffVerdict.IMPROVED, cur=None, base=1.0, delta=None)],
    )
    out = format_diff(diff)
    assert "cur=-" in out
    assert "Δ=-" in out
