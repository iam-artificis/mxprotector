"""Unit tests for ``gates.anti_analysis_coverage_gate``.

Direct unit-level tests against the gate's threshold arithmetic.
The runtime path through GateEvaluator is exercised by the broader
``test_shipgate_evaluator`` suite — here we focus on the
fail-below=0.4 / warn-below=0.6 / pass arithmetic.
"""

from __future__ import annotations

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    MetricDirection,
    MetricResult,
)
from mx_mcp.common.gate_base import GateLevel, GateScope
from mx_mcp.gates.anti_analysis_coverage_gate import AntiAnalysisCoverageGate


def _metric(p90: float | None) -> MetricResult:
    return MetricResult(
        name="anti_analysis_coverage_rate",
        direction=MetricDirection.HIGHER_BETTER,
        samples=[],
        aggregate=AggregateStats(
            p10=None, p50=None, p90=p90, mean=p90, stddev=None,
            n_samples=1, n_errors=0,
        ),
    )


def test_metadata_is_well_formed():
    g = AntiAnalysisCoverageGate()
    assert g.name == "anti_analysis_coverage"
    assert g.benchmark == "anti_analysis_coverage"
    assert g.metric == "anti_analysis_coverage_rate"
    assert g.scope is GateScope.SLOW


def test_pass_above_warn_band():
    out = AntiAnalysisCoverageGate().evaluate(_metric(0.80))
    assert out.level is GateLevel.PASS


def test_warn_in_band():
    out = AntiAnalysisCoverageGate().evaluate(_metric(0.55))
    assert out.level is GateLevel.WARN


def test_fail_at_threshold_inclusive():
    out = AntiAnalysisCoverageGate().evaluate(_metric(0.40))
    assert out.level is GateLevel.FAIL


def test_fail_below_threshold():
    out = AntiAnalysisCoverageGate().evaluate(_metric(0.20))
    assert out.level is GateLevel.FAIL


def test_skipped_when_metric_unavailable():
    out = AntiAnalysisCoverageGate().evaluate(_metric(None))
    assert out.level is GateLevel.SKIPPED
