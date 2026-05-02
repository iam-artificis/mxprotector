"""Unit tests for ``shipgate.evaluator``.

The evaluator is pure: walks a list of BenchmarkResults + the gate
registry, returns a TierVerdict. We inject custom gate factories so
the tests do not depend on the production catalogue.

Coverage:

1. ``_index_metrics`` flattens benchmarks correctly.
2. ``_summarise`` counts each level.
3. ``_downgrade_out_of_scope`` flips FAIL→WARN when scope mismatches.
4. ``GateEvaluator.evaluate`` happy paths: pass / fail / skipped.
5. Mixed-scope run: a slow-only FAIL during a fast run becomes WARN
   and ``gate_passed`` stays True.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
)
from mx_mcp.common.gate_base import (
    GateLevel,
    GateOutcome,
    GateScope,
    IGate,
)
from mx_mcp.shipgate.evaluator import (
    GateEvaluator,
    _downgrade_out_of_scope,
    _index_metrics,
    _summarise,
)


# ============================================================================
# Fixture helpers
# ============================================================================


def _metric(name: str, *, p90: float | None = None,
            mean: float | None = None,
            direction: MetricDirection = MetricDirection.LOWER_BETTER,
            ) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=[],
        aggregate=AggregateStats(
            p10=None, p50=None, p90=p90, mean=mean, stddev=None,
            n_samples=1, n_errors=0,
        ),
    )


def _bench(name: str, metrics: list[MetricResult]) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark=name, category="x", tier="fast",
        duration_ms=0, metrics=metrics, errors=[],
    )


def _outcome(*, level: GateLevel, scope: GateScope,
             gate: str = "g", benchmark: str = "b", metric: str = "m",
             ) -> GateOutcome:
    return GateOutcome(
        gate=gate, benchmark=benchmark, metric=metric,
        level=level, scope=scope, threshold_repr="x",
        observed=0.0, message="msg",
    )


def _make_gate(*, name: str, benchmark: str, metric: str,
               scope: GateScope, evaluate_level: GateLevel,
               ) -> type[IGate]:
    """Factory: build a stub IGate subclass for injection into the evaluator."""

    class _StubGate(IGate):
        name_v: ClassVar[str] = name           # avoid clash with IGate's `name`
        description: ClassVar[str] = "stub"

        # Mirror onto the IGate-required class attrs.
        # We can't dynamically set ClassVars at class-decoration time
        # easily, so plain class attribute assignment after class
        # definition is the simplest path.

        def evaluate(self, mr: MetricResult) -> GateOutcome:
            return _outcome(
                level=evaluate_level,
                scope=scope,
                gate=self.name,
                benchmark=self.benchmark,
                metric=self.metric,
            )

    _StubGate.name = name
    _StubGate.benchmark = benchmark
    _StubGate.metric = metric
    _StubGate.scope = scope
    return _StubGate


# ============================================================================
# Helpers — module-level pure functions
# ============================================================================


def test_index_metrics_flattens_benchmarks():
    a = _metric("ma", p90=1.0)
    b = _metric("mb", p90=2.0)
    c = _metric("mc", p90=3.0)
    benches = [_bench("BA", [a, b]), _bench("BC", [c])]
    idx = _index_metrics(benches)
    assert idx[("BA", "ma")] is a
    assert idx[("BA", "mb")] is b
    assert idx[("BC", "mc")] is c


def test_summarise_counts_each_level():
    outcomes = [
        _outcome(level=GateLevel.PASS, scope=GateScope.FAST),
        _outcome(level=GateLevel.WARN, scope=GateScope.FAST),
        _outcome(level=GateLevel.FAIL, scope=GateScope.FAST),
        _outcome(level=GateLevel.SKIPPED, scope=GateScope.FAST),
        _outcome(level=GateLevel.PASS, scope=GateScope.FAST),
    ]
    summary = _summarise(outcomes)
    assert summary.pass_ == 2
    assert summary.warn == 1
    assert summary.fail == 1
    assert summary.skipped == 1


def test_downgrade_out_of_scope_keeps_passes_unchanged():
    o = _outcome(level=GateLevel.PASS, scope=GateScope.SLOW)
    notes: list[str] = []
    out = _downgrade_out_of_scope(o, "fast", notes)
    assert out is o
    assert notes == []


def test_downgrade_out_of_scope_keeps_in_scope_fails_unchanged():
    o = _outcome(level=GateLevel.FAIL, scope=GateScope.FAST)
    notes: list[str] = []
    out = _downgrade_out_of_scope(o, "fast", notes)
    assert out is o
    assert out.level is GateLevel.FAIL
    assert notes == []


def test_downgrade_out_of_scope_keeps_any_scope_fails_unchanged():
    o = _outcome(level=GateLevel.FAIL, scope=GateScope.ANY)
    notes: list[str] = []
    out = _downgrade_out_of_scope(o, "fast", notes)
    assert out.level is GateLevel.FAIL
    assert notes == []


def test_downgrade_out_of_scope_flips_mismatched_fails_to_warn():
    o = _outcome(level=GateLevel.FAIL, scope=GateScope.SLOW, gate="myslow")
    notes: list[str] = []
    out = _downgrade_out_of_scope(o, "fast", notes)
    assert out.level is GateLevel.WARN
    assert "myslow" in notes[0]
    assert "downgraded" in out.message.lower()


# ============================================================================
# GateEvaluator
# ============================================================================


def test_evaluator_pass_when_no_fails():
    g = _make_gate(
        name="ok", benchmark="B", metric="m",
        scope=GateScope.FAST, evaluate_level=GateLevel.PASS,
    )
    benches = [_bench("B", [_metric("m", p90=0.1)])]
    verdict = GateEvaluator(lambda: [g]).evaluate("fast", benches)
    assert verdict.gate_passed is True
    assert verdict.summary.pass_ == 1
    assert verdict.summary.fail == 0


def test_evaluator_blocks_on_in_scope_fail():
    g = _make_gate(
        name="badfast", benchmark="B", metric="m",
        scope=GateScope.FAST, evaluate_level=GateLevel.FAIL,
    )
    benches = [_bench("B", [_metric("m", p90=0.99)])]
    verdict = GateEvaluator(lambda: [g]).evaluate("fast", benches)
    assert verdict.gate_passed is False
    assert verdict.summary.fail == 1


def test_evaluator_downgrades_slow_only_fail_in_fast_run():
    g = _make_gate(
        name="badslow", benchmark="B", metric="m",
        scope=GateScope.SLOW, evaluate_level=GateLevel.FAIL,
    )
    benches = [_bench("B", [_metric("m", p90=0.99)])]
    verdict = GateEvaluator(lambda: [g]).evaluate("fast", benches)
    # Downgraded → no FAIL → gate_passed True.
    assert verdict.gate_passed is True
    assert verdict.summary.fail == 0
    assert verdict.summary.warn == 1
    assert any("badslow" in n for n in verdict.notes)


def test_evaluator_skipped_when_metric_missing():
    g = _make_gate(
        name="ghost", benchmark="UNKNOWN", metric="m",
        scope=GateScope.FAST, evaluate_level=GateLevel.PASS,
    )
    # No benchmark named UNKNOWN in the input.
    verdict = GateEvaluator(lambda: [g]).evaluate("fast", [])
    assert verdict.gate_passed is True
    assert verdict.summary.skipped == 1
    assert verdict.outcomes[0].level is GateLevel.SKIPPED


def test_evaluator_runs_all_gates_and_orders_outcomes():
    """Every gate factory must produce one outcome, in registration order."""
    g1 = _make_gate(
        name="first", benchmark="B", metric="m1",
        scope=GateScope.ANY, evaluate_level=GateLevel.PASS,
    )
    g2 = _make_gate(
        name="second", benchmark="B", metric="m2",
        scope=GateScope.ANY, evaluate_level=GateLevel.WARN,
    )
    g3 = _make_gate(
        name="third", benchmark="B", metric="m3",
        scope=GateScope.ANY, evaluate_level=GateLevel.FAIL,
    )
    benches = [
        _bench("B", [_metric("m1"), _metric("m2"), _metric("m3")]),
    ]
    verdict = GateEvaluator(lambda: [g1, g2, g3]).evaluate("fast", benches)
    assert [o.gate for o in verdict.outcomes] == ["first", "second", "third"]
    assert verdict.gate_passed is False  # m3 FAILed in scope ANY
