"""Gate aggregation — pure function over BenchmarkResult.

Walks every registered :class:`~mx_mcp.common.gate_base.IGate`,
matches it against the right ``BenchmarkResult.metrics`` row, and
collects per-gate :class:`~mx_mcp.common.gate_base.GateOutcome`s
into a :class:`TierVerdict`.

## Tier-scope downgrade

A FAIL outcome on a gate scoped to a different tier than the
caller's run is *downgraded to WARN* — the gate's threshold may be
authoritative for the slow tier but blocking the fast tier on it
would be a UX bug. The downgrade is recorded in the outcome's
message so reviewers can see what happened.

## Missing benchmark / metric

If a registered gate's ``(benchmark, metric)`` does not match any
row in the input results, the gate emits a SKIPPED outcome. This
distinguishes "tier did not run the benchmark" from "the gate
passed". Callers see SKIPPED counts alongside PASS/WARN/FAIL.

## Determinism

Gates run in registration order; the verdict's outcome list is
stable across runs as long as the gate registry is. Tests can pin
ordering via the ``gate_factories`` injection seam.
"""

from __future__ import annotations

import logging
from typing import Callable

from pydantic import BaseModel, Field

from mx_mcp.common.benchmark_base import BenchmarkResult, MetricResult
from mx_mcp.common.gate_base import (
    GateLevel,
    GateOutcome,
    GateScope,
    IGate,
    all_gates,
)


_LOG = logging.getLogger(__name__)


# Test-injection seam: the runner can swap the gate source for a
# subset/mock catalog without monkeypatching ``all_gates``.
GateFactory = Callable[[], list[type[IGate]]]


# ============================================================================
# Verdict models
# ============================================================================


class VerdictSummary(BaseModel):
    """Counts per :class:`GateLevel` — quick at-a-glance readout.

    Field name ``passed`` (rather than ``pass``) avoids the Python
    reserved-word collision while keeping the JSON shape readable for
    downstream consumers.
    """

    passed: int = 0
    warn: int = 0
    fail: int = 0
    skipped: int = 0


class TierVerdict(BaseModel):
    """Aggregate ship-gate verdict for one tier run.

    ``gate_passed`` is true iff zero blocking-FAIL outcomes were
    recorded (gates whose scope matches the run tier *or* ANY).
    Non-blocking FAILs (slow-only gates during a fast run) are
    downgraded to WARN before counting.
    """

    tier: str
    gate_passed: bool
    summary: VerdictSummary
    outcomes: list[GateOutcome] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# ============================================================================
# Evaluator
# ============================================================================


class GateEvaluator:
    """Run every registered gate against a list of benchmark results.

    Stateless. Tests inject a custom :data:`gate_factories` to limit
    the catalog to specific gates.
    """

    def __init__(self, gate_factories: GateFactory | None = None) -> None:
        self._gate_factories = gate_factories or all_gates

    def evaluate(
        self,
        tier: str,
        benchmarks: list[BenchmarkResult],
    ) -> TierVerdict:
        """Aggregate gate outcomes into a :class:`TierVerdict`.

        ``tier`` must be ``"fast"`` or ``"slow"``. The evaluator does
        not validate it (the caller already does so via
        :func:`~mx_mcp.common.tiers.parse_tier`); it is used to
        decide blocking scope per outcome.
        """
        metrics_by_key = _index_metrics(benchmarks)

        outcomes: list[GateOutcome] = []
        notes: list[str] = []
        for gate_cls in self._gate_factories():
            outcome = self._evaluate_one(gate_cls, tier, metrics_by_key, notes)
            outcomes.append(outcome)

        summary = _summarise(outcomes)
        gate_passed = summary.fail == 0
        _LOG.info(
            "shipgate %s — pass=%d warn=%d fail=%d skipped=%d (passed=%s)",
            tier, summary.passed, summary.warn, summary.fail,
            summary.skipped, gate_passed,
        )
        return TierVerdict(
            tier=tier,
            gate_passed=gate_passed,
            summary=summary,
            outcomes=outcomes,
            notes=notes,
        )

    # ------------------------------------------------------------------

    def _evaluate_one(
        self,
        gate_cls: type[IGate],
        tier: str,
        metrics_by_key: dict[tuple[str, str], MetricResult],
        notes: list[str],
    ) -> GateOutcome:
        """Run one gate, applying tier-scope downgrade as needed."""
        gate = gate_cls()
        key = (gate.benchmark, gate.metric)
        metric = metrics_by_key.get(key)
        if metric is None:
            return GateOutcome(
                gate=gate.name,
                benchmark=gate.benchmark,
                metric=gate.metric,
                level=GateLevel.SKIPPED,
                scope=gate.scope,
                threshold_repr="(metric not present in tier output)",
                observed=None,
                message=(
                    f"benchmark/metric '{gate.benchmark}/{gate.metric}' "
                    f"missing from this tier's measurement output"
                ),
            )

        outcome = gate.evaluate(metric)
        return _downgrade_out_of_scope(outcome, tier, notes)


# ============================================================================
# Helpers — module-level so tests can exercise them directly.
# ============================================================================


def _index_metrics(
    benchmarks: list[BenchmarkResult],
) -> dict[tuple[str, str], MetricResult]:
    """Build a ``(benchmark_name, metric_name) → MetricResult`` index.

    Duplicate benchmark/metric pairs across the input list keep the
    last value seen — the input is normally produced by
    measure_defense which emits each benchmark exactly once, so a
    duplicate is a programmer error worth letting the index quietly
    coalesce.
    """
    out: dict[tuple[str, str], MetricResult] = {}
    for bench in benchmarks:
        for metric in bench.metrics:
            out[(bench.benchmark, metric.name)] = metric
    return out


def _summarise(outcomes: list[GateOutcome]) -> VerdictSummary:
    """Count outcomes per level."""
    counts = VerdictSummary()
    for o in outcomes:
        if o.level is GateLevel.PASS:
            counts.passed += 1
        elif o.level is GateLevel.WARN:
            counts.warn += 1
        elif o.level is GateLevel.FAIL:
            counts.fail += 1
        else:
            counts.skipped += 1
    return counts


def _downgrade_out_of_scope(
    outcome: GateOutcome, tier: str, notes: list[str],
) -> GateOutcome:
    """Downgrade FAILs whose scope does not include ``tier`` to WARN.

    The evaluator records a one-line note per downgrade so reviewers
    can see why a gate that "should" block is showing up as warn —
    it is authoritative for a different tier.
    """
    if outcome.level is not GateLevel.FAIL:
        return outcome
    if outcome.scope is GateScope.ANY or outcome.scope.value == tier:
        return outcome

    notes.append(
        f"gate '{outcome.gate}' FAILed but is scoped to the "
        f"'{outcome.scope.value}' tier; downgraded to WARN for this "
        f"'{tier}' run"
    )
    return outcome.model_copy(update={
        "level": GateLevel.WARN,
        "message": (
            f"{outcome.message} (downgraded — gate is scoped to "
            f"'{outcome.scope.value}' tier, run is '{tier}')"
        ),
    })


__all__ = [
    "GateEvaluator",
    "TierVerdict",
    "VerdictSummary",
]
