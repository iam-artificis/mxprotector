"""Shared threshold helpers for the gate catalogue.

Concrete gates lean on these to avoid duplicating "pick the right
aggregate / compare against threshold / build a fail-closed outcome
when the metric is missing" boilerplate. Kept here (not on the
:mod:`gate_base` ABC) so the public contract stays minimal — gates
that want bespoke logic can ignore this module entirely.

## Aggregate selection

Per ``MCP.md`` "Corpus-based: distributions over ≥10 samples; gates
use p90." For ``FALSE_BEST`` rate metrics (booleans surfaced through
the standard scale) gates compare ``mean`` instead — i.e. the failure
rate across the corpus — because p90 of a bool is not informative.

## Fail-closed semantics

A metric whose ``aggregate.p10/p50/p90/mean`` is ``None`` (every
sample errored) yields a SKIPPED outcome. The runner aggregates
SKIPPED separately so callers see "the gate did not run" rather
than "the build cleared the gate".
"""

from __future__ import annotations

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    MetricDirection,
    MetricResult,
)
from mx_mcp.common.gate_base import GateLevel, GateOutcome, GateScope


def select_observed(metric: MetricResult) -> float | None:
    """Return the aggregate value the gate should compare to its threshold.

    * ``higher_better`` / ``lower_better`` → ``aggregate.p90`` (matches
      the corpus-based gate model).
    * ``false_best`` → ``aggregate.mean`` (failure rate is the right
      view for booleans; p90 of a bool is information-poor).

    Returns ``None`` when the relevant aggregate is missing — every
    sample errored. Callers translate this to SKIPPED.
    """
    agg: AggregateStats = metric.aggregate
    if metric.direction is MetricDirection.FALSE_BEST:
        return agg.mean
    return agg.p90


def skipped_outcome(
    *,
    gate: str,
    benchmark: str,
    metric: str,
    scope: GateScope,
    threshold_repr: str,
    reason: str,
) -> GateOutcome:
    """Build a SKIPPED outcome — the metric was unavailable.

    ``reason`` is surfaced as the outcome message so reviewers can
    tell "no corpus matched" from "every sample errored".
    """
    return GateOutcome(
        gate=gate,
        benchmark=benchmark,
        metric=metric,
        level=GateLevel.SKIPPED,
        scope=scope,
        threshold_repr=threshold_repr,
        observed=None,
        message=reason,
    )


def upper_bound_outcome(
    *,
    gate: str,
    benchmark: str,
    metric: str,
    scope: GateScope,
    metric_result: MetricResult,
    fail_at: float,
    warn_at: float | None,
    fail_message: str,
    warn_message: str,
    pass_message: str,
) -> GateOutcome:
    """Outcome where lower is better and a high observed value FAILs.

    ``fail_at`` is inclusive — ``observed >= fail_at`` → FAIL.
    ``warn_at`` (if set) is also inclusive — ``observed >= warn_at``
    that did not yet trip ``fail_at`` → WARN.

    Used by gates like ``vm_handler_summarization_rate`` (FAIL ≥ 0.7)
    or ``mba_pattern_simplification_rate`` (FAIL ≥ 0.8). The
    ``threshold_repr`` is always ``"observed < {fail_at}"`` plus an
    optional ``"warn ≥ {warn_at}"`` annotation.
    """
    observed = select_observed(metric_result)
    threshold_repr = f"observed < {fail_at}"
    if warn_at is not None:
        threshold_repr += f" (warn ≥ {warn_at})"

    if observed is None:
        return skipped_outcome(
            gate=gate, benchmark=benchmark, metric=metric, scope=scope,
            threshold_repr=threshold_repr,
            reason=("metric unavailable — every corpus sample errored "
                    "or no entries matched"),
        )

    evidence = {
        "fail_at":     fail_at,
        "warn_at":     warn_at,
        "n_samples":   metric_result.aggregate.n_samples,
        "n_errors":    metric_result.aggregate.n_errors,
    }
    if observed >= fail_at:
        return GateOutcome(
            gate=gate, benchmark=benchmark, metric=metric, scope=scope,
            level=GateLevel.FAIL, threshold_repr=threshold_repr,
            observed=observed, message=fail_message, evidence=evidence,
        )
    if warn_at is not None and observed >= warn_at:
        return GateOutcome(
            gate=gate, benchmark=benchmark, metric=metric, scope=scope,
            level=GateLevel.WARN, threshold_repr=threshold_repr,
            observed=observed, message=warn_message, evidence=evidence,
        )
    return GateOutcome(
        gate=gate, benchmark=benchmark, metric=metric, scope=scope,
        level=GateLevel.PASS, threshold_repr=threshold_repr,
        observed=observed, message=pass_message, evidence=evidence,
    )


def lower_bound_outcome(
    *,
    gate: str,
    benchmark: str,
    metric: str,
    scope: GateScope,
    metric_result: MetricResult,
    fail_below: float,
    warn_below: float | None,
    fail_message: str,
    warn_message: str,
    pass_message: str,
) -> GateOutcome:
    """Outcome where higher is better and a low observed value FAILs.

    ``fail_below`` is inclusive on the FAIL side: ``observed <= fail_below``
    → FAIL. ``warn_below`` similarly. Used for HIGHER_BETTER metrics
    like ``budget_to_crack_steps_to_oep`` (FAIL ≤ 100 steps).
    """
    observed = select_observed(metric_result)
    threshold_repr = f"observed > {fail_below}"
    if warn_below is not None:
        threshold_repr += f" (warn ≤ {warn_below})"

    if observed is None:
        return skipped_outcome(
            gate=gate, benchmark=benchmark, metric=metric, scope=scope,
            threshold_repr=threshold_repr,
            reason=("metric unavailable — every corpus sample errored "
                    "or no entries matched"),
        )

    evidence = {
        "fail_below":  fail_below,
        "warn_below":  warn_below,
        "n_samples":   metric_result.aggregate.n_samples,
        "n_errors":    metric_result.aggregate.n_errors,
    }
    if observed <= fail_below:
        return GateOutcome(
            gate=gate, benchmark=benchmark, metric=metric, scope=scope,
            level=GateLevel.FAIL, threshold_repr=threshold_repr,
            observed=observed, message=fail_message, evidence=evidence,
        )
    if warn_below is not None and observed <= warn_below:
        return GateOutcome(
            gate=gate, benchmark=benchmark, metric=metric, scope=scope,
            level=GateLevel.WARN, threshold_repr=threshold_repr,
            observed=observed, message=warn_message, evidence=evidence,
        )
    return GateOutcome(
        gate=gate, benchmark=benchmark, metric=metric, scope=scope,
        level=GateLevel.PASS, threshold_repr=threshold_repr,
        observed=observed, message=pass_message, evidence=evidence,
    )


__all__ = [
    "lower_bound_outcome",
    "select_observed",
    "skipped_outcome",
    "upper_bound_outcome",
]
