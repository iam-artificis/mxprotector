"""Gate: any forbidden-literal hit FAILs every tier.

Cross-cutting (``GateScope.ANY``) gate that complements the
:mod:`mx_mcp.invariants.no_protector_metadata_leaked` invariant.
Where the invariant is a per-binary check fed into
``verify_protection_invariants``, this gate watches the corpus-wide
benchmark surface (``leakage_surface``): any non-zero count of
protector-identifying literals across the corpus FAILs both fast
and slow tiers.

We hard-fail here even though the invariant already does so per
sample — a CI runner that calls ``run_tier`` without first running
``verify_protection_invariants`` would otherwise miss the regression.
The double-coverage is intentional: leakage is the cheapest
regression to introduce and the most expensive to find via attacker
review later.

Both fast and slow tiers ship the ``leakage_surface`` benchmark
(``tier=fast``); the gate is scoped ``ANY`` so the slow tier picks
it up too via the ``measure_defense`` filter.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class LeakageForbiddenLiteralGate(IGate):
    """FAIL when any corpus entry leaks a forbidden literal."""

    name: ClassVar[str] = "leakage_forbidden_literal"
    description: ClassVar[str] = (
        "Block any tier when the leakage_surface benchmark records ≥1 "
        "forbidden-literal hit across the corpus — protector identity "
        "is leaking into shipped PEs."
    )
    benchmark: ClassVar[str] = "leakage_surface"
    metric: ClassVar[str] = "leaked_forbidden_literal_count"
    scope: ClassVar[GateScope] = GateScope.ANY

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return upper_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_at=0.5,           # >0 hits → FAIL (counts are integers)
            warn_at=None,
            fail_message=(
                "Forbidden literals leaking into shipped PEs — see "
                "leakage_surface evidence for the per-literal breakdown."
            ),
            warn_message="",
            pass_message="No forbidden literals detected across the corpus.",
        )
