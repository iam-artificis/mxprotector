"""Gate: claripy-only simplifier rate ≥ 80 % FAILs the slow tier.

Per ``MCP.md`` Mutation / MBA table:

    | msynth simplification rate | ↓ | msynth | FAIL ≥80% |

claripy's static rewrite pipeline is the always-on baseline peer in
the P7 ensemble. It is *not* MBA-aware — it only collapses
``a + 0`` / ``-(-a)`` / etc. — so a high simplification rate here
means the handlers leak even more elementary algebra than MBA-aware
tools would expect.

Slow-tier. Same 80 % FAIL threshold as the pattern peer; mirroring
keeps the two rows on the chart at the same scale.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class MbaClaripySimplificationGate(IGate):
    """FAIL when ≥80 % of handlers collapse under stock claripy."""

    name: ClassVar[str] = "mba_claripy_simplification"
    description: ClassVar[str] = (
        "Block the slow tier when the p90 ClaripySimplifier "
        "simplification rate is ≥ 0.80 — handlers leak elementary "
        "algebra even claripy collapses, before any MBA solver runs."
    )
    benchmark: ClassVar[str] = "vm_mba"
    metric: ClassVar[str] = "vm_mba_claripy_simplification_rate"
    scope: ClassVar[GateScope] = GateScope.SLOW

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return upper_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_at=0.80,
            warn_at=0.60,
            fail_message=(
                "Handler resistance broken — claripy alone collapses "
                "≥80 % of handler outputs."
            ),
            warn_message=(
                "Handler resistance regressing — claripy collapses "
                "≥60 % of handlers."
            ),
            pass_message=(
                "Handler resistance holds — claripy collapses "
                "<60 % of handlers."
            ),
        )
