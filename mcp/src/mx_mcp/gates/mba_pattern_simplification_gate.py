"""Gate: pattern-simplifier rate ≥ 80 % FAILs the slow tier.

Per ``MCP.md`` Mutation / MBA table:

    | SiMBA simplification rate | ↓ | SiMBA | FAIL ≥80% |

The pattern simplifier is the second peer in the P7 ensemble (sister
to claripy). It approximates SiMBA / MBA-Blast's coverage on
classical linear-MBA identities; if 80 % of handlers collapse under
the curated catalog, the protector is leaking obfuscation that any
mainstream MBA tool would unwind.

Slow-tier per the underlying benchmark. Soft warn band at 60 %.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class MbaPatternSimplificationGate(IGate):
    """FAIL when ≥80 % of handlers collapse under the pattern catalog."""

    name: ClassVar[str] = "mba_pattern_simplification"
    description: ClassVar[str] = (
        "Block the slow tier when the p90 PatternSimplifier "
        "simplification rate is ≥ 0.80 — handlers are leaking classical "
        "linear-MBA identities that any mainstream MBA tool unwinds."
    )
    benchmark: ClassVar[str] = "vm_mba"
    metric: ClassVar[str] = "vm_mba_pattern_simplification_rate"
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
                "MBA resistance broken — pattern catalog collapses "
                "≥80 % of handler outputs."
            ),
            warn_message=(
                "MBA resistance regressing — pattern catalog collapses "
                "≥60 % of handlers but still under the FAIL threshold."
            ),
            pass_message=(
                "MBA resistance holds — pattern catalog collapses "
                "<60 % of handlers."
            ),
        )
