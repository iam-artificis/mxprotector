"""Gate: any angr-reached OEP FAILs the slow tier.

Per ``MCP.md`` Budget-to-crack table:

    | angr symbolic steps to reach OEP | ↑ | angr | warn on regression |

The numeric step-count metric warns rather than blocks (a build that
takes fewer steps but still does not reach is informational). The
binary "did angr reach OEP at all within budget?" sister metric is
the hard block: a successful symbolic walk to OEP means the packer
stub is symbolically tractable, which voids most of the runtime
defence narrative.

Slow tier per the underlying benchmark.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class BudgetToCrackOepGate(IGate):
    """FAIL when angr reached OEP on any corpus entry within budget."""

    name: ClassVar[str] = "budget_to_crack_oep_reached"
    description: ClassVar[str] = (
        "Block the slow tier when angr's symbolic walk reached the "
        "original entry point on at least one corpus entry within "
        "budget — the stub is symbolically tractable."
    )
    benchmark: ClassVar[str] = "budget_to_crack_oep"
    metric: ClassVar[str] = "budget_to_crack_oep_reached"
    scope: ClassVar[GateScope] = GateScope.SLOW

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return upper_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_at=0.0001,
            warn_at=None,
            fail_message=(
                "Symbolic OEP-reach succeeded on at least one entry — "
                "stub is symbolically tractable within slow-tier budget."
            ),
            warn_message="",
            pass_message="Symbolic OEP-reach failed on every corpus entry.",
        )
