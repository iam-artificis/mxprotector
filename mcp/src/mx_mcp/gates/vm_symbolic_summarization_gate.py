"""Gate: angr handler-summarization rate ≥ 70 % FAILs the slow tier.

Per ``MCP.md`` VM table:

    | angr handler-summarization rate (p90) | ↓ | angr | FAIL ≥70% |

If ≥70 % of sampled handlers can be walked to completion by stock
angr inside the per-handler budget, the VM defence has been
effectively broken — an attacker armed with the same backend would
collapse most handlers symbolically. Slow-tier gate (the underlying
benchmark is ``slow``).

We add a soft warn band at 50 % so a regression that is creeping
toward FAIL surfaces before it actually breaches.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class VmSymbolicSummarizationGate(IGate):
    """FAIL when ≥70 % of handlers fall to stock angr."""

    name: ClassVar[str] = "vm_symbolic_summarization"
    description: ClassVar[str] = (
        "Block the slow tier when the p90 angr handler-summarisation rate "
        "across the corpus is ≥ 0.70 — defence has effectively collapsed."
    )
    benchmark: ClassVar[str] = "vm_symbolic"
    metric: ClassVar[str] = "vm_handler_summarization_rate"
    scope: ClassVar[GateScope] = GateScope.SLOW

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return upper_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_at=0.70,
            warn_at=0.50,
            fail_message=(
                "VM resistance broken — angr summarises ≥70 % of handlers "
                "within budget."
            ),
            warn_message=(
                "VM resistance regressing — angr summarises ≥50 % of handlers "
                "but still under the FAIL threshold."
            ),
            pass_message="VM resistance holds — angr cracks <50 % of handlers.",
        )
