"""Gate: any successful Unicorn OEP-reach FAILs the fast tier.

Per ``MCP.md`` Packer table:

    | Unicorn OEP-reach | false-best | Unicorn | FAIL on reach |

A protected build whose packer stub runs cleanly under stock
Unicorn — no PEB-walk crash, no IAT trip — is one a script kiddie
can unpack with a 50-line emulator harness. Any non-zero corpus
rate FAILs.

Fast tier per the underlying benchmark.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class UnicornOepReachGate(IGate):
    """FAIL when Unicorn reached the original entry point on any entry."""

    name: ClassVar[str] = "unicorn_oep_reach"
    description: ClassVar[str] = (
        "Block the fast tier when Unicorn landed PC at the original entry "
        "point on at least one corpus entry — the packer stub tolerated "
        "stock emulation through to the OEP."
    )
    benchmark: ClassVar[str] = "unicorn_oep_reach"
    metric: ClassVar[str] = "unicorn_oep_reached"
    scope: ClassVar[GateScope] = GateScope.FAST

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
                "Packer / OS coupling weak — Unicorn reached OEP on at "
                "least one entry. Inspect evidence for the failing samples."
            ),
            warn_message="",
            pass_message=(
                "Packer / OS coupling holds — Unicorn never reached OEP."
            ),
        )
