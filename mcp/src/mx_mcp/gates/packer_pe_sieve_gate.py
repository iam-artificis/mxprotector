"""Gate: any clean pe-sieve dump FAILs the fast tier.

Per ``MCP.md`` Packer table:

    | pe-sieve dump success | false-best | pe-sieve | FAIL on clean dump |

A pe-sieve dump that comes back clean means the runtime PE state
matched the on-disk PE — i.e. the packer's runtime obfuscation did
not survive a stock dump. Any non-zero rate across the corpus is a
hard FAIL, no warn band: a partial leak is still a leak.

Fast-tier — pe-sieve runs in seconds and the benchmark is wired
under the fast budget (see ``packer_benchmark.py``).
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class PackerPeSieveDumpGate(IGate):
    """FAIL when pe-sieve dumped any module cleanly on any corpus entry."""

    name: ClassVar[str] = "packer_pe_sieve_dump"
    description: ClassVar[str] = (
        "Block the fast tier when pe-sieve produced a clean PE dump on at "
        "least one corpus entry — the packer's runtime obfuscation did not "
        "survive a stock memory dump."
    )
    benchmark: ClassVar[str] = "packer_pesieve"
    metric: ClassVar[str] = "pesieve_dumped_modules"
    scope: ClassVar[GateScope] = GateScope.FAST

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return upper_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_at=0.0001,        # any non-zero failure rate
            warn_at=None,          # no soft band — clean dump is binary
            fail_message=(
                "Packer compromised — pe-sieve dumped at least one entry "
                "cleanly. Inspect evidence for the failing samples."
            ),
            warn_message="",       # unused; no warn band
            pass_message="Packer holds — every pe-sieve dump came back broken.",
        )
