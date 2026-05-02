"""Gate: detection-coverage rate ≤ 0.40 FAILs the slow tier.

Per ``MCP.md`` cross-cutting Anti-analysis table:

    | Detection coverage {…} | ↑ | anti_analysis/coverage | FAIL < threshold |

The benchmark emits ``anti_analysis_coverage_rate`` (HIGHER_BETTER).
The gate threshold sits at 0.40 — the protector should defend
against at least two-of-the-five detectors. The 0.60 warn band
nudges before a regression actually breaches.

Slow tier per the underlying benchmark.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import lower_bound_outcome


@register_gate
class AntiAnalysisCoverageGate(IGate):
    """FAIL when fewer than ~40 % of anti-analysis detectors fire."""

    name: ClassVar[str] = "anti_analysis_coverage"
    description: ClassVar[str] = (
        "Block the slow tier when the p90 anti-analysis detection "
        "coverage rate is ≤ 0.40 — the protector defends against "
        "fewer than two of the five tool families."
    )
    benchmark: ClassVar[str] = "anti_analysis_coverage"
    metric: ClassVar[str] = "anti_analysis_coverage_rate"
    scope: ClassVar[GateScope] = GateScope.SLOW

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return lower_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_below=0.40,
            warn_below=0.60,
            fail_message=(
                "Anti-analysis surface too narrow — coverage rate ≤ 0.40 "
                "across the corpus. Protector defends against fewer than "
                "two of the five tool families."
            ),
            warn_message=(
                "Anti-analysis surface regressing — coverage ≤ 0.60 but "
                "still over the FAIL threshold."
            ),
            pass_message=(
                "Anti-analysis surface holds — coverage > 0.60 across the corpus."
            ),
        )
