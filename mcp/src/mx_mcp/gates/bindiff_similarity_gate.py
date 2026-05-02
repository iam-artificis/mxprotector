"""Gate: BinDiff similarity ≥ 70 % FAILs the slow tier.

Per ``MCP.md`` Diffing-resistance table:

    | BinDiff similarity between two seeded builds | ↓ | BinDiff | FAIL ≥70% |

If two consecutive seeded builds end up ≥ 70 % similar under
BinDiff, the protector is failing to diversify across builds — an
attacker building a per-build YARA rule from one sample will catch
every other build with the same primitives.

Slow tier per the diffing benchmark.
"""

from __future__ import annotations

from typing import ClassVar

from mx_mcp.common.benchmark_base import MetricResult
from mx_mcp.common.gate_base import GateOutcome, GateScope, IGate, register_gate
from mx_mcp.gates._thresholds import upper_bound_outcome


@register_gate
class BindiffSimilarityGate(IGate):
    """FAIL when two seeded builds are ≥ 70 % BinDiff-similar."""

    name: ClassVar[str] = "bindiff_similarity"
    description: ClassVar[str] = (
        "Block the slow tier when the p90 BinDiff similarity between "
        "two seeded builds is ≥ 0.70 — protector is not diversifying "
        "enough across builds for per-build YARA rules to fail."
    )
    benchmark: ClassVar[str] = "bindiff_resistance"
    metric: ClassVar[str] = "bindiff_similarity"
    scope: ClassVar[GateScope] = GateScope.SLOW

    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        return upper_bound_outcome(
            gate=self.name,
            benchmark=self.benchmark,
            metric=self.metric,
            scope=self.scope,
            metric_result=metric_result,
            fail_at=0.70,
            warn_at=0.55,
            fail_message=(
                "Diffing resistance broken — two seeded builds are "
                "≥70 % BinDiff-similar."
            ),
            warn_message=(
                "Diffing resistance regressing — similarity is ≥55 % "
                "but still under the FAIL threshold."
            ),
            pass_message=(
                "Diffing resistance holds — seeded builds diverge "
                "below 55 % BinDiff similarity."
            ),
        )
