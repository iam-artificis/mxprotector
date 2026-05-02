"""MCP tool: run one tier and return the ship-gate verdict.

Single agent-facing entry point for P8 (MCP.md tier runners +
ship-gate). Wraps :class:`~mx_mcp.shipgate.runner.TierRunner` so a
CI caller can ask "may this commit ship under tier ``fast``?" or
"may this branch merge under tier ``slow``?" and read a single
``gate_passed`` bool from the response.

The tool internally runs ``measure_defense`` filtered to the
requested tier, walks the registered :mod:`mx_mcp.gates` against
the result, and aggregates per-gate outcomes into a
:class:`~mx_mcp.shipgate.evaluator.TierVerdict`.

## Output shape

Two top-level fields:

* ``verdict.gate_passed`` — the bool every CI runner ultimately
  reads. ``False`` iff at least one gate FAILed in scope for the
  requested tier.
* ``measurement`` — the full ``MeasureDefenseOutput`` so reviewers
  can drill into per-metric distributions without a second
  round-trip.

The verdict's ``outcomes`` list carries one
:class:`~mx_mcp.common.gate_base.GateOutcome` per registered gate;
the ``summary`` rolls them up into pass / warn / fail / skipped
counts.

## Tier semantics

Per ``MCP.md``:

* ``fast`` — every build, hard budget <5 min. **Failure blocks commit.**
* ``slow`` — pre-PR review, budget <30 min. **Failure blocks merge.**

The tier value is mandatory — there is no "all tiers" mode here.
Mixing fast + slow gates would defeat the scope-downgrade logic
that prevents a slow-only gate from blocking a commit.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from mx_mcp.common.tiers import parse_tier
from mx_mcp.common.tool_base import ITool, register_tool
from mx_mcp.shipgate.runner import TierRunResult, TierRunner
from mx_mcp.tools.measure_defense import (
    DEFAULT_TIMEOUT_S,
    MeasureDefenseInput,
)


_LOG = logging.getLogger(__name__)


# ============================================================================
# I/O schema
# ============================================================================


class RunTierInput(BaseModel):
    """Inputs forwarded to the underlying ``measure_defense`` plus tier."""

    tier: str = Field(
        description=(
            "Tier to run — ``fast`` (block-on-fail = block commit) or "
            "``slow`` (block-on-fail = block merge). ``nightly`` is "
            "reserved (FUTURE.md)."
        ),
    )
    corpus_path: str | None = Field(
        default=None,
        description=(
            "Override the corpus root (absolute or workspace-relative). "
            "Default: mcp/fixtures/corpus relative to the workspace root."
        ),
    )
    level: str = Field(
        default="strong",
        description="Protection level forwarded to the builder.",
    )
    builder_args: list[str] = Field(
        default_factory=list,
        description="Extra CLI args forwarded to mxprotector_builder.",
    )
    timeout_s: float = Field(
        default=DEFAULT_TIMEOUT_S,
        description=(
            "Outer timeout (seconds) for the whole tier run. Acts as a "
            "cap on the underlying measure_defense call; per-benchmark "
            "budgets live on the benchmark side."
        ),
    )
    snapshot: bool = Field(
        default=True,
        description=(
            "Persist the underlying measurement as a snapshot. Same "
            "semantics as measure_defense's flag."
        ),
    )
    snapshots_root: str | None = Field(
        default=None,
        description=(
            "Override for the snapshot store root; default "
            "``mcp/reports/snapshots``."
        ),
    )


class RunTierOutput(BaseModel):
    """Returned shape — wraps :class:`TierRunResult` for MCP transport."""

    result: TierRunResult


# ============================================================================
# Tool
# ============================================================================


@register_tool
class RunTierTool(ITool[RunTierInput, RunTierOutput]):
    """Execute one tier and emit the ship-gate verdict."""

    name = "run_tier"
    description = (
        "Run one tier (fast | slow) end-to-end: measure registered "
        "benchmarks, walk registered ship-gates, aggregate per-gate "
        "outcomes (pass / warn / fail / skipped), and return a single "
        "verdict.gate_passed bool. Fast FAIL → block commit, "
        "slow FAIL → block merge. Returns the full underlying "
        "measurement for drill-down."
    )
    input_schema = RunTierInput
    output_schema = RunTierOutput

    def __init__(self, runner: TierRunner | None = None) -> None:
        self._runner = runner or TierRunner()

    async def run(self, args: RunTierInput, session) -> RunTierOutput:
        # Validate the tier eagerly so a typo surfaces with the
        # "expected one of" hint rather than as "no benchmarks
        # matched filter" deeper in measure_defense.
        tier = parse_tier(args.tier)

        measure_overrides = MeasureDefenseInput(
            corpus_path=args.corpus_path,
            level=args.level,
            builder_args=list(args.builder_args),
            timeout_s=args.timeout_s,
            snapshot=args.snapshot,
            snapshots_root=args.snapshots_root,
        )
        result = await self._runner.run(
            tier=tier.value,
            session=session,
            measure_overrides=measure_overrides,
        )
        _LOG.info(
            "run_tier(%s) → gate_passed=%s",
            tier.value, result.verdict.gate_passed,
        )
        return RunTierOutput(result=result)


__all__ = [
    "RunTierInput",
    "RunTierOutput",
    "RunTierTool",
]
