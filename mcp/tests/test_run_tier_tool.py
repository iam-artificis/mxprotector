"""Unit tests for ``tools.run_tier``.

Verifies the MCP tool wraps the TierRunner correctly: tier validation,
input → measurement override forwarding, and output shape.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
)
from mx_mcp.shipgate.evaluator import GateEvaluator, TierVerdict
from mx_mcp.shipgate.runner import TierRunner, TierRunResult
from mx_mcp.tools.measure_defense import MeasureDefenseOutput
from mx_mcp.tools.run_tier import (
    RunTierInput,
    RunTierOutput,
    RunTierTool,
)


# ============================================================================
# Stubs
# ============================================================================


class _StubRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def run(self, *, tier, session, measure_overrides=None):
        self.calls.append((tier, measure_overrides))
        return TierRunResult(
            verdict=TierVerdict(
                tier=tier, gate_passed=True,
                summary={"passed": 0, "warn": 0, "fail": 0, "skipped": 0},
                outcomes=[], notes=[],
            ),
            measurement=MeasureDefenseOutput(
                corpus_path=str(session.workspace_root / "corpus"),
                corpus_size=0, benchmark_count=0,
                duration_ms=1, benchmarks=[],
                notes=[],
            ),
            notes=[],
        )


def _session(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=tmp_path)


# ============================================================================
# Tests
# ============================================================================


def test_tool_rejects_unknown_tier(tmp_path):
    """Tier validation surfaces with the helpful 'expected one of' error."""
    tool = RunTierTool(runner=_StubRunner())
    with pytest.raises(ValueError, match="expected one of"):
        asyncio.run(tool.run(
            RunTierInput(tier="warpdrive"), _session(tmp_path),
        ))


def test_tool_forwards_args_to_runner(tmp_path):
    runner = _StubRunner()
    tool = RunTierTool(runner=runner)
    args = RunTierInput(
        tier="slow",
        corpus_path="alt/corpus",
        level="standard",
        builder_args=["--extra"],
        timeout_s=42.0,
        snapshot=False,
        snapshots_root="/tmp/snaps",
    )
    asyncio.run(tool.run(args, _session(tmp_path)))

    assert len(runner.calls) == 1
    tier, overrides = runner.calls[0]
    assert tier == "slow"
    assert overrides is not None
    assert overrides.corpus_path == "alt/corpus"
    assert overrides.level == "standard"
    assert overrides.builder_args == ["--extra"]
    assert overrides.timeout_s == 42.0
    assert overrides.snapshot is False
    assert overrides.snapshots_root == "/tmp/snaps"


def test_tool_returns_run_tier_output(tmp_path):
    tool = RunTierTool(runner=_StubRunner())
    out = asyncio.run(tool.run(RunTierInput(tier="fast"), _session(tmp_path)))
    assert isinstance(out, RunTierOutput)
    assert out.result.verdict.tier == "fast"
    assert out.result.verdict.gate_passed is True


def test_tool_class_metadata_is_well_formed():
    assert RunTierTool.name == "run_tier"
    assert RunTierTool.input_schema is RunTierInput
    assert RunTierTool.output_schema is RunTierOutput
    assert "block commit" in RunTierTool.description
    assert "block merge" in RunTierTool.description


def test_input_validates_required_tier_field():
    """Tier is mandatory — pydantic must reject input without it."""
    with pytest.raises(ValidationError):
        RunTierInput()  # type: ignore[call-arg]
