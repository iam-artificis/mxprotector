"""Unit tests for ``shipgate.runner``.

Stubs out :class:`MeasureDefenseTool` and the gate registry so the
runner test exercises *just* the orchestration layer: tier forcing,
result wrapping, empty-result note.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
)
from mx_mcp.common.gate_base import (
    GateLevel,
    GateScope,
    IGate,
)
from mx_mcp.shipgate.evaluator import GateEvaluator
from mx_mcp.shipgate.runner import TierRunner
from mx_mcp.tools.measure_defense import (
    MeasureDefenseInput,
    MeasureDefenseOutput,
)


# ============================================================================
# Stubs
# ============================================================================


class _StubMeasureTool:
    """Records what tier was forwarded; emits a canned MeasureDefenseOutput."""

    def __init__(self, *, benchmarks: list[BenchmarkResult]) -> None:
        self._benchmarks = benchmarks
        self.last_args: MeasureDefenseInput | None = None

    async def run(self, args, session):
        self.last_args = args
        return MeasureDefenseOutput(
            corpus_path=str(session.workspace_root / "corpus"),
            corpus_size=0,
            benchmark_count=len(self._benchmarks),
            duration_ms=1,
            benchmarks=self._benchmarks,
            notes=[],
        )


def _bench(name: str, metric: MetricResult) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark=name, category="x", tier="fast",
        duration_ms=0, metrics=[metric], errors=[],
    )


def _metric(*, p90: float = 0.1) -> MetricResult:
    return MetricResult(
        name="m", direction=MetricDirection.LOWER_BETTER, samples=[],
        aggregate=AggregateStats(
            p10=None, p50=None, p90=p90, mean=p90, stddev=None,
            n_samples=1, n_errors=0,
        ),
    )


def _make_passing_gate(*, name: str, scope: GateScope) -> type[IGate]:
    class _G(IGate):
        description = "stub"

        def evaluate(self, mr):
            from mx_mcp.common.gate_base import GateOutcome
            return GateOutcome(
                gate=self.name, benchmark=self.benchmark, metric=self.metric,
                level=GateLevel.PASS, scope=self.scope,
                threshold_repr="x", observed=mr.aggregate.p90,
                message="ok",
            )

    _G.name = name
    _G.benchmark = "B"
    _G.metric = "m"
    _G.scope = scope
    return _G


def _session(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=tmp_path)


# ============================================================================
# Tests
# ============================================================================


def test_runner_forces_tier_onto_measure_args(tmp_path):
    measure = _StubMeasureTool(benchmarks=[_bench("B", _metric())])
    evaluator = GateEvaluator(
        lambda: [_make_passing_gate(name="g", scope=GateScope.FAST)],
    )
    runner = TierRunner(measure_tool=measure, evaluator=evaluator)
    overrides = MeasureDefenseInput(tier="slow", level="standard")

    result = asyncio.run(runner.run(
        tier="fast", session=_session(tmp_path), measure_overrides=overrides,
    ))

    assert measure.last_args is not None
    # Tier was overridden.
    assert measure.last_args.tier == "fast"
    # Other knob preserved.
    assert measure.last_args.level == "standard"
    assert result.verdict.gate_passed is True


def test_runner_constructs_default_args_when_none_given(tmp_path):
    measure = _StubMeasureTool(benchmarks=[])
    evaluator = GateEvaluator(lambda: [])
    runner = TierRunner(measure_tool=measure, evaluator=evaluator)

    asyncio.run(runner.run(tier="fast", session=_session(tmp_path)))

    assert measure.last_args is not None
    assert measure.last_args.tier == "fast"
    assert measure.last_args.level == "strong"   # default in MeasureDefenseInput


def test_runner_emits_note_on_zero_benchmarks(tmp_path):
    measure = _StubMeasureTool(benchmarks=[])
    evaluator = GateEvaluator(lambda: [])
    runner = TierRunner(measure_tool=measure, evaluator=evaluator)

    result = asyncio.run(runner.run(tier="fast", session=_session(tmp_path)))

    assert result.verdict.gate_passed is True   # no FAIL → passes
    assert any("zero benchmark" in n for n in result.notes)


def test_runner_returns_full_measurement_payload(tmp_path):
    """Runner must surface the full MeasureDefenseOutput so reviewers
    can drill into per-metric distributions without a second call."""
    benches = [_bench("B", _metric(p90=0.42))]
    measure = _StubMeasureTool(benchmarks=benches)
    evaluator = GateEvaluator(
        lambda: [_make_passing_gate(name="g", scope=GateScope.FAST)],
    )
    runner = TierRunner(measure_tool=measure, evaluator=evaluator)

    result = asyncio.run(runner.run(tier="fast", session=_session(tmp_path)))

    assert result.measurement.benchmark_count == 1
    assert result.measurement.benchmarks[0].benchmark == "B"
