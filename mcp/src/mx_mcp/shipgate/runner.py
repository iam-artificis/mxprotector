"""Tier runner — measure + evaluate, return a single ship-gate verdict.

Wires :class:`~mx_mcp.tools.measure_defense.MeasureDefenseTool` to
:class:`~mx_mcp.shipgate.evaluator.GateEvaluator` so a CI caller can
ask one question — "may this commit ship under tier X?" — and get
one answer.

Returns a :class:`TierRunResult` carrying the underlying
:class:`MeasureDefenseOutput` *plus* the
:class:`~mx_mcp.shipgate.evaluator.TierVerdict`. CI usually only
reads ``verdict.gate_passed``; debugging clients walk the full
benchmark output for context.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from mx_mcp.shipgate.evaluator import GateEvaluator, TierVerdict


# ``mx_mcp.tools.measure_defense`` triggers ``mx_mcp.tools/__init__.py``,
# which imports every tool module — including ``tools.run_tier``,
# which imports back into this module. Importing the dependency
# lazily inside the constructor breaks that cycle: by the time
# ``TierRunner.__init__`` runs, the ``tools`` package has finished
# initialising. The TYPE_CHECKING block keeps the imports visible
# to mypy without paying the side-effect at module import time.
if TYPE_CHECKING:
    from mx_mcp.tools.measure_defense import (
        MeasureDefenseInput,
        MeasureDefenseOutput,
        MeasureDefenseTool,
    )


_LOG = logging.getLogger(__name__)


# ============================================================================
# Result model
# ============================================================================


class TierRunResult(BaseModel):
    """One full tier-run output: the verdict + the underlying measurement.

    ``verdict.gate_passed`` is the single bool a CI runner reads to
    decide block-or-allow. ``measurement`` is the full
    ``measure_defense`` output so reviewers can drill into per-metric
    distributions without a second round-trip.
    """

    verdict: TierVerdict
    measurement: "MeasureDefenseOutput"
    notes: list[str] = Field(default_factory=list)


# ============================================================================
# Runner
# ============================================================================


class TierRunner:
    """Run one tier and aggregate the gate verdict.

    Constructor injection seams keep tests fast: production callers
    use the zero-arg defaults and ride the global tool / gate
    registries; tests pass a stub :class:`MeasureDefenseTool` and a
    fixed gate factory.
    """

    def __init__(
        self,
        measure_tool: "MeasureDefenseTool | None" = None,
        evaluator: GateEvaluator | None = None,
    ) -> None:
        if measure_tool is None:
            # Lazy import to break the tools↔shipgate cycle (see top of
            # module). Resolved exactly once when the default tool is
            # constructed; tests inject a stub and skip this path.
            from mx_mcp.tools.measure_defense import MeasureDefenseTool
            measure_tool = MeasureDefenseTool()
        self._measure = measure_tool
        self._evaluator = evaluator or GateEvaluator()

    async def run(
        self,
        *,
        tier: str,
        session: Any,
        measure_overrides: "MeasureDefenseInput | None" = None,
    ) -> TierRunResult:
        """Run measure_defense filtered to ``tier`` and return a verdict.

        ``measure_overrides`` lets the caller set non-tier knobs
        (corpus path, builder args, level, snapshot opt-out, …).
        The runner forces ``tier`` onto whatever the caller passed;
        a tier-runner call MUST be tier-pinned, otherwise the gate
        scope rules become meaningless.
        """
        args = self._build_measure_args(tier, measure_overrides)
        measurement = await self._measure.run(args, session)
        verdict = self._evaluator.evaluate(tier, measurement.benchmarks)

        notes: list[str] = []
        if measurement.benchmark_count == 0:
            notes.append(
                f"tier '{tier}' produced zero benchmark results — "
                f"verdict reflects gates SKIPPED for missing metrics"
            )

        _LOG.info(
            "tier %s run: %d benchmarks, gate_passed=%s",
            tier, measurement.benchmark_count, verdict.gate_passed,
        )
        return TierRunResult(
            verdict=verdict,
            measurement=measurement,
            notes=notes,
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _build_measure_args(
        tier: str,
        overrides: "MeasureDefenseInput | None",
    ) -> "MeasureDefenseInput":
        """Merge overrides + the forced ``tier``.

        We rebuild the model rather than mutate so the input pydantic
        validation still fires on the tier value (and any override
        the caller passed).
        """
        # Lazy import — see __init__ for the cycle-breaking rationale.
        from mx_mcp.tools.measure_defense import MeasureDefenseInput

        if overrides is None:
            return MeasureDefenseInput(tier=tier)
        # ``model_copy(update=...)`` re-runs validators on the changed
        # field, which is what we want for ``tier``.
        return overrides.model_copy(update={"tier": tier})


__all__ = [
    "TierRunResult",
    "TierRunner",
]


# Resolve the ``"MeasureDefenseOutput"`` forward reference on
# :class:`TierRunResult`. The import lives at the bottom of the
# module on purpose: importing it earlier would trigger
# ``mx_mcp.tools.__init__.py``, which imports ``tools.run_tier``,
# which imports back into this module — a circular reference that
# Python tolerates only when the class definitions above have
# already executed. By the time we reach this line, ``TierRunResult``
# is in the module namespace, so the cycle resolves cleanly. The
# ``model_rebuild`` call promotes the string forward reference into
# the real class so pydantic instantiation works at runtime.
from mx_mcp.tools.measure_defense import MeasureDefenseOutput  # noqa: E402

TierRunResult.model_rebuild()
