"""MCP tool: compare current metrics against a stored baseline.

Runs ``measure_defense`` internally, loads the named baseline from the
``mcp/baselines/data/`` store, and emits a per-metric diff with
verdicts (``improved`` / ``regressed`` / ``unchanged`` / ``skipped`` /
``added`` / ``removed``). The ``gate_passed`` flag is the single
number CI callers care about.

Tolerance semantics are documented on ``baselines.diff_baselines``.
"""

from __future__ import annotations

import datetime as _dt
import logging
from pathlib import Path

from pydantic import BaseModel, Field

from mx_mcp.common.baselines import (
    BaselineDiff,
    BaselineNotFoundError,
    JsonFileStore,
    diff_baselines,
)
from mx_mcp.common.tool_base import ITool, register_tool
from mx_mcp.tools.measure_defense import (
    DEFAULT_TIMEOUT_S,
    MeasureDefenseInput,
    MeasureDefenseTool,
)


_LOG = logging.getLogger(__name__)


DEFAULT_BASELINES_REL = Path("mcp") / "baselines" / "data"
DEFAULT_TOLERANCE_PCT = 5.0


def _iso_utc_now() -> str:
    """ISO-8601 UTC timestamp to the second, with trailing ``Z``."""
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_baselines_root(
    override: str | None, workspace_root: Path
) -> Path:
    if override is None:
        return workspace_root / DEFAULT_BASELINES_REL
    p = Path(override)
    return p if p.is_absolute() else (workspace_root / p).resolve()


# ============================================================================
# I/O schema
# ============================================================================


class DiffDefenseBaselineInput(BaseModel):
    baseline_name: str = Field(description="Name of the baseline to compare against.")
    baselines_root: str | None = Field(
        default=None,
        description=(
            "Override the baselines store root. Default: "
            "mcp/baselines/data relative to the workspace root."
        ),
    )
    corpus_path: str | None = Field(default=None)
    categories: list[str] | None = Field(default=None)
    tier: str | None = Field(default=None)
    level: str = Field(default="strong")
    builder_args: list[str] = Field(default_factory=list)
    timeout_s: float = Field(default=DEFAULT_TIMEOUT_S)
    tolerance_pct: float = Field(
        default=DEFAULT_TOLERANCE_PCT,
        description=(
            "Relative band (%) for higher/lower-better metrics, or "
            "absolute band for false_best rates. Metrics within the "
            "band are classified ``unchanged``."
        ),
    )
    output_png: str | None = Field(
        default=None,
        description=(
            "If set, render the diff as a PNG chart at this path. "
            "Requires matplotlib — see measure_defense's ``output_png`` "
            "for the install recipe. Independent of the measurement "
            "chart — they produce distinct visuals (per-metric scores "
            "vs. per-metric deltas)."
        ),
    )


class DiffDefenseBaselineOutput(BaseModel):
    baseline_name: str
    baselines_root: str
    corpus_size: int
    benchmark_count: int
    duration_ms: int
    diff: BaselineDiff
    measure_notes: list[str] = Field(default_factory=list)
    png_path: str | None = None
    png_note: str | None = None


# ============================================================================
# Tool
# ============================================================================


@register_tool
class DiffDefenseBaselineTool(
    ITool[DiffDefenseBaselineInput, DiffDefenseBaselineOutput]
):
    """Measure + diff against a stored baseline. Single verdict per run."""

    name = "diff_defense_baseline"
    description = (
        "Measure current defense metrics (internally runs measure_defense) "
        "and diff them against a stored baseline. Returns per-metric "
        "verdicts (improved / regressed / unchanged / skipped) and the "
        "aggregate ``gate_passed`` flag."
    )
    input_schema = DiffDefenseBaselineInput
    output_schema = DiffDefenseBaselineOutput

    def __init__(
        self,
        measure_tool: MeasureDefenseTool | None = None,
        store_factory: "StoreFactory | None" = None,
    ) -> None:
        # Dependency injection seams for tests. Production path uses
        # the registry-backed tool and the JSON file store.
        self._measure = measure_tool or MeasureDefenseTool()
        self._store_factory = store_factory or JsonFileStore

    async def run(
        self, args: DiffDefenseBaselineInput, session
    ) -> DiffDefenseBaselineOutput:
        current_ts = _iso_utc_now()

        baselines_root = _resolve_baselines_root(
            args.baselines_root, session.workspace_root
        )
        store = self._store_factory(baselines_root)

        # Load the baseline up front so a missing file fails fast —
        # no point running the full measurement to then discover the
        # baseline doesn't exist.
        try:
            baseline = store.load(args.baseline_name)
        except BaselineNotFoundError as e:
            known = store.list_baselines()
            raise BaselineNotFoundError(
                f"{e} Known baselines in {baselines_root}: "
                f"{known if known else '(none)'}"
            ) from e

        measure_args = MeasureDefenseInput(
            corpus_path=args.corpus_path,
            categories=args.categories,
            tier=args.tier,
            level=args.level,
            builder_args=args.builder_args,
            timeout_s=args.timeout_s,
        )
        measure_result = await self._measure.run(measure_args, session)

        diff = diff_baselines(
            current_benchmarks=measure_result.benchmarks,
            baseline=baseline,
            tolerance_pct=args.tolerance_pct,
            current_timestamp=current_ts,
        )

        _LOG.info(
            "diff vs baseline '%s': +%d / -%d / =%d / skipped %d",
            args.baseline_name,
            len(diff.improvements), len(diff.regressions),
            len(diff.unchanged), len(diff.skipped),
        )

        output = DiffDefenseBaselineOutput(
            baseline_name=args.baseline_name,
            baselines_root=str(baselines_root),
            corpus_size=measure_result.corpus_size,
            benchmark_count=measure_result.benchmark_count,
            duration_ms=measure_result.duration_ms,
            diff=diff,
            measure_notes=measure_result.notes,
        )

        # Optional PNG rendering — delayed imports keep the tool free
        # of a top-level matplotlib / reporting dependency.
        if args.output_png is not None:
            from mx_mcp.reporting.charts.diff_chart import DiffChartRenderer
            from mx_mcp.reporting.render_or_skip import try_render_png

            output.png_path, output.png_note = try_render_png(
                DiffChartRenderer(), output, args.output_png,
            )

        return output


# Type alias for the test-injectable store factory.
from typing import Callable

from mx_mcp.common.baselines import IBaselineStore

StoreFactory = Callable[[Path], IBaselineStore]
