"""MCP tool: snapshot the current defense metrics as a named baseline.

Runs ``measure_defense`` internally, wraps the result in a
``BaselineDoc``, and persists it to ``mcp/baselines/data/<name>.json``.
Baselines are committed to git intentionally — they are historical
facts about the builder at a point in time and are reviewable in PR
diffs.

Baseline freshness is the caller's responsibility: the tool does not
verify that the current working tree is clean or that the builder
matches ``git_commit``. It only records what the current binary in
``build/.../mxprotector_builder.exe`` produced against the corpus.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from mx_mcp.common.baselines import (
    BASELINE_SCHEMA_VERSION,
    BaselineDoc,
    BaselineExistsError,
    JsonFileStore,
)
from mx_mcp.common.tool_base import ITool, register_tool
from mx_mcp.tools.diff_defense_baseline import DEFAULT_BASELINES_REL
from mx_mcp.tools.measure_defense import (
    DEFAULT_TIMEOUT_S,
    MeasureDefenseInput,
    MeasureDefenseTool,
)


_LOG = logging.getLogger(__name__)


def _iso_utc_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _read_git_commit(workspace_root: Path) -> str | None:
    """Best-effort ``git rev-parse HEAD`` lookup. ``None`` on failure.

    The timestamp and name fields on ``BaselineDoc`` are the canonical
    identity; git commit is informational. Silent failure keeps the
    recorder functional in environments without git installed.
    """
    def _run() -> str | None:
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(workspace_root),
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if proc.returncode != 0:
                return None
            return proc.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            return None

    return await asyncio.to_thread(_run)


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


class RecordBaselineInput(BaseModel):
    baseline_name: str = Field(
        description=(
            "Stable identifier for the snapshot; becomes the on-disk "
            "file stem. Accepted characters: alphanumerics, '-', '_', '.'"
        ),
    )
    baselines_root: str | None = Field(
        default=None,
        description="Override for the baselines store; default mcp/baselines/data.",
    )
    overwrite: bool = Field(
        default=False,
        description="Allow replacing an existing baseline with the same name.",
    )
    corpus_path: str | None = Field(default=None)
    categories: list[str] | None = Field(default=None)
    tier: str | None = Field(default=None)
    level: str = Field(default="strong")
    builder_args: list[str] = Field(default_factory=list)
    timeout_s: float = Field(default=DEFAULT_TIMEOUT_S)


class RecordBaselineOutput(BaseModel):
    baseline_name: str
    baseline_path: str
    timestamp: str
    git_commit: str | None
    corpus_size: int
    benchmark_count: int
    metric_count: int
    notes: list[str] = Field(default_factory=list)


# ============================================================================
# Tool
# ============================================================================


@register_tool
class RecordBaselineTool(ITool[RecordBaselineInput, RecordBaselineOutput]):
    """Snapshot current metrics as a named baseline."""

    name = "record_baseline"
    description = (
        "Run measure_defense internally and save the result as a named "
        "baseline under mcp/baselines/data/<name>.json. Pass overwrite=true "
        "to replace an existing baseline."
    )
    input_schema = RecordBaselineInput
    output_schema = RecordBaselineOutput

    def __init__(
        self,
        measure_tool: MeasureDefenseTool | None = None,
        store_factory: "StoreFactory | None" = None,
    ) -> None:
        self._measure = measure_tool or MeasureDefenseTool()
        self._store_factory = store_factory or JsonFileStore

    async def run(
        self, args: RecordBaselineInput, session
    ) -> RecordBaselineOutput:
        timestamp = _iso_utc_now()
        git_commit = await _read_git_commit(session.workspace_root)

        measure_args = MeasureDefenseInput(
            corpus_path=args.corpus_path,
            categories=args.categories,
            tier=args.tier,
            level=args.level,
            builder_args=args.builder_args,
            timeout_s=args.timeout_s,
        )
        measure_result = await self._measure.run(measure_args, session)

        doc = BaselineDoc(
            schema_version=BASELINE_SCHEMA_VERSION,
            name=args.baseline_name,
            timestamp=timestamp,
            git_commit=git_commit,
            builder_level=args.level,
            builder_args=list(args.builder_args),
            benchmarks=list(measure_result.benchmarks),
        )

        baselines_root = _resolve_baselines_root(
            args.baselines_root, session.workspace_root
        )
        store = self._store_factory(baselines_root)

        try:
            path = store.save(doc, overwrite=args.overwrite)
        except BaselineExistsError as e:
            raise BaselineExistsError(
                f"{e} Pass overwrite=true to replace."
            ) from e

        metric_count = sum(len(b.metrics) for b in doc.benchmarks)

        _LOG.info(
            "recorded baseline '%s' at %s (%d benchmarks, %d metrics)",
            args.baseline_name, path, len(doc.benchmarks), metric_count,
        )

        return RecordBaselineOutput(
            baseline_name=args.baseline_name,
            baseline_path=str(path),
            timestamp=timestamp,
            git_commit=git_commit,
            corpus_size=measure_result.corpus_size,
            benchmark_count=len(doc.benchmarks),
            metric_count=metric_count,
            notes=measure_result.notes,
        )


# Type alias shared with diff_defense_baseline's injection point.
from typing import Callable

from mx_mcp.common.baselines import IBaselineStore

StoreFactory = Callable[[Path], IBaselineStore]
