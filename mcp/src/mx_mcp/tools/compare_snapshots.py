"""MCP tool: compare two measurement snapshots.

Loads a pair of snapshots from :class:`SnapshotStore`, re-uses the
existing :func:`diff_baselines` logic for the numeric verdict (what
improved / regressed / stayed the same), and optionally renders a
side-by-side ``ComparisonChartRenderer`` PNG.

Resolver conveniences: ``latest`` / ``previous`` are accepted in place
of real ids so the common "is today's run better than the last one?"
workflow becomes ``compare_snapshots left=previous right=latest``.

The tool does not trigger any builds — it only reads snapshots that
``measure_defense`` already persisted. Comparing a freshly captured
run against a month-old one is therefore instant.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from pydantic import BaseModel, Field

from mx_mcp.common.baselines import (
    BASELINE_SCHEMA_VERSION,
    BaselineDiff,
    BaselineDoc,
    diff_baselines,
)
from mx_mcp.common.benchmark_base import BenchmarkResult
from mx_mcp.common.snapshots import (
    Snapshot,
    SnapshotCorruptError,
    SnapshotNotFoundError,
    SnapshotStore,
)
from mx_mcp.common.tool_base import ITool, register_tool
from mx_mcp.tools.measure_defense import DEFAULT_SNAPSHOTS_REL


_LOG = logging.getLogger(__name__)


_LATEST_ALIAS = "latest"
_PREVIOUS_ALIAS = "previous"


class SnapshotResolveError(LookupError):
    """Raised when a snapshot id / alias cannot be resolved."""


# ============================================================================
# I/O schema
# ============================================================================


class CompareSnapshotsInput(BaseModel):
    left: str = Field(
        description=(
            "Snapshot id to treat as the baseline. Accepts the literal "
            "'latest' (newest snapshot) or 'previous' (second-to-newest) "
            "as a convenience."
        ),
    )
    right: str = Field(
        description=(
            "Snapshot id to treat as the current value. Same 'latest'/"
            "'previous' aliases apply."
        ),
    )
    snapshots_root: str | None = Field(
        default=None,
        description="Override for the snapshot store root; default mcp/reports/snapshots.",
    )
    output_png: str | None = Field(
        default=None,
        description=(
            "Optional path for the comparison PNG. Requires matplotlib "
            "(``pip install -e \".[viz]\"`` in mcp/). When unavailable "
            "the tool still returns the numeric diff and surfaces an "
            "install hint in ``png_note``."
        ),
    )
    tolerance_pct: float = Field(
        default=5.0,
        description=(
            "Relative delta band (as a percentage) within which metrics "
            "count as 'unchanged'. Also the absolute band for false_best "
            "rate metrics."
        ),
    )


class CompareSnapshotsOutput(BaseModel):
    left_id: str
    right_id: str
    left_timestamp: str
    right_timestamp: str
    left_git_commit: str | None
    right_git_commit: str | None
    diff: BaselineDiff
    png_path: str | None = None
    png_note: str | None = None
    notes: list[str] = Field(default_factory=list)


# ============================================================================
# Tool
# ============================================================================


@register_tool
class CompareSnapshotsTool(
    ITool[CompareSnapshotsInput, CompareSnapshotsOutput]
):
    """Compare two measurement snapshots and optionally render a PNG."""

    name = "compare_snapshots"
    description = (
        "Load two snapshots from mcp/reports/snapshots/, compute "
        "per-metric improvements/regressions, and (optionally) "
        "render a grouped-bar comparison PNG. Accepts 'latest' and "
        "'previous' aliases for the common 'did my last change help?' "
        "workflow."
    )
    input_schema = CompareSnapshotsInput
    output_schema = CompareSnapshotsOutput

    def __init__(
        self,
        store_factory: "StoreFactory | None" = None,
    ) -> None:
        self._store_factory = store_factory or SnapshotStore

    async def run(
        self, args: CompareSnapshotsInput, session,
    ) -> CompareSnapshotsOutput:
        snapshots_root = _resolve_snapshots_root(
            args.snapshots_root, session.workspace_root,
        )
        store = self._store_factory(snapshots_root)

        notes: list[str] = []

        try:
            left_snap = _resolve(store, args.left)
            right_snap = _resolve(store, args.right)
        except (SnapshotResolveError, SnapshotNotFoundError,
                SnapshotCorruptError) as e:
            raise SnapshotResolveError(str(e)) from e

        left_benchmarks = _read_benchmarks(left_snap)
        right_benchmarks = _read_benchmarks(right_snap)

        # Warn but do not fail when the two snapshots used different
        # corpora — metrics remain comparable by name, but the warning
        # helps a human reviewer spot mismatched conditions.
        if left_snap.manifest.corpus_path != right_snap.manifest.corpus_path:
            notes.append(
                f"corpus path differs between snapshots: "
                f"left={left_snap.manifest.corpus_path!r}, "
                f"right={right_snap.manifest.corpus_path!r}"
            )

        # Reuse the existing diff engine — it classifies each metric
        # by direction, handles missing values, and returns a typed
        # BaselineDiff. We synthesise a minimal BaselineDoc from the
        # left snapshot to feed it (the fields beyond benchmarks are
        # informational).
        baseline_doc = _synthesise_baseline_doc(left_snap, left_benchmarks)
        diff = diff_baselines(
            current_benchmarks=right_benchmarks,
            baseline=baseline_doc,
            tolerance_pct=args.tolerance_pct,
            current_timestamp=right_snap.manifest.timestamp,
        )

        output = CompareSnapshotsOutput(
            left_id=left_snap.manifest.snapshot_id,
            right_id=right_snap.manifest.snapshot_id,
            left_timestamp=left_snap.manifest.timestamp,
            right_timestamp=right_snap.manifest.timestamp,
            left_git_commit=left_snap.manifest.git_commit,
            right_git_commit=right_snap.manifest.git_commit,
            diff=diff,
            notes=notes,
        )

        if args.output_png is not None:
            output.png_path, output.png_note = await asyncio.to_thread(
                _render_chart,
                left_snap, right_snap, left_benchmarks, right_benchmarks,
                args.output_png,
            )

        return output


# ============================================================================
# Resolver — 'latest' / 'previous' conveniences + hard ids
# ============================================================================


def _resolve(store: SnapshotStore, ref: str) -> Snapshot:
    """Return the :class:`Snapshot` for an id or named alias."""
    if ref == _LATEST_ALIAS:
        snap = store.latest()
        if snap is None:
            raise SnapshotResolveError(
                f"alias '{_LATEST_ALIAS}' — store at {store.root} has no snapshots"
            )
        return snap
    if ref == _PREVIOUS_ALIAS:
        ids = store.list_ids()
        if len(ids) < 2:
            raise SnapshotResolveError(
                f"alias '{_PREVIOUS_ALIAS}' — store at {store.root} "
                f"has only {len(ids)} snapshot(s); need at least 2"
            )
        return store.load(ids[-2])
    return store.load(ref)


def _resolve_snapshots_root(
    override: str | None, workspace_root: Path,
) -> Path:
    if override is None:
        return workspace_root / DEFAULT_SNAPSHOTS_REL
    p = Path(override)
    return p if p.is_absolute() else (workspace_root / p).resolve()


# ============================================================================
# Measurement parsing — snapshots store raw JSON; we coerce into the
# typed BenchmarkResult list the diff engine expects.
# ============================================================================


def _read_benchmarks(snap: Snapshot) -> list[BenchmarkResult]:
    """Extract ``benchmarks: list[BenchmarkResult]`` from a snapshot."""
    payload = snap.read_measurement()
    raw_benchmarks = payload.get("benchmarks", [])
    return [BenchmarkResult.model_validate(b) for b in raw_benchmarks]


def _synthesise_baseline_doc(
    snap: Snapshot, benchmarks: list[BenchmarkResult],
) -> BaselineDoc:
    """Wrap a snapshot in a ``BaselineDoc`` so ``diff_baselines`` consumes it.

    Snapshots and baselines share most fields conceptually. Rather
    than teaching the diff engine about two schemas, we adapt at the
    boundary.
    """
    return BaselineDoc(
        schema_version=BASELINE_SCHEMA_VERSION,
        name=snap.manifest.snapshot_id,
        timestamp=snap.manifest.timestamp,
        git_commit=snap.manifest.git_commit,
        builder_level=snap.manifest.builder_level,
        builder_args=list(snap.manifest.builder_args),
        benchmarks=benchmarks,
    )


# ============================================================================
# Chart plumbing — kept inline (small, specialised) rather than
# adding another render_or_skip helper.
# ============================================================================


def _render_chart(
    left: Snapshot,
    right: Snapshot,
    left_benchmarks: list[BenchmarkResult],
    right_benchmarks: list[BenchmarkResult],
    output_png: str,
) -> tuple[str | None, str | None]:
    """Render the comparison PNG. Returns (png_path, png_note).

    Signature mirrors ``try_render_png`` (from ``render_or_skip``) so
    a future refactor can fold both paths onto a single helper.
    """
    from mx_mcp.reporting.charts.comparison_chart import (
        ComparisonChartInput,
        ComparisonChartRenderer,
        ComparisonSide,
    )
    from mx_mcp.reporting.render_or_skip import try_render_png

    data = ComparisonChartInput(
        title="Defense Comparison",
        left=ComparisonSide(
            label=_short_label(left),
            subtitle=_long_label(left),
            benchmarks=left_benchmarks,
        ),
        right=ComparisonSide(
            label=_short_label(right),
            subtitle=_long_label(right),
            benchmarks=right_benchmarks,
        ),
    )
    return try_render_png(ComparisonChartRenderer(), data, output_png)


def _short_label(snap: Snapshot) -> str:
    """Compact identifier for legend entries."""
    commit = snap.manifest.git_commit
    if commit:
        suffix = " (dirty)" if snap.manifest.git_dirty else ""
        return commit[:7] + suffix
    return snap.manifest.snapshot_id


def _long_label(snap: Snapshot) -> str:
    """Longer context line for the figure subtitle."""
    parts = [snap.manifest.timestamp]
    if snap.manifest.git_branch:
        parts.append(f"branch={snap.manifest.git_branch}")
    return "  ·  ".join(parts)


# Type alias so tests can override the store factory.
from typing import Callable

StoreFactory = Callable[[Path], SnapshotStore]
