"""Comparison chart — two snapshots rendered side-by-side on one PNG.

Companion to :mod:`measurement_chart` for the cross-snapshot workflow
(``compare_snapshots`` MCP tool). Each metric in either snapshot
becomes a pair of horizontal bars: left side is the "older" snapshot
(muted sand colour), right side is the "newer" (bright accent). The
eye reads "did the bar on top grow or shrink from the bar below?"
without having to decode percentages.

## Metric handling

* Metric in both → two bars at offset y-positions, same x-axis scale
  ([0, 1] score or raw value when no scale is declared).
* Metric only in ``right`` → one bar + ``[NEW]`` badge.
* Metric only in ``left`` → one bar + ``[REMOVED]`` badge.
* Metric without a ``MetricScale`` on either side → hatched band
  annotated ``(no scale)``; it still appears so the chart never
  silently hides data, but the bar sits at zero.

## Subplot grouping

Same layout as :mod:`measurement_chart`: one subplot per benchmark
with its metrics stacked inside. Benchmarks that exist only on one
side still get their own subplot — the "missing side" is rendered
as empty padding so layout remains consistent between measurement
and comparison charts.

## Duck typing

``ComparisonSide.benchmarks`` is pydantic-validated to
``list[BenchmarkResult]``, which mirrors what
``MeasureDefenseOutput.benchmarks`` carries — so the tool layer
composes the input without importing from ``tools/``. The renderer
stays in the reporting layer with no upward imports, preserving the
dependency direction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mx_mcp.common.benchmark_base import BenchmarkResult, MetricResult
from mx_mcp.reporting.charts._mpl import (
    DARK_THEME,
    FIGURE_DPI,
    matplotlib_available,
    require_matplotlib,
    style_axis_for_dark,
    style_figure_for_dark,
)
from mx_mcp.reporting.charts.base import IChartRenderer, register_chart


_LOG = logging.getLogger(__name__)


# Visual constants. Larger row heights than the single-measurement
# chart because each row now holds two bars vertically.
_ROW_HEIGHT_IN = 0.55
_BENCH_HEADER_IN = 0.65
_MIN_AXIS_HEIGHT_IN = 1.60
_FIG_MIN_HEIGHT_IN = 3.20
_BAR_HEIGHT = 0.34
_BAR_PAIR_GAP = 0.18

# Colours tuned for the dark palette. The "left / older" side uses a
# warm sand that reads as "historical" next to the cool-blue
# "current" accent. Both survive common colour-blind dichromacies
# because hue + luminance differ independently.
_COLOR_LEFT = "#d4a373"
_COLOR_RIGHT = "#4fb3ff"
_COLOR_NO_SCALE_EDGE = DARK_THEME["hatch_edge"]


# ============================================================================
# Input schema
# ============================================================================


class ComparisonSide(BaseModel):
    """One half of a two-snapshot comparison.

    ``label`` appears in the legend / subtitle and should be short
    (ID or commit SHA); ``subtitle`` carries the longer context
    (date + branch + dirty flag) shown once under the figure title.
    """

    label: str = Field(description="Short legend label (commit7 / snapshot id).")
    subtitle: str = Field(
        default="", description="Longer context line — timestamp + branch.",
    )
    benchmarks: list[BenchmarkResult] = Field(
        default_factory=list,
        description="Full benchmark list mirroring MeasureDefenseOutput.benchmarks.",
    )


class ComparisonChartInput(BaseModel):
    """Everything :class:`ComparisonChartRenderer` needs to render."""

    title: str = Field(
        default="Defense Comparison",
        description="Figure suptitle shown above both snapshots.",
    )
    left: ComparisonSide
    right: ComparisonSide


# ============================================================================
# Intermediate row model — keeps pure logic out of matplotlib
# ============================================================================


@dataclass(frozen=True, slots=True)
class _PairRow:
    """One metric's worth of rendering state."""

    metric_name: str
    left_score: float | None
    right_score: float | None
    left_raw: float | None
    right_raw: float | None
    left_n: int                   # samples that produced a value
    right_n: int
    badge: str                    # "" / "NEW" / "REMOVED" / "no scale"
    has_scale: bool


# ============================================================================
# Renderer
# ============================================================================


@register_chart
class ComparisonChartRenderer(IChartRenderer[ComparisonChartInput]):
    """Grouped-bar comparison PNG for two measurement snapshots."""

    name = "comparison"
    description = (
        "Two snapshots overlaid on one PNG — grouped horizontal bars "
        "with dark theme. Left (older) in warm sand, right (newer) in "
        "bright cyan. Added / removed metrics are flagged explicitly."
    )
    input_schema = ComparisonChartInput

    def is_available(self) -> bool:
        return matplotlib_available()

    def render(
        self, data: ComparisonChartInput, output_path: Path,
    ) -> Path:
        plt = require_matplotlib()

        bench_groups = _align_benchmarks(data.left.benchmarks, data.right.benchmarks)
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not bench_groups:
            return _render_empty_figure(plt, output_path, data)

        fig_height = _figure_height_inches(bench_groups)
        fig, axes = plt.subplots(
            nrows=len(bench_groups), ncols=1,
            figsize=(11.0, fig_height), dpi=FIGURE_DPI, squeeze=False,
        )

        fig.suptitle(
            f"{data.title}  —  {data.left.label}  ↔  {data.right.label}",
            fontsize=12, y=0.995, color=DARK_THEME["accent"],
        )
        style_figure_for_dark(fig)

        # Subtitle with the two side-subtitles — written as a single
        # line of small text below the suptitle.
        subtitle = _compose_subtitle(data.left, data.right)
        if subtitle:
            fig.text(
                0.5, 0.968, subtitle,
                ha="center", va="top", fontsize=8.5,
                color=DARK_THEME["accent_muted"],
            )

        for ax, group in zip([a[0] for a in axes], bench_groups):
            _draw_axis(ax, group)

        _draw_figure_legend(fig, data.left.label, data.right.label)

        fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.94))
        fig.savefig(
            output_path, format="png", bbox_inches="tight",
            facecolor=DARK_THEME["bg"],
        )
        plt.close(fig)

        _LOG.info(
            "comparison chart → %s (%d benchmark(s), %d row(s))",
            output_path, len(bench_groups),
            sum(len(g.rows) for g in bench_groups),
        )
        return output_path


# ============================================================================
# Alignment + row building
# ============================================================================


@dataclass(frozen=True, slots=True)
class _BenchGroup:
    """One benchmark's render-ready state for the comparison chart.

    Carries both-side error counts so the subplot title can flag
    lopsided runs (e.g. 4 legacy entries erroring on the right side
    only) without reaching back into the original
    ``BenchmarkResult`` objects.
    """

    bench_name: str
    left_errors: int
    right_errors: int
    rows: list[_PairRow]


def _align_benchmarks(
    left: list[BenchmarkResult], right: list[BenchmarkResult],
) -> list[_BenchGroup]:
    """Produce per-benchmark render groups covering both sides.

    Benchmark order follows the left side's manifest order, then
    appends any benchmarks that exist only on the right. This
    produces a stable top-to-bottom read independent of hashed
    iteration order.
    """
    left_by_name = {b.benchmark: b for b in left}
    right_by_name = {b.benchmark: b for b in right}

    all_names = list(left_by_name) + [
        n for n in right_by_name if n not in left_by_name
    ]

    groups: list[_BenchGroup] = []
    for bench_name in all_names:
        lb = left_by_name.get(bench_name)
        rb = right_by_name.get(bench_name)
        rows = _pair_rows(lb, rb)
        if rows:
            groups.append(_BenchGroup(
                bench_name=bench_name,
                left_errors=len(lb.errors) if lb else 0,
                right_errors=len(rb.errors) if rb else 0,
                rows=rows,
            ))
    return groups


def _pair_rows(
    left: BenchmarkResult | None, right: BenchmarkResult | None,
) -> list[_PairRow]:
    """Pair up a single benchmark's metrics across sides."""
    left_metrics = {m.name: m for m in (left.metrics if left else [])}
    right_metrics = {m.name: m for m in (right.metrics if right else [])}

    ordered: list[str] = []
    for m in (left.metrics if left else []):
        if m.name not in ordered:
            ordered.append(m.name)
    for m in (right.metrics if right else []):
        if m.name not in ordered:
            ordered.append(m.name)

    rows: list[_PairRow] = []
    for name in ordered:
        lm = left_metrics.get(name)
        rm = right_metrics.get(name)
        row = _pair_row(name, lm, rm)
        if row is not None:
            rows.append(row)
    return rows


def _pair_row(
    name: str, left: MetricResult | None, right: MetricResult | None,
) -> _PairRow | None:
    """Build one :class:`_PairRow` or ``None`` when both sides lack data."""
    left_raw = left.aggregate.p90 if left else None
    right_raw = right.aggregate.p90 if right else None

    if left_raw is None and right_raw is None:
        return None

    # Scale is taken from whichever side declares one. If both do,
    # prefer right (current) since it is authoritative for the latest
    # schema; callers can retune scales without invalidating old
    # snapshots.
    scale = (right.scale if right and right.scale else
             (left.scale if left and left.scale else None))

    if scale is not None:
        left_score = scale.normalize(float(left_raw)) if left_raw is not None else None
        right_score = scale.normalize(float(right_raw)) if right_raw is not None else None
        has_scale = True
    else:
        left_score = right_score = None
        has_scale = False

    if left is None:
        badge = "NEW"
    elif right is None:
        badge = "REMOVED"
    elif not has_scale:
        badge = "no scale"
    else:
        badge = ""

    # Per-side sample counts — zero when the side didn't emit the
    # metric at all (NEW / REMOVED cases). Surfaced in the annotation
    # so a lopsided "3 vs 7" comparison is visible at a glance.
    left_n = left.aggregate.n_samples if left else 0
    right_n = right.aggregate.n_samples if right else 0

    return _PairRow(
        metric_name=name,
        left_score=left_score, right_score=right_score,
        left_raw=left_raw, right_raw=right_raw,
        left_n=left_n, right_n=right_n,
        badge=badge, has_scale=has_scale,
    )


# ============================================================================
# Drawing primitives
# ============================================================================


def _draw_axis(ax: Any, group: _BenchGroup) -> None:
    """Render one benchmark's grouped bars onto the supplied axis."""
    style_axis_for_dark(ax)
    ax.set_title(
        _compose_subplot_title(group),
        fontsize=10, loc="left", color=DARK_THEME["accent"],
    )

    ax.set_xlim(0.0, 1.0)
    ax.set_xlabel(
        "Defense score (0 = weak, 1 = strong)", fontsize=9,
        color=DARK_THEME["accent"],
    )
    ax.axvline(
        0.5, color=DARK_THEME["spine"], linestyle="--", linewidth=0.6,
    )
    ax.grid(axis="x", color=DARK_THEME["grid"], linewidth=0.5)
    ax.set_axisbelow(True)

    y_centers = list(range(len(group.rows)))
    for y, row in zip(y_centers, group.rows):
        _draw_row(ax, y, row)

    ax.set_yticks(y_centers)
    ax.set_yticklabels(
        [r.metric_name for r in group.rows], fontsize=9,
        color=DARK_THEME["accent_muted"],
    )
    ax.invert_yaxis()


def _compose_subplot_title(group: _BenchGroup) -> str:
    """Subplot title — benchmark name + asymmetric error counts.

    Silent when both sides cleared without errors. Reports each side
    separately when either had errors so the reader can tell "this
    is a new regression" (only right errored) apart from "stable
    state" (both errored the same way).
    """
    if group.left_errors == 0 and group.right_errors == 0:
        return group.bench_name
    parts: list[str] = []
    if group.left_errors:
        parts.append(f"L={group.left_errors} err")
    if group.right_errors:
        parts.append(f"R={group.right_errors} err")
    return f"{group.bench_name}  ·  {', '.join(parts)}"


def _draw_row(ax: Any, y_center: float, row: _PairRow) -> None:
    """Draw the left + right bars for a single metric row.

    The left bar sits slightly above the metric label baseline, the
    right bar slightly below — standard grouped-bar offset.
    """
    y_left = y_center - _BAR_PAIR_GAP
    y_right = y_center + _BAR_PAIR_GAP

    if row.left_score is not None:
        ax.barh(
            y_left, row.left_score,
            color=_COLOR_LEFT, edgecolor=DARK_THEME["edge"],
            linewidth=0.5, height=_BAR_HEIGHT,
        )
    if row.right_score is not None:
        ax.barh(
            y_right, row.right_score,
            color=_COLOR_RIGHT, edgecolor=DARK_THEME["edge"],
            linewidth=0.5, height=_BAR_HEIGHT,
        )

    # Hatched overlay when the metric has no declared scale.
    if not row.has_scale:
        ax.barh(
            y_center, 1.0,
            facecolor="none", edgecolor=_COLOR_NO_SCALE_EDGE,
            hatch="///", linewidth=0.4, height=_BAR_HEIGHT * 2 + 0.1,
        )

    _draw_row_annotations(ax, y_left, y_right, row)


def _draw_row_annotations(
    ax: Any, y_left: float, y_right: float, row: _PairRow,
) -> None:
    left_label = _format_value(row.left_score, row.left_raw, row.left_n)
    right_label = _format_value(row.right_score, row.right_raw, row.right_n)

    if left_label:
        lx = 0.02 if row.left_score is None else min(row.left_score + 0.02, 0.97)
        ax.text(
            lx, y_left, left_label,
            va="center", fontsize=7.5, color=DARK_THEME["text_on_bar"],
        )
    if right_label:
        rx = 0.02 if row.right_score is None else min(row.right_score + 0.02, 0.97)
        ax.text(
            rx, y_right, right_label,
            va="center", fontsize=7.5, color=DARK_THEME["text_on_bar"],
        )

    if row.badge:
        ax.text(
            0.995, (y_left + y_right) / 2.0,
            f"[{row.badge}]",
            va="center", ha="right", fontsize=7.5,
            color=DARK_THEME["accent"],
            transform=ax.get_yaxis_transform(),
        )


def _format_value(
    score: float | None, raw: float | None, n: int,
) -> str:
    """One-line annotation for a bar — score if available, else raw.

    ``n`` is the number of successful samples that produced the
    value; it is always included so a reader comparing two sides
    with different sample counts sees the disparity without checking
    the subplot title.
    """
    if score is not None and raw is not None:
        return f"{score:.2f}  (p90={raw:.4g}, n={n})"
    if raw is not None:
        return f"p90={raw:.4g}, n={n}"
    return ""


def _draw_figure_legend(
    fig: Any, left_label: str, right_label: str,
) -> None:
    """One compact legend, bottom-right, tinted for the dark bg."""
    from matplotlib.patches import Patch

    handles = [
        Patch(
            facecolor=_COLOR_LEFT, edgecolor=DARK_THEME["edge"],
            label=f"left  · {left_label}",
        ),
        Patch(
            facecolor=_COLOR_RIGHT, edgecolor=DARK_THEME["edge"],
            label=f"right · {right_label}",
        ),
    ]
    legend = fig.legend(
        handles=handles, loc="lower right", ncols=2, fontsize=8,
        frameon=True, framealpha=0.92,
        facecolor=DARK_THEME["panel"],
        edgecolor=DARK_THEME["spine"],
        labelcolor=DARK_THEME["accent_muted"],
    )
    legend.get_frame().set_linewidth(0.5)


def _compose_subtitle(left: ComparisonSide, right: ComparisonSide) -> str:
    parts: list[str] = []
    if left.subtitle:
        parts.append(f"left: {left.subtitle}")
    if right.subtitle:
        parts.append(f"right: {right.subtitle}")
    return "     |     ".join(parts)


# ============================================================================
# Layout helpers
# ============================================================================


def _figure_height_inches(bench_groups: list[_BenchGroup]) -> float:
    total_rows = sum(len(g.rows) for g in bench_groups)
    per_bench_overhead = _BENCH_HEADER_IN * len(bench_groups)
    axes_height = max(
        _ROW_HEIGHT_IN * total_rows + per_bench_overhead,
        _MIN_AXIS_HEIGHT_IN * max(1, len(bench_groups)),
    )
    return max(axes_height, _FIG_MIN_HEIGHT_IN)


def _render_empty_figure(
    plt: Any, output_path: Path, data: ComparisonChartInput,
) -> Path:
    """Render a placeholder PNG when neither side has anything to show."""
    fig = plt.figure(figsize=(8, 2.5), dpi=FIGURE_DPI)
    ax = fig.add_subplot(1, 1, 1)
    ax.axis("off")
    ax.text(
        0.5, 0.5, "no benchmark rows to compare",
        ha="center", va="center", fontsize=13,
        color=DARK_THEME["text_dim"],
    )
    fig.suptitle(
        f"{data.title}  —  {data.left.label}  ↔  {data.right.label}",
        fontsize=12, color=DARK_THEME["accent"],
    )
    style_figure_for_dark(fig)
    ax.set_facecolor(DARK_THEME["bg"])
    fig.tight_layout()
    fig.savefig(
        output_path, format="png", bbox_inches="tight",
        facecolor=DARK_THEME["bg"],
    )
    plt.close(fig)
    _LOG.info("comparison chart (empty) → %s", output_path)
    return output_path
