"""Measurement chart — one PNG summarising a ``measure_defense`` run.

Layout:

* One vertically-stacked subplot per benchmark.
* Horizontal bar per metric; length = normalised score (``0..1``).
* Colour by direction (``HIGHER_BETTER``/``LOWER_BETTER``/``FALSE_BEST``).
* Annotation: ``score=0.42 (p90=5.0)`` — score + raw representative.
* Midpoint reference line at ``x=0.5``.

Design notes:

* The input type is duck-typed against ``MeasureDefenseOutput`` to
  avoid a top-level import cycle with ``tools/measure_defense.py``.
  Callers pass the real pydantic instance; the chart reads
  ``.benchmarks[].metrics[].{aggregate.p90, scale, direction, name}``.
* Metrics without a declared ``scale`` are rendered in a hatched
  secondary row annotated ``(no scale)``; they do not contribute a
  numeric score but still appear so the chart never silently hides
  data.
* Figure sizing scales with total metric count so dense runs stay
  readable without cropping.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mx_mcp.reporting.charts._mpl import (
    DARK_THEME,
    DIRECTION_COLORS,
    FIGURE_DPI,
    matplotlib_available,
    require_matplotlib,
    style_axis_for_dark,
    style_figure_for_dark,
)
from mx_mcp.reporting.charts.base import IChartRenderer, register_chart


_LOG = logging.getLogger(__name__)


# Row visual constants — pulled out so tests can reason about spacing
# deterministically.
_ROW_HEIGHT_IN = 0.40        # inches per metric row
_BENCH_HEADER_IN = 0.60      # title space per benchmark subplot
_MIN_AXIS_HEIGHT_IN = 1.20   # so even one-metric benchmarks read
_FIG_MIN_HEIGHT_IN = 2.80


@dataclass(frozen=True, slots=True)
class _PlotRow:
    """Single horizontal-bar row prepared for rendering.

    Intermediate representation so the math ( score / direction /
    annotation ) stays pure and testable without invoking matplotlib.
    """

    metric_name: str
    score: float | None        # None when the metric has no scale
    raw_p90: float | None
    annotation: str
    color: str
    has_scale: bool


def _row_for_metric(metric: Any) -> _PlotRow | None:
    """Compute the plot row for one ``MetricResult``.

    Returns ``None`` when the metric has no representative value
    (``p90 is None`` — no valid samples) so callers can filter out
    empty rows before figure sizing.
    """
    p90 = metric.aggregate.p90
    if p90 is None:
        return None

    direction_value = metric.direction.value
    color = DIRECTION_COLORS.get(direction_value, DARK_THEME["spine"])

    # Sample count — number of corpus entries that actually produced
    # a value for this metric. Entries that erred at the benchmark
    # level (build failed, pe-sieve couldn't attach, …) are *not*
    # represented here; they land in ``BenchmarkResult.errors`` and
    # surface in the subplot title via ``_draw_benchmark_axis``.
    n = metric.aggregate.n_samples

    if metric.scale is not None:
        score = metric.scale.normalize(float(p90))
        annotation = f"{score:.2f}  (p90={float(p90):.4g}, n={n})"
        return _PlotRow(
            metric_name=metric.name,
            score=score,
            raw_p90=float(p90),
            annotation=annotation,
            color=color,
            has_scale=True,
        )

    # No scale — we still show a row so users see the metric, but its
    # bar sits at 0 and carries a plain-text annotation. Differentiates
    # "no data" from "data without scale" at a glance.
    return _PlotRow(
        metric_name=metric.name,
        score=None,
        raw_p90=float(p90),
        annotation=f"p90={float(p90):.4g}, n={n}  (no scale)",
        color=color,
        has_scale=False,
    )


def _prepare_benchmark_rows(bench: Any) -> list[_PlotRow]:
    rows: list[_PlotRow] = []
    for m in bench.metrics:
        row = _row_for_metric(m)
        if row is not None:
            rows.append(row)
    return rows


def _figure_height_inches(bench_rows: list[list[_PlotRow]]) -> float:
    """Pick a figure height that stays readable for any metric count."""
    total_rows = sum(len(rs) for rs in bench_rows)
    per_bench_overhead = _BENCH_HEADER_IN * len(bench_rows)
    axes_height = max(
        _ROW_HEIGHT_IN * total_rows + per_bench_overhead,
        _MIN_AXIS_HEIGHT_IN * max(1, len(bench_rows)),
    )
    return max(axes_height, _FIG_MIN_HEIGHT_IN)


@register_chart
class MeasurementChartRenderer(IChartRenderer):
    """Normalised per-metric bar chart for a ``MeasureDefenseOutput``."""

    name = "measurement"
    description = (
        "Horizontal bars of defence score (0=weak, 1=strong) per "
        "metric, grouped by benchmark. Metrics without a scale are "
        "rendered with a 'no scale' annotation and zero-length bar."
    )
    # Duck-typed at runtime — see module docstring for the cycle-avoidance
    # rationale. Tool wiring passes a real ``MeasureDefenseOutput``.
    input_schema = BaseModel

    def is_available(self) -> bool:
        return matplotlib_available()

    def render(self, data: BaseModel, output_path: Path) -> Path:
        plt = require_matplotlib()

        benchmarks = list(getattr(data, "benchmarks", []))
        bench_rows = [_prepare_benchmark_rows(b) for b in benchmarks]

        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not benchmarks:
            fig = plt.figure(figsize=(8, 2.5), dpi=FIGURE_DPI)
            ax = fig.add_subplot(1, 1, 1)
            ax.axis("off")
            ax.text(
                0.5, 0.5, "no benchmark results",
                ha="center", va="center", fontsize=14,
                color=DARK_THEME["text_dim"],
            )
            fig.suptitle(
                "Defense Measurement", fontsize=13,
                color=DARK_THEME["accent"],
            )
            style_figure_for_dark(fig)
            ax.set_facecolor(DARK_THEME["bg"])
            fig.tight_layout()
            fig.savefig(
                output_path, format="png", bbox_inches="tight",
                facecolor=DARK_THEME["bg"],
            )
            plt.close(fig)
            _LOG.info("measurement chart (empty) → %s", output_path)
            return output_path

        fig_height = _figure_height_inches(bench_rows)
        fig, axes = plt.subplots(
            nrows=len(benchmarks), ncols=1,
            figsize=(10.0, fig_height), dpi=FIGURE_DPI,
            squeeze=False,
        )

        corpus_label = getattr(data, "corpus_path", "<unknown corpus>")
        fig.suptitle(
            f"Defense Measurement — {corpus_label}",
            fontsize=12, y=0.995, color=DARK_THEME["accent"],
        )
        style_figure_for_dark(fig)

        for ax, bench, rows in zip([a[0] for a in axes], benchmarks, bench_rows):
            _draw_benchmark_axis(ax, bench, rows)

        fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.97))
        fig.savefig(
            output_path, format="png", bbox_inches="tight",
            facecolor=DARK_THEME["bg"],
        )
        plt.close(fig)

        _LOG.info(
            "measurement chart → %s (%d benchmark(s), %d rows)",
            output_path, len(benchmarks), sum(len(rs) for rs in bench_rows),
        )
        return output_path


def _draw_benchmark_axis(ax: Any, bench: Any, rows: list[_PlotRow]) -> None:
    """Render one benchmark's metrics onto the supplied axis."""
    style_axis_for_dark(ax)

    # Subplot title carries both taxonomy (category/tier) and an error
    # count. A non-zero ``bench.errors`` length is the canonical
    # signal that fewer samples than corpus entries made it through
    # — rendering it in the title prevents a reader from mis-reading
    # the p90 bar as "all N corpus entries agree on this value".
    title = (
        f"{bench.benchmark}  "
        f"(category={bench.category}, tier={bench.tier})"
    )
    n_errors = len(getattr(bench, "errors", []))
    if n_errors:
        title += f"  ·  {n_errors} error(s)"
    ax.set_title(
        title, fontsize=10, loc="left", color=DARK_THEME["accent"],
    )

    if not rows:
        ax.axis("off")
        ax.text(
            0.5, 0.5, "no scored metrics",
            ha="center", va="center", fontsize=10,
            color=DARK_THEME["text_dim"],
            transform=ax.transAxes,
        )
        return

    ax.set_xlim(0.0, 1.0)
    ax.set_xlabel(
        "Defense score (0 = weak, 1 = strong)", fontsize=9,
        color=DARK_THEME["accent"],
    )
    ax.axvline(
        0.5, color=DARK_THEME["spine"], linestyle="--", linewidth=0.7,
    )
    ax.grid(axis="x", color=DARK_THEME["grid"], linewidth=0.5)
    ax.set_axisbelow(True)

    y_positions = list(range(len(rows)))
    bar_values = [(r.score if r.score is not None else 0.0) for r in rows]
    colors = [r.color for r in rows]
    ax.barh(
        y_positions, bar_values,
        color=colors, edgecolor=DARK_THEME["edge"], linewidth=0.5, height=0.6,
    )

    # Hatched overlay for rows without a scale — makes the "no real
    # bar" explicit at a glance.
    for y, row in zip(y_positions, rows):
        if not row.has_scale:
            ax.barh(
                y, 1.0,
                facecolor="none", edgecolor=DARK_THEME["hatch_edge"],
                hatch="///", linewidth=0.4, height=0.6,
            )

    ax.set_yticks(y_positions)
    ax.set_yticklabels(
        [r.metric_name for r in rows], fontsize=9,
        color=DARK_THEME["accent_muted"],
    )
    # invert so the first metric appears at the top for reading order
    ax.invert_yaxis()

    for y, row in zip(y_positions, rows):
        annotation_x = 0.02 if row.score is None else min(float(row.score) + 0.02, 0.97)
        ax.text(
            annotation_x, y, row.annotation,
            va="center", fontsize=8, color=DARK_THEME["text_on_bar"],
        )
