"""Diff chart — visualises a ``DiffDefenseBaselineOutput`` vs a baseline.

Each registered metric becomes a horizontal bar whose length is the
``delta_pct`` (signed) and colour is dictated by the verdict:

* ``improved``  — green
* ``regressed`` — red
* ``unchanged`` — neutral grey
* ``added``     — teal (informational)
* ``removed``   — amber (informational)
* ``skipped``   — light grey

Regressions are pulled to the top; improvements follow. Unchanged /
skipped entries drop to the tail so the eye hits the blocking items
first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mx_mcp.reporting.charts._mpl import (
    DARK_THEME,
    FIGURE_DPI,
    VERDICT_COLORS,
    matplotlib_available,
    require_matplotlib,
    style_axis_for_dark,
    style_figure_for_dark,
)
from mx_mcp.reporting.charts.base import IChartRenderer, register_chart


_LOG = logging.getLogger(__name__)


_VERDICT_ORDER: tuple[str, ...] = (
    "regressed", "improved", "added", "removed", "skipped", "unchanged",
)

_ROW_HEIGHT_IN = 0.32
_MIN_FIG_HEIGHT_IN = 3.2


@dataclass(frozen=True, slots=True)
class _DiffRow:
    label: str            # "{bench}::{metric}"
    verdict: str          # "improved" | "regressed" | …
    delta_pct: float      # 0 when baseline or current is missing a value
    annotation: str
    color: str


def _row_for_entry(entry: Any) -> _DiffRow:
    label = f"{entry.benchmark}::{entry.metric}"

    cur = entry.current_value
    base = entry.baseline_value
    cur_s = "-" if cur is None else f"{float(cur):.3g}"
    base_s = "-" if base is None else f"{float(base):.3g}"

    if entry.delta_pct is None:
        delta_val = 0.0
        delta_s = "-"
    else:
        delta_val = float(entry.delta_pct)
        delta_s = f"{delta_val:+.1f}%"

    annotation = f"{delta_s}  (cur={cur_s}, base={base_s})"
    color = VERDICT_COLORS.get(entry.verdict.value, DARK_THEME["spine"])
    return _DiffRow(
        label=label,
        verdict=entry.verdict.value,
        delta_pct=delta_val,
        annotation=annotation,
        color=color,
    )


def _collect_rows(diff: Any) -> list[_DiffRow]:
    """Flatten all diff entries into rows, ordered by verdict severity."""
    by_verdict: dict[str, list[Any]] = {
        "regressed": diff.regressions,
        "improved":  diff.improvements,
        "added":     diff.added,
        "removed":   diff.removed,
        "skipped":   diff.skipped,
        "unchanged": diff.unchanged,
    }
    rows: list[_DiffRow] = []
    for verdict in _VERDICT_ORDER:
        entries = by_verdict.get(verdict) or []
        for e in entries:
            rows.append(_row_for_entry(e))
    return rows


def _figure_height_inches(n_rows: int) -> float:
    return max(_ROW_HEIGHT_IN * max(n_rows, 1) + 1.3, _MIN_FIG_HEIGHT_IN)


def _symmetric_xlim(rows: list[_DiffRow]) -> tuple[float, float]:
    """Pick a symmetric x-range so positive and negative deltas read
    on the same scale. Always at least ``±10%`` so tiny deltas remain
    visible instead of collapsing onto the y-axis."""
    if not rows:
        return (-10.0, 10.0)
    max_abs = max((abs(r.delta_pct) for r in rows), default=10.0)
    limit = max(max_abs * 1.15, 10.0)
    return (-limit, limit)


@register_chart
class DiffChartRenderer(IChartRenderer):
    """Baseline-comparison chart — coloured-by-verdict delta bars."""

    name = "diff"
    description = (
        "Per-metric delta_pct bars vs a stored baseline, ordered by "
        "verdict severity (regressions first). Green=improved, "
        "red=regressed, grey=unchanged."
    )
    input_schema = BaseModel   # duck-typed to DiffDefenseBaselineOutput

    def is_available(self) -> bool:
        return matplotlib_available()

    def render(self, data: BaseModel, output_path: Path) -> Path:
        plt = require_matplotlib()

        # ``data`` is a DiffDefenseBaselineOutput; ``.diff`` is a
        # BaselineDiff. Accept either shape for robustness.
        diff_obj = getattr(data, "diff", data)

        rows = _collect_rows(diff_obj)
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not rows:
            fig = plt.figure(figsize=(8, 2.5), dpi=FIGURE_DPI)
            ax = fig.add_subplot(1, 1, 1)
            ax.axis("off")
            ax.text(
                0.5, 0.5, "no diff entries",
                ha="center", va="center", fontsize=13,
                color=DARK_THEME["text_dim"],
            )
            fig.suptitle(
                "Defense Diff", fontsize=12, color=DARK_THEME["accent"],
            )
            style_figure_for_dark(fig)
            ax.set_facecolor(DARK_THEME["bg"])
            fig.tight_layout()
            fig.savefig(
                output_path, format="png", bbox_inches="tight",
                facecolor=DARK_THEME["bg"],
            )
            plt.close(fig)
            _LOG.info("diff chart (empty) → %s", output_path)
            return output_path

        fig_height = _figure_height_inches(len(rows))
        fig, ax = plt.subplots(figsize=(10.0, fig_height), dpi=FIGURE_DPI)

        baseline_name = getattr(diff_obj, "baseline_name", "<baseline>")
        gate_passed = bool(getattr(diff_obj, "gate_passed", False))
        gate_badge = "PASS" if gate_passed else "FAIL"
        fig.suptitle(
            f"Defense Diff vs '{baseline_name}'  [gate: {gate_badge}]",
            fontsize=12, y=0.995, color=DARK_THEME["accent"],
        )
        style_figure_for_dark(fig)
        style_axis_for_dark(ax)

        y_positions = list(range(len(rows)))
        ax.barh(
            y_positions,
            [r.delta_pct for r in rows],
            color=[r.color for r in rows],
            edgecolor=DARK_THEME["edge"], linewidth=0.5, height=0.6,
        )
        ax.axvline(0.0, color=DARK_THEME["spine"], linewidth=0.8)

        ax.set_xlim(*_symmetric_xlim(rows))
        ax.set_xlabel("Δ %", fontsize=9, color=DARK_THEME["accent"])
        ax.grid(axis="x", color=DARK_THEME["grid"], linewidth=0.5)
        ax.set_axisbelow(True)

        ax.set_yticks(y_positions)
        ax.set_yticklabels(
            [r.label for r in rows], fontsize=8,
            color=DARK_THEME["accent_muted"],
        )
        ax.invert_yaxis()

        for y, row in zip(y_positions, rows):
            offset = 1.5 if row.delta_pct >= 0 else -1.5
            ha = "left" if row.delta_pct >= 0 else "right"
            ax.text(
                row.delta_pct + offset, y,
                row.annotation,
                va="center", ha=ha, fontsize=7.5,
                color=DARK_THEME["text_on_bar"],
            )

        # Verdict legend — compact, matching the dark theme.
        from matplotlib.patches import Patch

        legend_handles = [
            Patch(
                facecolor=VERDICT_COLORS[v], edgecolor=DARK_THEME["edge"],
                label=v,
            )
            for v in _VERDICT_ORDER if any(r.verdict == v for r in rows)
        ]
        if legend_handles:
            legend = ax.legend(
                handles=legend_handles,
                loc="lower right", fontsize=8, framealpha=0.92,
                facecolor=DARK_THEME["panel"],
                edgecolor=DARK_THEME["spine"],
                labelcolor=DARK_THEME["accent_muted"],
            )
            legend.get_frame().set_linewidth(0.5)

        fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.97))
        fig.savefig(
            output_path, format="png", bbox_inches="tight",
            facecolor=DARK_THEME["bg"],
        )
        plt.close(fig)

        _LOG.info(
            "diff chart → %s (%d row(s), gate=%s)",
            output_path, len(rows), gate_badge,
        )
        return output_path
