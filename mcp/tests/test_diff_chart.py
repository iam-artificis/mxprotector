"""Unit tests for reporting.charts.diff_chart.

Matplotlib-gated — skip when the ``[viz]`` extra is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mx_mcp.common.baselines import BaselineDiff, DiffVerdict, MetricDiff
from mx_mcp.common.benchmark_base import MetricDirection
from mx_mcp.reporting.charts._mpl import matplotlib_available
from mx_mcp.reporting.charts.diff_chart import (
    DiffChartRenderer,
    _collect_rows,
    _symmetric_xlim,
)
from mx_mcp.tools.diff_defense_baseline import DiffDefenseBaselineOutput


pytestmark = pytest.mark.skipif(
    not matplotlib_available(),
    reason="matplotlib not installed — pip install -e \".[viz]\"",
)


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _entry(
    *, name: str = "m", benchmark: str = "b", verdict: DiffVerdict,
    delta: float | None = 0.0, cur: float | None = 1.0, base: float | None = 1.0,
) -> MetricDiff:
    return MetricDiff(
        benchmark=benchmark, metric=name,
        direction=MetricDirection.HIGHER_BETTER,
        verdict=verdict,
        current_value=cur, baseline_value=base, delta_pct=delta,
    )


def _diff_doc(**kwargs) -> BaselineDiff:
    defaults = {
        "baseline_name": "v1",
        "baseline_timestamp": "2026-04-20T00:00:00Z",
        "current_timestamp": "2026-04-20T12:00:00Z",
        "gate_passed": True,
        "improvements": [],
        "regressions": [],
        "unchanged": [],
        "skipped": [],
        "added": [],
        "removed": [],
    }
    defaults.update(kwargs)
    return BaselineDiff(**defaults)


def _wrap(diff: BaselineDiff) -> DiffDefenseBaselineOutput:
    return DiffDefenseBaselineOutput(
        baseline_name=diff.baseline_name,
        baselines_root="/tmp",
        corpus_size=0,
        benchmark_count=0,
        duration_ms=1,
        diff=diff,
    )


# ============================================================================
# Pure-logic helpers
# ============================================================================


def test_collect_rows_orders_regressions_first():
    diff = _diff_doc(
        gate_passed=False,
        improvements=[_entry(name="i", verdict=DiffVerdict.IMPROVED, delta=+10.0)],
        regressions=[_entry(name="r", verdict=DiffVerdict.REGRESSED, delta=-10.0)],
        unchanged=[_entry(name="u", verdict=DiffVerdict.UNCHANGED, delta=0.0)],
    )
    rows = _collect_rows(diff)
    assert rows[0].verdict == "regressed"
    assert rows[1].verdict == "improved"
    assert rows[2].verdict == "unchanged"


def test_symmetric_xlim_minimum_visible():
    # Single tiny delta → the floor kicks in so the bar stays visible.
    rows = _collect_rows(_diff_doc(
        improvements=[_entry(verdict=DiffVerdict.IMPROVED, delta=+0.5)],
    ))
    lo, hi = _symmetric_xlim(rows)
    assert lo == -hi
    assert hi >= 10.0


def test_symmetric_xlim_scales_with_data():
    rows = _collect_rows(_diff_doc(
        improvements=[_entry(verdict=DiffVerdict.IMPROVED, delta=+80.0)],
    ))
    lo, hi = _symmetric_xlim(rows)
    assert hi >= 80.0
    assert lo <= -80.0


# ============================================================================
# render()
# ============================================================================


def test_render_diff_produces_png(tmp_path: Path):
    diff = _diff_doc(
        gate_passed=False,
        regressions=[
            _entry(name="mc_blocks", verdict=DiffVerdict.REGRESSED,
                   cur=0.5, base=1.0, delta=-50.0),
        ],
        improvements=[
            _entry(name="mc_gotos", verdict=DiffVerdict.IMPROVED,
                   cur=2.0, base=1.0, delta=+100.0),
        ],
    )
    out = tmp_path / "diff.png"
    DiffChartRenderer().render(_wrap(diff), out)
    assert out.exists()
    assert out.read_bytes()[:8] == _PNG_MAGIC
    assert out.stat().st_size > 500


def test_render_empty_diff_still_writes_png(tmp_path: Path):
    out = tmp_path / "empty.png"
    DiffChartRenderer().render(_wrap(_diff_doc()), out)
    assert out.exists()
    assert out.read_bytes()[:8] == _PNG_MAGIC


def test_render_accepts_bare_baseline_diff(tmp_path: Path):
    """Renderer duck-types: ``BaselineDiff`` works as input too."""
    diff = _diff_doc(
        improvements=[_entry(verdict=DiffVerdict.IMPROVED, delta=+5.0)],
    )
    out = tmp_path / "bare.png"
    DiffChartRenderer().render(diff, out)  # type: ignore[arg-type]
    assert out.exists()
