"""Unit tests for reporting.charts.comparison_chart.

Split into two tiers:

* Pure-logic tests exercise ``_pair_row`` and ``_align_benchmarks``
  deterministically without invoking matplotlib — run whenever the
  package imports.
* Rendering tests skip gracefully when matplotlib is missing, and
  assert real PNG magic on the output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
    MetricSample,
    MetricScale,
)
from mx_mcp.reporting.charts._mpl import matplotlib_available
from mx_mcp.reporting.charts.comparison_chart import (
    ComparisonChartInput,
    ComparisonChartRenderer,
    ComparisonSide,
    _align_benchmarks,
    _pair_row,
)


# ============================================================================
# Helpers
# ============================================================================


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _metric(
    *, name: str, p90: float | None,
    scale: MetricScale | None = MetricScale(weak_value=0.0, strong_value=10.0),
    direction: MetricDirection = MetricDirection.HIGHER_BETTER,
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=[MetricSample(sample_name="x", value=p90)] if p90 is not None else [],
        aggregate=AggregateStats(
            p10=p90, p50=p90, p90=p90, mean=p90, stddev=None,
            n_samples=1 if p90 is not None else 0, n_errors=0,
        ),
        scale=scale,
    )


def _bench(name: str, metrics: list[MetricResult]) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark=name, category="cff", tier="fast",
        duration_ms=1, metrics=metrics,
    )


def _side(label: str, benchmarks: list[BenchmarkResult]) -> ComparisonSide:
    return ComparisonSide(label=label, subtitle="", benchmarks=benchmarks)


# ============================================================================
# _pair_row pure logic
# ============================================================================


def test_pair_row_both_sides_have_scale_computes_scores():
    left = _metric(name="m", p90=3.0)   # score = 0.3
    right = _metric(name="m", p90=7.0)  # score = 0.7
    row = _pair_row("m", left, right)
    assert row is not None
    assert row.left_score == pytest.approx(0.3)
    assert row.right_score == pytest.approx(0.7)
    assert row.has_scale is True
    assert row.badge == ""


def test_pair_row_missing_left_flags_new():
    row = _pair_row("m", None, _metric(name="m", p90=5.0))
    assert row is not None
    assert row.left_score is None
    assert row.right_score is not None
    assert row.badge == "NEW"


def test_pair_row_missing_right_flags_removed():
    row = _pair_row("m", _metric(name="m", p90=4.0), None)
    assert row is not None
    assert row.right_score is None
    assert row.left_score is not None
    assert row.badge == "REMOVED"


def test_pair_row_no_data_returns_none():
    left = _metric(name="m", p90=None)
    right = _metric(name="m", p90=None)
    assert _pair_row("m", left, right) is None


def test_pair_row_no_scale_marks_badge():
    left = _metric(name="m", p90=1.0, scale=None)
    right = _metric(name="m", p90=2.0, scale=None)
    row = _pair_row("m", left, right)
    assert row is not None
    assert row.badge == "no scale"
    assert row.has_scale is False
    assert row.left_score is None and row.right_score is None
    assert row.left_raw == 1.0
    assert row.right_raw == 2.0


def test_pair_row_right_scale_preferred_when_both_present():
    """Retuning the scale on the right side (latest) should drive
    normalisation — left snapshot's old scale is informational only."""
    left = _metric(
        name="m", p90=5.0,
        scale=MetricScale(weak_value=0.0, strong_value=100.0),  # old
    )
    right = _metric(
        name="m", p90=5.0,
        scale=MetricScale(weak_value=0.0, strong_value=10.0),   # new
    )
    row = _pair_row("m", left, right)
    assert row is not None
    # Both p90 are 5.0; using the right scale [0,10] yields 0.5 on
    # both. The old [0,100] scale would have yielded 0.05.
    assert row.left_score == pytest.approx(0.5)
    assert row.right_score == pytest.approx(0.5)


# ============================================================================
# _align_benchmarks
# ============================================================================


def test_align_preserves_left_benchmark_order():
    left = [_bench("a", []), _bench("b", [])]
    right = [_bench("b", []), _bench("c", [])]
    groups = _align_benchmarks(left, right)
    # Empty-metric benchmarks produce zero rows — so they drop.
    # Seed both with a metric so the benchmarks survive.
    left = [_bench("a", [_metric(name="m", p90=1.0)]),
            _bench("b", [_metric(name="m", p90=1.0)])]
    right = [_bench("b", [_metric(name="m", p90=1.0)]),
             _bench("c", [_metric(name="m", p90=1.0)])]
    groups = _align_benchmarks(left, right)
    assert [g.bench_name for g in groups] == ["a", "b", "c"]


def test_align_metric_appears_in_both_sides():
    left = [_bench("b", [_metric(name="m", p90=2.0)])]
    right = [_bench("b", [_metric(name="m", p90=8.0)])]
    groups = _align_benchmarks(left, right)
    assert len(groups) == 1
    rows = groups[0].rows
    assert len(rows) == 1
    row = rows[0]
    assert row.left_score is not None and row.right_score is not None


# ============================================================================
# Rendering (requires matplotlib)
# ============================================================================


pytestmark = pytest.mark.skipif(
    not matplotlib_available(),
    reason="matplotlib not installed — pip install -e \".[viz]\"",
)


def test_render_produces_png_for_paired_benchmarks(tmp_path: Path):
    left_bench = _bench("cff_microcode", [
        _metric(name="mc_blocks", p90=5.0),
        _metric(name="mc_gotos",  p90=3.0),
    ])
    right_bench = _bench("cff_microcode", [
        _metric(name="mc_blocks", p90=7.5),
        _metric(name="mc_gotos",  p90=4.0),
    ])
    data = ComparisonChartInput(
        left=_side("a1bfa66", [left_bench]),
        right=_side("f1598c6", [right_bench]),
    )

    out = tmp_path / "comparison.png"
    result = ComparisonChartRenderer().render(data, out)
    assert result == out.resolve()
    assert out.exists()
    assert out.read_bytes()[:8] == _PNG_MAGIC
    assert out.stat().st_size > 1000


def test_render_with_empty_input_still_writes_png(tmp_path: Path):
    data = ComparisonChartInput(
        left=_side("empty_left", []),
        right=_side("empty_right", []),
    )
    out = tmp_path / "empty.png"
    ComparisonChartRenderer().render(data, out)
    assert out.read_bytes()[:8] == _PNG_MAGIC


def test_render_handles_added_and_removed_metrics(tmp_path: Path):
    left_bench = _bench("b1", [_metric(name="only_old", p90=5.0)])
    right_bench = _bench("b1", [_metric(name="only_new", p90=7.0)])
    data = ComparisonChartInput(
        left=_side("old", [left_bench]),
        right=_side("new", [right_bench]),
    )
    out = tmp_path / "added_removed.png"
    ComparisonChartRenderer().render(data, out)
    assert out.read_bytes()[:8] == _PNG_MAGIC


def test_render_mixed_scaled_and_unscaled(tmp_path: Path):
    left_bench = _bench("b1", [
        _metric(name="with_scale", p90=5.0),
        _metric(name="without_scale", p90=0.3, scale=None),
    ])
    right_bench = _bench("b1", [
        _metric(name="with_scale", p90=8.0),
        _metric(name="without_scale", p90=0.2, scale=None),
    ])
    data = ComparisonChartInput(
        left=_side("L", [left_bench]),
        right=_side("R", [right_bench]),
    )
    out = tmp_path / "mixed.png"
    ComparisonChartRenderer().render(data, out)
    assert out.read_bytes()[:8] == _PNG_MAGIC
