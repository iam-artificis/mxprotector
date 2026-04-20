"""Unit tests for reporting.charts.measurement_chart.

Matplotlib-gated — tests skip gracefully when the ``[viz]`` extra is
not installed.
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
from mx_mcp.reporting.charts.measurement_chart import (
    MeasurementChartRenderer,
    _row_for_metric,
)
from mx_mcp.tools.measure_defense import MeasureDefenseOutput


pytestmark = pytest.mark.skipif(
    not matplotlib_available(),
    reason="matplotlib not installed — pip install -e \".[viz]\"",
)


# ============================================================================
# Helpers
# ============================================================================


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _metric(
    *, name: str, direction: MetricDirection, p90: float | None,
    scale: MetricScale | None,
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


def _measurement(benchmarks: list[BenchmarkResult]) -> MeasureDefenseOutput:
    return MeasureDefenseOutput(
        corpus_path="corpus/",
        corpus_size=len(benchmarks),
        benchmark_count=len(benchmarks),
        duration_ms=10,
        benchmarks=benchmarks,
    )


# ============================================================================
# Pure-logic helpers (cheap, always run when matplotlib is present)
# ============================================================================


def test_row_for_metric_with_scale_produces_score():
    m = _metric(
        name="m",
        direction=MetricDirection.HIGHER_BETTER,
        p90=15.0,
        scale=MetricScale(weak_value=1.0, strong_value=30.0),
    )
    row = _row_for_metric(m)
    assert row is not None
    assert row.has_scale is True
    assert row.score is not None
    # Interior value on [1,30] → roughly 0.48 for p90=15.
    assert 0.40 < row.score < 0.55


def test_row_for_metric_without_scale_marks_no_scale():
    m = _metric(
        name="m",
        direction=MetricDirection.HIGHER_BETTER,
        p90=7.0,
        scale=None,
    )
    row = _row_for_metric(m)
    assert row is not None
    assert row.has_scale is False
    assert row.score is None
    assert "no scale" in row.annotation


def test_row_for_metric_with_no_data_returns_none():
    m = _metric(
        name="m",
        direction=MetricDirection.HIGHER_BETTER,
        p90=None,
        scale=MetricScale(weak_value=0.0, strong_value=1.0),
    )
    assert _row_for_metric(m) is None


# ============================================================================
# render() end-to-end — produces a valid PNG
# ============================================================================


def test_render_produces_png_for_populated_benchmark(tmp_path: Path):
    bench = _bench("cff_microcode", [
        _metric(
            name=n,
            direction=MetricDirection.HIGHER_BETTER,
            p90=v,
            scale=MetricScale(weak_value=0.0, strong_value=10.0),
        )
        for n, v in [("mc_blocks", 5.0), ("mc_gotos", 1.0)]
    ])
    data = _measurement([bench])

    renderer = MeasurementChartRenderer()
    assert renderer.is_available()

    out = tmp_path / "measurement.png"
    result = renderer.render(data, out)
    assert result == out.resolve()
    assert out.exists()
    assert out.stat().st_size > 500  # sanity lower bound for a real chart
    assert out.read_bytes()[:8] == _PNG_MAGIC


def test_render_empty_measurement_still_writes_png(tmp_path: Path):
    data = _measurement([])

    out = tmp_path / "empty.png"
    MeasurementChartRenderer().render(data, out)
    assert out.exists()
    assert out.read_bytes()[:8] == _PNG_MAGIC


def test_render_mixed_scaled_and_unscaled_metrics(tmp_path: Path):
    # One scaled + one unscaled — both should appear.
    bench = _bench("b1", [
        _metric(
            name="m_scaled",
            direction=MetricDirection.HIGHER_BETTER,
            p90=5.0,
            scale=MetricScale(weak_value=0.0, strong_value=10.0),
        ),
        _metric(
            name="m_raw",
            direction=MetricDirection.LOWER_BETTER,
            p90=0.3,
            scale=None,
        ),
    ])

    out = tmp_path / "mixed.png"
    MeasurementChartRenderer().render(_measurement([bench]), out)
    assert out.exists()
    assert out.read_bytes()[:8] == _PNG_MAGIC
