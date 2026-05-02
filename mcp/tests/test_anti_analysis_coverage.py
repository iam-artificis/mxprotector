"""Unit tests for ``anti_analysis.coverage``."""

from __future__ import annotations

from mx_mcp.anti_analysis.coverage import compute_coverage
from mx_mcp.anti_analysis.detector_base import DetectionResult


def _r(*, tool: str, detected: bool, skipped: bool = False,
       error: str | None = None) -> DetectionResult:
    return DetectionResult(
        tool=tool, detected=detected, skipped=skipped, error=error,
    )


def test_compute_coverage_empty_input():
    coverage = compute_coverage([])
    assert coverage.detectors_total == 0
    assert coverage.detectors_informative == 0
    assert coverage.detected == 0
    assert coverage.skipped == 0
    assert coverage.errored == 0
    assert coverage.rate is None


def test_compute_coverage_all_detected():
    results = [
        _r(tool="a", detected=True),
        _r(tool="b", detected=True),
        _r(tool="c", detected=True),
    ]
    coverage = compute_coverage(results)
    assert coverage.detectors_total == 3
    assert coverage.detectors_informative == 3
    assert coverage.detected == 3
    assert coverage.skipped == 0
    assert coverage.rate == 1.0


def test_compute_coverage_none_detected():
    results = [_r(tool="a", detected=False), _r(tool="b", detected=False)]
    coverage = compute_coverage(results)
    assert coverage.detected == 0
    assert coverage.rate == 0.0


def test_compute_coverage_partial_detection():
    results = [
        _r(tool="a", detected=True),
        _r(tool="b", detected=True),
        _r(tool="c", detected=False),
        _r(tool="d", detected=False),
    ]
    coverage = compute_coverage(results)
    assert coverage.rate == 0.5


def test_compute_coverage_skipped_excluded_from_denominator():
    """A skipped detector neither counts nor deflates the rate."""
    results = [
        _r(tool="a", detected=True),
        _r(tool="b", detected=False),
        _r(tool="c", detected=False, skipped=True),
    ]
    coverage = compute_coverage(results)
    # informative = 2; detected = 1; rate = 0.5.
    assert coverage.detectors_informative == 2
    assert coverage.skipped == 1
    assert coverage.rate == 0.5


def test_compute_coverage_all_skipped_yields_none_rate():
    results = [
        _r(tool="a", detected=False, skipped=True),
        _r(tool="b", detected=False, skipped=True),
    ]
    coverage = compute_coverage(results)
    assert coverage.all_skipped is True
    assert coverage.detectors_informative == 0
    assert coverage.rate is None


def test_compute_coverage_errored_counted_in_informative():
    """An error result still informs the rate (it indicates a failure)."""
    results = [
        _r(tool="a", detected=True),
        _r(tool="b", detected=False, error="blew up"),
    ]
    coverage = compute_coverage(results)
    assert coverage.detectors_informative == 2
    assert coverage.errored == 1
    assert coverage.rate == 0.5
