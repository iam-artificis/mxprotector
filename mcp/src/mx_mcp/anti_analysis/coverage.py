"""Coverage aggregator — list[DetectionResult] → DetectionCoverage.

Pure function; the benchmark calls into here once it has every
detector's outcome. Split out so the aggregation logic is unit-
testable without invoking detectors.

## Rate semantics

``rate = detected_count / informative_count``.

* ``informative_count`` excludes SKIPPED results (the tool wasn't
  available, so the detector cannot speak to coverage).
* ``detected_count`` counts ``detected=True`` informative results.

When *every* detector skipped, ``rate is None`` and downstream
callers (the benchmark, gates) treat that as "no signal" rather
than zero.
"""

from __future__ import annotations

from typing import Sequence

from pydantic import BaseModel, Field

from mx_mcp.anti_analysis.detector_base import DetectionResult


class DetectionCoverage(BaseModel):
    """Aggregate over one binary's per-detector outcomes."""

    detectors_total: int = Field(
        description="Number of registered detectors that produced a result."
    )
    detectors_informative: int = Field(
        description="Detectors that contributed to the rate (not skipped)."
    )
    detected: int = Field(
        description="Detectors that flagged the binary as defending."
    )
    skipped: int = Field(
        description="Detectors that skipped (tool/backend unavailable)."
    )
    errored: int = Field(
        description="Detectors that produced an error result (counted in informative)."
    )
    rate: float | None = Field(
        default=None,
        description=(
            "detected / informative; None when every detector skipped."
        ),
    )

    @property
    def all_skipped(self) -> bool:
        return self.detectors_total > 0 and self.detectors_informative == 0


def compute_coverage(results: Sequence[DetectionResult]) -> DetectionCoverage:
    """Aggregate per-detector outcomes into a single coverage record.

    Empty input returns a zero-everything record with ``rate=None``;
    the benchmark surfaces that as "no detectors registered" rather
    than synthesising a 0.0 score.
    """
    detectors_total = len(results)
    informative = [r for r in results if r.informative]
    detected = sum(1 for r in informative if r.detected)
    skipped = sum(1 for r in results if r.skipped)
    errored = sum(1 for r in results if r.error is not None and not r.skipped)

    rate: float | None
    if not informative:
        rate = None
    else:
        rate = detected / float(len(informative))

    return DetectionCoverage(
        detectors_total=detectors_total,
        detectors_informative=len(informative),
        detected=detected,
        skipped=skipped,
        errored=errored,
        rate=rate,
    )


__all__ = ["DetectionCoverage", "compute_coverage"]
