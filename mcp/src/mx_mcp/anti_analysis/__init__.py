"""Anti-analysis detection coverage (P10).

Cross-cutting subsystem that scores whether the protected binary
ships anti-X primitives covering the major analysis tool families
called out in MCP.md: x64dbg, Frida, Unicorn, pafish, al-khaser.

## Architecture

* :mod:`detector_base` — :class:`IDetector` ABC + registry decorator
  + :class:`DetectionResult` model. Mirrors the IBenchmark / IGate
  patterns: one file per detector, decorator-based registration,
  zero edits to existing files when adding a new family.
* :mod:`coverage` — pure aggregator: ``list[DetectionResult]`` →
  :class:`DetectionCoverage` with rate / detected / skipped counts.
* :mod:`detectors` — package with one file per analysis tool family.
  Initial catalogue: x64dbg, Frida, Unicorn, pafish, al-khaser.
* :mod:`_static_evidence` — shared helpers: scan PE bytes for
  ASCII / UTF-16LE API-name strings, search code sections for
  characteristic opcode byte sequences (CPUID, RDTSC).

## Design rationale

We **stay static** for the MVP: each detector scans the protected PE
on disk for primitives that match the targeted analysis tool. Real
dynamic detection (run-binary-under-tool, observe-behaviour) requires
external tools (x64dbg subprocess, pafish.exe, al-khaser.exe) and is
deferred to FUTURE.md. Static coverage is honest — if the packer's
stub wipes API names via Hell's Gate, the static detector reports
``False`` for that family, which is the right answer for "does the
shipped binary ship visible anti-X primitives".

The detector contract is async-shaped to leave the door open for
dynamic backends; current implementations all run sync inside
``asyncio.to_thread``.

## Coverage metric

``coverage_rate`` = ``detected_count / non_skipped_count``. SKIPPED
detectors (external tool unavailable) are excluded from the
denominator so a host without pafish does not artificially deflate
the score. When *every* detector skips, the rate is reported as
``None`` — indistinguishable from "no evidence" by design.
"""

from mx_mcp.anti_analysis.coverage import DetectionCoverage, compute_coverage
from mx_mcp.anti_analysis.detector_base import (
    DetectionResult,
    IDetector,
    all_detectors,
    register_detector,
)

# Side-effect import: pulling the detectors subpackage triggers
# ``@register_detector`` on every concrete detector module. Mirrors
# how benchmarks/__init__.py and gates/__init__.py auto-register.
from mx_mcp.anti_analysis import detectors as _detectors_pkg  # noqa: F401, E402

__all__ = [
    "DetectionCoverage",
    "DetectionResult",
    "IDetector",
    "all_detectors",
    "compute_coverage",
    "register_detector",
]
