"""al-khaser anti-analysis suite detection — broad-coverage primitives.

al-khaser is a comprehensive anti-analysis test suite (debugging,
emulation, anti-dump, hooking) that publishes a long catalogue of
runtime checks. A protected binary that ships any meaningful subset
of those primitives reads as "broad anti-analysis surface"; the
detector spotlights APIs central to al-khaser's "level 2 / level 3"
families that are NOT already covered by the simpler debugger and
sandbox detectors.

## Rationale + caveats

* By design this needle list overlaps slightly with
  :mod:`x64dbg_detector` — we deliberately keep the high-signal
  anti-debug primitives in BOTH lists so the al-khaser score does
  not depend on the x64dbg detector having succeeded. Independence
  of detectors lets the coverage rate aggregate sensibly.
* We pick API names al-khaser specifically uses for advanced
  techniques (``BlockInput`` for input lockout, ``FindWindow`` for
  classic OllyDbg / x64dbg window detection, ``Process32First`` /
  ``Module32First`` for analysis-tool process enumeration,
  ``GetTickCount`` for time-based detection).
* Same encoding-and-packer caveats as the other static detectors.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar

from mx_mcp.anti_analysis._static_evidence import scan_strings
from mx_mcp.anti_analysis.detector_base import (
    DetectionResult,
    IDetector,
    register_detector,
)


_LOG = logging.getLogger(__name__)


_AL_KHASER_NEEDLES: tuple[str, ...] = (
    # Tool-window enumeration.
    "FindWindowA",
    "FindWindowW",
    "FindWindowExA",
    "FindWindowExW",
    "EnumWindows",
    # Process enumeration (pafish-overlap-tolerant — al-khaser uses these too).
    "Process32First",
    "Process32Next",
    "Module32First",
    "CreateToolhelp32Snapshot",
    # Anti-debug helpers beyond IsDebuggerPresent.
    "BlockInput",
    "SwitchDesktop",
    "GetThreadContext",
    "ZwQueryInformationThread",
    # Timing-based.
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    # Hook detection.
    "GetModuleHandleA",
    "GetProcAddress",
)


@register_detector
class AlKhaserDetector(IDetector):
    """Static scan for al-khaser-style broad anti-analysis primitives."""

    name: ClassVar[str] = "al_khaser"
    description: ClassVar[str] = (
        "Static plaintext scan for the API surface al-khaser uses to "
        "exercise advanced anti-analysis primitives: tool-window "
        "enumeration (FindWindow), analysis-tool process discovery "
        "(Process32First), input lockout (BlockInput), timing-based "
        "detection (GetTickCount), and hook detection (GetProcAddress)."
    )
    targets: ClassVar[tuple[str, ...]] = ("al-khaser",)

    async def detect(self, binary_path: Path) -> DetectionResult:
        try:
            hits = scan_strings(binary_path, _AL_KHASER_NEEDLES)
        except OSError as e:
            return DetectionResult(
                tool=self.name, detected=False,
                error=f"scan failed: {e}",
            )
        unique = sorted({h.needle for h in hits})
        _LOG.debug(
            "al-khaser detector: %s hits=%d unique=%d",
            binary_path.name, len(hits), len(unique),
        )
        return DetectionResult(
            tool=self.name,
            detected=bool(hits),
            evidence={
                "hit_count": len(hits),
                "unique_needles": unique,
                "first_offsets": [
                    {"needle": h.needle, "offset": h.offset, "encoding": h.encoding}
                    for h in hits[:8]
                ],
            },
        )
