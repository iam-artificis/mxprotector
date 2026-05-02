"""x64dbg-class debugger detection — anti-debug API surface.

The user-mode debugger family (x64dbg, OllyDbg, WinDbg, IDA's
local debugger) trips on anti-debug APIs the protector calls before
decrypting user code. We answer "does the protected PE ship visible
anti-debug API references?" — a static plaintext scan over the PE.

## Rationale + caveats

* A packer that wipes the IAT via Hell's Gate (the default at
  ``--level strong``) hides every ``IsDebuggerPresent`` reference
  past the stub's import-resolution phase. Plaintext API names
  remaining in the PE come from the stub's *own* IAT (the bare
  minimum the loader needs) plus any RTTI / debug residue.
* False negatives are *expected* on a well-packed binary. The
  metric is honest: zero static evidence in a packed PE means the
  protector does not leak anti-debug API names, which by itself is
  one ingredient of "we defend against debuggers" (alongside the
  dynamic primitives that wired-in dynamic detectors will measure
  in the future).
* False positives are mostly inert. A binary that imports
  ``IsDebuggerPresent`` purely for its dwOSVersion check still
  reads as "anti-debug surface present"; this matches the metric's
  intent (we are scoring *coverage*, not effective-defence).

## Patterns

The needle list pairs the classic ring-3 anti-debug APIs with
the smaller-but-overlooked ones (``OutputDebugStringA`` for the
OllyDbg format-string vector, ``CloseHandle`` with invalid handle
for the unhandled-exception trick).
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


# Curated list — every entry is hand-picked as a primitive that real
# anti-debug primer code uses. Order does not matter; coverage is
# binary (detected / not).
_X64DBG_NEEDLES: tuple[str, ...] = (
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "DbgUiRemoteBreakin",
    "DbgBreakPoint",
)


@register_detector
class X64dbgDetector(IDetector):
    """Static scan for anti-debug API surface targeting x64dbg-class debuggers."""

    name: ClassVar[str] = "x64dbg"
    description: ClassVar[str] = (
        "Static plaintext scan for ring-3 anti-debug API names "
        "(IsDebuggerPresent, NtQueryInformationProcess, …). Detects "
        "whether the protected PE leaks visible references to the "
        "anti-debug surface that x64dbg-class debuggers trip on."
    )
    targets: ClassVar[tuple[str, ...]] = ("x64dbg", "OllyDbg", "WinDbg")

    async def detect(self, binary_path: Path) -> DetectionResult:
        try:
            hits = scan_strings(binary_path, _X64DBG_NEEDLES)
        except OSError as e:
            return DetectionResult(
                tool=self.name, detected=False,
                error=f"scan failed: {e}",
            )
        unique = sorted({h.needle for h in hits})
        _LOG.debug(
            "x64dbg detector: %s hits=%d unique=%d",
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
