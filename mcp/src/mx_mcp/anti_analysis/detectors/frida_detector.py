"""Frida instrumentation detection — anti-instrumentation surface.

Frida injects a JS engine + agent into the target process. Common
anti-Frida primitives scan for distinctive thread names / module
names / file paths Frida leaves behind. This detector answers "does
the protected PE ship any of those scan strings?".

## Rationale + caveats

* Anti-Frida primitives are typically string-driven: the binary
  enumerates threads / modules / open files and pattern-matches
  against ``"gum-js-loop"``, ``"frida-agent"``, etc. Even with a
  Hell's Gate IAT wipe, those *string literals* must live somewhere
  in the binary.
* A packer that encrypts strings in addition to wiping the IAT
  hides this evidence too. Static detection then reads as "no
  anti-Frida primitives surfaced", which is the honest answer.
* Catching ``"frida-server"`` or ``"frida-helper"`` mostly happens
  on Linux; we keep them in the list because the detector is
  cross-platform and a Linux MxProtector port is on the deferred
  roadmap.
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


_FRIDA_NEEDLES: tuple[str, ...] = (
    "gum-js-loop",
    "gmain",
    "gdbus",
    "frida-agent",
    "frida-helper",
    "frida-server",
    "frida-gadget",
    "linjector",
)


@register_detector
class FridaDetector(IDetector):
    """Static scan for anti-Frida instrumentation primitives."""

    name: ClassVar[str] = "frida"
    description: ClassVar[str] = (
        "Static plaintext scan for distinctive Frida-injected names "
        "(gum-js-loop, frida-agent, …). Detects whether the protected "
        "PE ships strings the binary uses at runtime to enumerate "
        "Frida-leftover threads, modules, or paths."
    )
    targets: ClassVar[tuple[str, ...]] = ("Frida",)

    async def detect(self, binary_path: Path) -> DetectionResult:
        try:
            hits = scan_strings(binary_path, _FRIDA_NEEDLES)
        except OSError as e:
            return DetectionResult(
                tool=self.name, detected=False,
                error=f"scan failed: {e}",
            )
        unique = sorted({h.needle for h in hits})
        _LOG.debug(
            "frida detector: %s hits=%d unique=%d",
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
