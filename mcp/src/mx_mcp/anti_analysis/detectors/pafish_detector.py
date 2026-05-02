"""pafish / sandbox detection — anti-VM identifier surface.

pafish is a sample-targeted anti-sandbox primer that codifies the
canonical "am I in a VM?" checks: virtualisation vendor strings in
the system, hypervisor MAC OUI prefixes, vmtools service names,
sandbox-specific registry keys.

A protected binary that ships those same strings is one that runs
the same checks at runtime. We answer "does the PE leak the
identifier substrings real anti-VM primitives compare against?".

## Rationale + caveats

* The strings live in the BINARY's memory, not in the registry /
  hardware they end up comparing against. A packer that encrypts
  strings hides this evidence — same caveat as the Frida detector.
* Some of these strings appear in benign code as well (e.g.
  ``"VBoxService"`` could be a friendly logger string). We accept
  modest false-positive risk because the metric is *coverage*, not
  *effective-defence*.
* The list mirrors the public pafish primer in spirit; we curate
  it against the protector's surface area rather than ship the
  whole ~100-string pafish dictionary verbatim.
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


_PAFISH_NEEDLES: tuple[str, ...] = (
    # VirtualBox indicators.
    "VBoxService",
    "VBoxTray",
    "VBoxMouse",
    "VBoxGuest",
    # VMware indicators.
    "vmtoolsd",
    "vmwareuser",
    "VMwareVMX",
    "vmware",
    # Hyper-V / Xen / QEMU.
    "vmicheartbeat",
    "vmicvss",
    "qemu-ga",
    "xenservice",
    # Sandbox-specific.
    "Sandboxie",
    "SbieSvc",
    "wine_get_unix_file_name",
)


@register_detector
class PafishDetector(IDetector):
    """Static scan for anti-VM / anti-sandbox identifier strings."""

    name: ClassVar[str] = "pafish"
    description: ClassVar[str] = (
        "Static plaintext scan for VM / sandbox indicator strings "
        "(VBoxService, vmtoolsd, Sandboxie, …). Detects whether the "
        "protected PE ships the substrings real anti-VM primitives "
        "compare against to recognise their host environment."
    )
    targets: ClassVar[tuple[str, ...]] = (
        "pafish", "VirtualBox", "VMware", "Sandboxie", "Wine",
    )

    async def detect(self, binary_path: Path) -> DetectionResult:
        try:
            hits = scan_strings(binary_path, _PAFISH_NEEDLES)
        except OSError as e:
            return DetectionResult(
                tool=self.name, detected=False,
                error=f"scan failed: {e}",
            )
        unique = sorted({h.needle for h in hits})
        _LOG.debug(
            "pafish detector: %s hits=%d unique=%d",
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
