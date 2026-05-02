"""Unicorn / emulator detection — anti-emulation opcode surface.

Pure-CPU emulators like Unicorn implement neither the full PEB / TEB
nor every privileged opcode. Anti-emulation primitives lean on this
gap by emitting characteristic instructions whose semantics differ
between native CPUs and emulators:

* ``CPUID`` (``0F A2``) — legitimate hardware reports vendor, family,
  feature flags. Unicorn's default CPUID returns a thin canned
  response; mismatches are easy to detect at runtime.
* ``RDTSC`` / ``RDTSCP`` (``0F 31`` / ``0F 01 F9``) — timing primitives
  used to detect single-stepping / emulation slow-down.
* ``IN AL, DX`` (``EC``) — port I/O, illegal in user mode but rejected
  with non-uniform semantics across emulators.
* ``RDPMC`` (``0F 33``) — performance-counter read; emulators stub it.

## Rationale + caveats

The detection is byte-pattern-based: we scan the PE on disk for
these opcode sequences. Code-section restriction is intentionally
absent for now (PE parsing of arbitrary packed binaries is brittle);
false positives in non-code data are rare in practice (random
``0F A2`` byte adjacencies happen, but the count gate is binary —
one match is enough).

Unlike the string-based detectors, this one's signal survives even
when the packer wipes the IAT and encrypts strings: opcode bytes
have to be present in plaintext at *some* point for the CPU to
execute them. A packer that encrypts the stub's anti-emulation
primitives until runtime would mask this signal — that is a valid
defensive trade-off but it also means the static signal is honest.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar

from mx_mcp.anti_analysis._static_evidence import scan_byte_patterns
from mx_mcp.anti_analysis.detector_base import (
    DetectionResult,
    IDetector,
    register_detector,
)


_LOG = logging.getLogger(__name__)


# Each entry is (byte sequence, label). Order does not matter; the
# detection is binary across the whole list.
_UNICORN_PATTERNS: tuple[tuple[bytes, str], ...] = (
    (b"\x0f\xa2",       "CPUID"),
    (b"\x0f\x31",       "RDTSC"),
    (b"\x0f\x01\xf9",   "RDTSCP"),
    (b"\x0f\x33",       "RDPMC"),
)


@register_detector
class UnicornDetector(IDetector):
    """Static scan for anti-emulation opcode bytes."""

    name: ClassVar[str] = "unicorn"
    description: ClassVar[str] = (
        "Static byte-pattern scan for characteristic anti-emulation "
        "opcodes (CPUID, RDTSC, RDTSCP, RDPMC). Detects whether the "
        "protected PE ships instructions whose semantics diverge "
        "between real CPUs and pure-CPU emulators like Unicorn."
    )
    targets: ClassVar[tuple[str, ...]] = ("Unicorn", "QEMU", "BoxedWine")

    async def detect(self, binary_path: Path) -> DetectionResult:
        try:
            hits = scan_byte_patterns(binary_path, _UNICORN_PATTERNS)
        except OSError as e:
            return DetectionResult(
                tool=self.name, detected=False,
                error=f"scan failed: {e}",
            )
        labels = sorted({h.label for h in hits})
        _LOG.debug(
            "unicorn detector: %s hits=%d unique=%d",
            binary_path.name, len(hits), len(labels),
        )
        return DetectionResult(
            tool=self.name,
            detected=bool(hits),
            evidence={
                "hit_count": len(hits),
                "unique_opcodes": labels,
                "first_offsets": [
                    {"opcode": h.label, "offset": h.offset}
                    for h in hits[:8]
                ],
            },
        )
