"""Static-evidence helpers for the per-tool detectors.

Every static detector inside :mod:`mx_mcp.anti_analysis.detectors`
asks one of two shapes of question:

* "Does the protected PE contain any of these ASCII / UTF-16LE
  API-name or library-name strings?" — answered by
  :func:`scan_strings`.
* "Does the protected PE's executable bytes contain any of these
  byte sequences (e.g. ``CPUID`` opcode = ``0F A2``)?" — answered by
  :func:`scan_byte_patterns`.

The helpers are deliberately narrow — anything richer (PE import
table parsing, decompiled-code analysis) would either break on
packed binaries (no plaintext IDT after Hell's Gate) or pull a
heavy dependency. Static plaintext scans are honest: they find
exactly what the packer left visible and nothing more.

## Fail-closed

Unreadable files raise :class:`OSError` to the caller; detectors
translate that into ``DetectionResult.error`` with ``detected=False``.
Empty binaries trivially miss every pattern.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path


_LOG = logging.getLogger(__name__)


# ============================================================================
# String matching
# ============================================================================


@dataclass(frozen=True, slots=True)
class StringHit:
    """One ASCII / UTF-16LE match inside the binary."""

    needle: str
    encoding: str  # "ascii" | "utf16le"
    offset: int


def scan_strings(
    binary_path: Path, needles: tuple[str, ...],
) -> list[StringHit]:
    """Scan ``binary_path`` for every occurrence of every needle.

    Each needle is matched in both ASCII and UTF-16LE encodings —
    Windows binaries routinely carry both shapes, depending on
    whether the producer used ``"foo"`` or ``L"foo"``. Offsets are
    raw file offsets; duplicate matches at different offsets are
    all reported (count matters for evidence).

    The function reads the file once and runs ``bytes.find`` per
    needle/encoding. Linear in file size — fine for the seed corpus
    (binaries < ~5 MiB).
    """
    if not needles:
        return []

    data = binary_path.read_bytes()
    hits: list[StringHit] = []
    for needle in needles:
        ascii_n = needle.encode("ascii", errors="replace")
        utf16_n = needle.encode("utf-16le", errors="replace")
        hits.extend(_find_all_string(data, ascii_n, needle, "ascii"))
        hits.extend(_find_all_string(data, utf16_n, needle, "utf16le"))
    hits.sort(key=lambda h: (h.offset, h.needle, h.encoding))
    return hits


# ============================================================================
# Byte-pattern matching
# ============================================================================


@dataclass(frozen=True, slots=True)
class BytePatternHit:
    """One opcode / byte-sequence match inside the binary."""

    pattern: bytes
    label: str
    offset: int


# Precompiled regex over `[\x20-\x7e]+` for printable-string isolation.
# Currently unused but kept so future heuristics that walk strings
# do not duplicate it.
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")


def scan_byte_patterns(
    binary_path: Path, patterns: tuple[tuple[bytes, str], ...],
) -> list[BytePatternHit]:
    """Find every occurrence of every ``(byte_sequence, label)`` pair.

    Used to spot characteristic opcodes (``CPUID`` = ``0F A2``,
    ``RDTSC`` = ``0F 31``, ``IN AL, DX`` = ``EC``) inside the
    protected binary's executable bytes. Labels are the human-readable
    name we surface in evidence so reviewers do not have to recognise
    raw bytes.

    The scan is whole-file: code sections live in distinct PE
    sections but locating them requires PE parsing we do not need
    for plaintext byte hunting. Plaintext non-code data that
    accidentally contains ``0F A2`` is acceptably rare in practice;
    if false-positive rates ever matter, a future enhancement can
    restrict the scan to executable sections.
    """
    if not patterns:
        return []

    data = binary_path.read_bytes()
    hits: list[BytePatternHit] = []
    for needle, label in patterns:
        if not needle:
            continue
        hits.extend(_find_all_bytes(data, needle, label))
    hits.sort(key=lambda h: (h.offset, h.label))
    return hits


# ============================================================================
# Private helpers
# ============================================================================


def _find_all_string(
    haystack: bytes, needle: bytes, decoded: str, encoding: str,
) -> list[StringHit]:
    """Non-overlapping ``bytes.find`` loop — same shape as leakage_scan."""
    out: list[StringHit] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        out.append(StringHit(needle=decoded, encoding=encoding, offset=idx))
        start = idx + len(needle)
    return out


def _find_all_bytes(
    haystack: bytes, needle: bytes, label: str,
) -> list[BytePatternHit]:
    """Non-overlapping byte-sequence search."""
    out: list[BytePatternHit] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        out.append(BytePatternHit(pattern=needle, label=label, offset=idx))
        start = idx + len(needle)
    return out


__all__ = [
    "BytePatternHit",
    "StringHit",
    "scan_byte_patterns",
    "scan_strings",
]
