"""Metadata-leakage byte scanner.

Shared primitive for P5. Two surfaces consume it:

* :mod:`mx_mcp.invariants.no_protector_metadata_leaked` — hard-block
  invariant. Any hit on the forbidden list fails the protected build.
* :mod:`mx_mcp.benchmarks.leakage_benchmark` — soft regression
  benchmark. Counts forbidden hits, PDB-path residue, and Rich-header
  presence across the corpus.

## Scanner model

The scanner reads the whole PE into memory and hunts for byte
signatures. Every forbidden literal is matched in **two encodings**:

* **ASCII** — raw bytes of the literal.
* **UTF-16LE** — each byte interleaved with a NUL, matching the
  on-disk layout of ``wchar_t`` string tables and resources on
  Windows.

UTF-16BE is skipped: Windows PEs are little-endian and inserting a
BE match surface would invite false positives (every even-offset
ASCII run looks like a BE string if you squint).

Offsets reported are raw file offsets, because that is the form
accepted by hex editors / ``binwalk -o`` and is trivially mapped
to an RVA later via the section table if a tool needs it.

## Fail-closed

Unreadable files propagate :class:`OSError` to the caller — the
invariant and benchmark both translate that to a FAIL / error-sample
consistent with the rest of the stack. Empty binary → no hits
(trivially clean).

## Scope

The scanner is **not** a string extractor. It matches exact
literals. Regex-based category checks (e.g. "anything ending in
``.pdb``") are separate helpers that scan the same bytes once
and decode ASCII runs lazily.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path


_LOG = logging.getLogger(__name__)


# ============================================================================
# Forbidden-literal catalogue
# ============================================================================
#
# Every entry here is a string that should never leak into a shipped
# protected binary. Three families:
#
# 1. **Protector identity** — ``MxProtector`` / ``mxprotector`` /
#    SDK namespace markers. Their presence means the protector's
#    *name* is plaintext in the output — a direct attacker signal
#    and a trivial YARA hit.
# 2. **SDK guard markers** — ``MX_VM_BEGIN`` / ``MX_GUARD_BEGIN`` /
#    ``MX_CFF_BEGIN``. These are macro names the SDK *strips* during
#    protection; if any survive, a pass failed to process its region.
# 3. **Pass class names** — ``VirtualizationPass`` etc. These live in
#    the builder, not the output, so a hit here means debug info /
#    RTTI from the builder somehow got linked into the packer stub.
#
# The list is intentionally case-sensitive. Case-insensitive matching
# would drag in false positives (e.g. ``mxNetwork``); explicit
# lowercase and capitalised entries are paired below where both casings
# are realistic.
_FORBIDDEN_LITERALS: tuple[str, ...] = (
    # Protector identity.
    "MxProtector",
    "mxprotector",
    "mx::sdk",
    "basic_mx_string",
    "MxString",
    "MxWString",
    # SDK guard markers — must be stripped during build.
    "MX_VM_BEGIN",
    "MX_VM_END",
    "MX_GUARD_BEGIN",
    "MX_GUARD_END",
    "MX_CFF_BEGIN",
    "MX_CFF_END",
    # Pass class names — builder-only symbols.
    "VirtualizationPass",
    "PackerPass",
    "GuardPass",
    "MutationPass",
    "ObfuscationPass",
    "CfgFlatteningPass",
    "StringProtectionPass",
)


def forbidden_literals() -> tuple[str, ...]:
    """Return the default forbidden-literal catalogue.

    Exposed as a function so callers can extend it (``(*forbidden_literals(),
    "CustomLeak")``) without mutating the module-level tuple in place.
    """
    return _FORBIDDEN_LITERALS


# ============================================================================
# Match record
# ============================================================================


@dataclass(frozen=True, slots=True)
class LeakHit:
    """One forbidden-literal match inside a PE.

    ``encoding`` distinguishes ``ascii`` from ``utf16le`` — the same
    literal can match both, and a post-hoc reviewer usually wants to
    know which encoding flagged so they can reproduce the hit with
    ``strings`` / ``strings -eL``.
    """

    literal: str
    encoding: str  # "ascii" | "utf16le"
    offset: int


# ============================================================================
# Scanners
# ============================================================================


def scan_forbidden_literals(
    binary_path: Path,
    literals: tuple[str, ...] | None = None,
) -> list[LeakHit]:
    """Scan ``binary_path`` for every occurrence of every forbidden literal.

    Reports both ASCII and UTF-16LE matches. Offsets are raw file
    offsets (file start = 0). Duplicate matches of the same literal at
    different offsets are all reported — an invariant wants to know
    the magnitude, and a benchmark wants to count occurrences.

    ``literals`` defaults to :func:`forbidden_literals`. Passing an
    explicit tuple lets tests target a synthetic catalogue without
    polluting the global one.
    """
    if literals is None:
        literals = _FORBIDDEN_LITERALS
    if not literals:
        return []

    data = binary_path.read_bytes()
    hits: list[LeakHit] = []

    for lit in literals:
        ascii_needle = lit.encode("ascii")
        utf16_needle = lit.encode("utf-16le")
        hits.extend(_find_all(ascii_needle, data, lit, "ascii"))
        hits.extend(_find_all(utf16_needle, data, lit, "utf16le"))

    hits.sort(key=lambda h: (h.offset, h.literal, h.encoding))
    return hits


# Regex over ASCII runs: printable byte run of 1+ chars followed by
# ``.pdb``. Anchored on the ``.pdb`` suffix specifically — we want
# "was a PDB path shipped", not "any printable run". The 1-char
# prefix floor filters a bare ``.pdb`` tag (not a real path), while
# still catching the shortest realistic leak ``a.pdb`` = 5 chars
# as well as long paths like ``D:\build\protect.pdb``.
_PDB_RE = re.compile(rb"[\x20-\x7e]+\.pdb", re.IGNORECASE)


def scan_pdb_paths(binary_path: Path) -> list[tuple[int, str]]:
    """Return all ``.pdb``-ending printable runs in ``binary_path``.

    One tuple per match: ``(file_offset, literal)``. The returned
    literal is the full printable run, including any surrounding
    path — i.e. ``D:\\build\\foo.pdb`` rather than just ``foo.pdb``.

    A packed binary produced by a release-mode builder should emit
    zero results. Any hit is a candidate for ``leaked_pdb_path``
    benchmark surface regression and/or a debug-info strip failure.
    """
    data = binary_path.read_bytes()
    out: list[tuple[int, str]] = []
    for m in _PDB_RE.finditer(data):
        out.append((m.start(), m.group().decode("ascii", errors="replace")))
    return out


# The MSVC ``Rich`` signature sits between the DOS stub and the PE
# header. The four-byte marker ``Rich`` is XOR-encoded with a key
# that varies per link, so we cannot sniff the obfuscated entries —
# only the terminating ``Rich`` tag, which is emitted in the clear.
# Real MSVC binaries carry it; the packer currently preserves it.
_RICH_MARKER = b"Rich"


def has_rich_header(binary_path: Path) -> bool:
    """True iff the MSVC Rich-header signature ``b"Rich"`` is present.

    Scan is bounded to the first 2 KiB — the Rich tag always sits
    inside the DOS stub / pre-PE gap, well under that floor. Bounding
    the read avoids a false positive from a random ASCII payload
    later in the file matching the four-byte needle.
    """
    with binary_path.open("rb") as f:
        prefix = f.read(0x800)
    return _RICH_MARKER in prefix


# ============================================================================
# Private helpers
# ============================================================================


def _find_all(
    needle: bytes, haystack: bytes, literal: str, encoding: str,
) -> list[LeakHit]:
    """Non-overlapping ``bytes.find`` loop → :class:`LeakHit` list.

    ``bytes.find`` is C-speed; a generator-based regex is overkill
    for the ~50 literals × 4 MiB haystacks we process. Non-overlapping
    matches are the right semantic: two occurrences of
    ``MxProtector`` next to each other should count as two hits, not
    three.
    """
    out: list[LeakHit] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        out.append(LeakHit(literal=literal, encoding=encoding, offset=idx))
        start = idx + len(needle)
    return out
