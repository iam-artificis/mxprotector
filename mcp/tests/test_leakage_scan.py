"""Unit tests for the byte-level leakage scanner.

Covers the three public helpers in :mod:`mx_mcp.common.leakage_scan`:

* ``scan_forbidden_literals`` — exact-match hunt across a tuple of
  strings, ASCII + UTF-16LE.
* ``scan_pdb_paths`` — regex hunt for ``.pdb``-ending printable runs.
* ``has_rich_header`` — MSVC ``Rich`` tag presence in first 2 KiB.

Every test uses a synthetic ``bytes`` payload written to a temp file;
nothing here needs a real PE or the builder. The scanner's contract is
pure file → match-list, so fixture size stays minimal.
"""

from __future__ import annotations

from pathlib import Path

from mx_mcp.common.leakage_scan import (
    forbidden_literals,
    has_rich_header,
    scan_forbidden_literals,
    scan_pdb_paths,
)


# ============================================================================
# scan_forbidden_literals
# ============================================================================


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_forbidden_scan_empty_file_returns_no_hits(tmp_path: Path):
    binary = _write(tmp_path, "empty.bin", b"")
    assert scan_forbidden_literals(binary) == []


def test_forbidden_scan_clean_file_returns_no_hits(tmp_path: Path):
    # Synthetic PE-like prefix plus arbitrary junk — no protector literal.
    binary = _write(
        tmp_path, "clean.bin",
        b"MZ" + b"\x00" * 64 + b"KERNEL32.DLL\x00VirtualProtect\x00" * 4,
    )
    assert scan_forbidden_literals(binary) == []


def test_forbidden_scan_finds_ascii_hit(tmp_path: Path):
    binary = _write(
        tmp_path, "leak.bin",
        b"\x00" * 128 + b"MxProtector" + b"\x00" * 32,
    )
    hits = scan_forbidden_literals(binary)
    assert len(hits) == 1
    assert hits[0].literal == "MxProtector"
    assert hits[0].encoding == "ascii"
    assert hits[0].offset == 128


def test_forbidden_scan_finds_utf16le_hit(tmp_path: Path):
    needle = "MxProtector".encode("utf-16le")
    binary = _write(
        tmp_path, "leak_w.bin",
        b"\x00" * 64 + needle + b"\x00" * 16,
    )
    hits = scan_forbidden_literals(binary)
    # Only UTF-16LE matches — the ASCII scan finds no contiguous ASCII
    # copy of the needle.
    assert len(hits) == 1
    assert hits[0].encoding == "utf16le"
    assert hits[0].offset == 64


def test_forbidden_scan_detects_both_encodings(tmp_path: Path):
    """Same literal appearing once as ASCII and once as UTF-16LE
    produces two distinct hits with different ``encoding`` tags."""
    ascii_part = b"before\x00MxProtector\x00after"
    utf_part = "MxProtector".encode("utf-16le")
    binary = _write(
        tmp_path, "both.bin", ascii_part + b"\x00" * 16 + utf_part,
    )
    hits = scan_forbidden_literals(binary)
    encodings = {h.encoding for h in hits}
    assert encodings == {"ascii", "utf16le"}
    literals = {h.literal for h in hits}
    assert literals == {"MxProtector"}


def test_forbidden_scan_multiple_hits_same_literal_nonoverlapping(tmp_path: Path):
    """Adjacent occurrences count separately; the finder is
    non-overlapping so two back-to-back copies = two hits (not three)."""
    needle = b"MxProtector"
    binary = _write(tmp_path, "dup.bin", needle + needle + b"\x00" * 4)
    hits = scan_forbidden_literals(binary)
    ascii_hits = [h for h in hits if h.encoding == "ascii"]
    assert [h.offset for h in ascii_hits] == [0, len(needle)]


def test_forbidden_scan_custom_literals_isolate_from_default_catalogue(
    tmp_path: Path,
):
    """A custom catalogue overrides the default; default literals
    present in the file are ignored when a caller passes an explicit
    tuple."""
    binary = _write(
        tmp_path, "custom.bin",
        b"MxProtector" + b"FoobarMarker" + b"\x00" * 4,
    )
    hits = scan_forbidden_literals(binary, literals=("FoobarMarker",))
    assert len(hits) == 1
    assert hits[0].literal == "FoobarMarker"


def test_forbidden_scan_empty_catalogue_returns_no_hits(tmp_path: Path):
    binary = _write(tmp_path, "noop.bin", b"MxProtector" * 8)
    assert scan_forbidden_literals(binary, literals=()) == []


def test_forbidden_scan_output_is_deterministic_sort(tmp_path: Path):
    """Hits sort by (offset, literal, encoding) so snapshot tests
    in the invariant stay stable across runs."""
    data = (
        b"PackerPass"                     # offset 0
        + b"\x00" * 16
        + "GuardPass".encode("utf-16le")   # offset 26
        + b"\x00" * 8
        + b"GuardPass"                    # offset ... (later)
    )
    binary = _write(tmp_path, "sorted.bin", data)
    hits = scan_forbidden_literals(binary)
    # Sorted strictly ascending by offset.
    offsets = [h.offset for h in hits]
    assert offsets == sorted(offsets)


def test_forbidden_literals_includes_expected_anchors():
    cat = forbidden_literals()
    # A representative slice of each family — not a full enumeration
    # (full list would make the test brittle to intentional additions).
    assert "MxProtector" in cat
    assert "mxprotector" in cat
    assert "MX_VM_BEGIN" in cat
    assert "MX_GUARD_BEGIN" in cat
    assert "VirtualizationPass" in cat
    assert "PackerPass" in cat


# ============================================================================
# scan_pdb_paths
# ============================================================================


def test_pdb_scan_no_pdb_path_returns_empty(tmp_path: Path):
    binary = _write(
        tmp_path, "nopdb.bin",
        b"KERNEL32.DLL\x00VirtualProtect\x00",
    )
    assert scan_pdb_paths(binary) == []


def test_pdb_scan_finds_simple_pdb_path(tmp_path: Path):
    binary = _write(
        tmp_path, "pdb.bin",
        b"\x00D:\\build\\protect.pdb\x00",
    )
    hits = scan_pdb_paths(binary)
    assert len(hits) == 1
    off, lit = hits[0]
    assert lit.endswith(".pdb")
    assert "D:\\build\\protect.pdb" in lit
    # Offset points at the start of the matched run.
    assert off == 1


def test_pdb_scan_is_case_insensitive(tmp_path: Path):
    binary = _write(tmp_path, "upper.bin", b"\x00FOO.PDB\x00")
    assert len(scan_pdb_paths(binary)) == 1


def test_pdb_scan_finds_multiple(tmp_path: Path):
    binary = _write(
        tmp_path, "multi.bin",
        b"a.pdb\x00\x00\x00C:\\other.pdb\x00",
    )
    hits = scan_pdb_paths(binary)
    assert len(hits) == 2
    literals = [lit for _, lit in hits]
    assert literals[0].endswith("a.pdb")
    assert literals[1].endswith("other.pdb")


def test_pdb_scan_ignores_bare_suffix_without_prefix(tmp_path: Path):
    """A bare ``.pdb`` with no preceding printable chars is filtered.

    The regex requires ≥1 printable character before the ``.pdb``
    suffix so this case — four printable chars total, zero filename
    — does not produce a hit. A real leaked path always has a name
    component before the extension.
    """
    binary = _write(tmp_path, "bare.bin", b"\x00.pdb\x00")
    assert scan_pdb_paths(binary) == []


def test_pdb_scan_shortest_realistic_match(tmp_path: Path):
    """``x.pdb`` — 1-char filename — is the minimum accepted hit."""
    binary = _write(tmp_path, "short.bin", b"\x00x.pdb\x00")
    assert len(scan_pdb_paths(binary)) == 1


# ============================================================================
# has_rich_header
# ============================================================================


def test_rich_header_absent_returns_false(tmp_path: Path):
    binary = _write(tmp_path, "norich.bin", b"MZ" + b"\x00" * 512)
    assert has_rich_header(binary) is False


def test_rich_header_present_within_prefix(tmp_path: Path):
    binary = _write(
        tmp_path, "rich.bin",
        b"MZ" + b"\x00" * 128 + b"Rich" + b"\x00" * 64,
    )
    assert has_rich_header(binary) is True


def test_rich_header_beyond_prefix_is_ignored(tmp_path: Path):
    """A stray ``Rich`` well past the DOS-stub region (past first
    2 KiB) should not trigger a false positive."""
    binary = _write(
        tmp_path, "latetag.bin",
        b"MZ" + b"\x00" * 0x800 + b"Rich" + b"\x00" * 64,
    )
    assert has_rich_header(binary) is False
