"""Unit tests for ``anti_analysis._static_evidence``.

Covers ``scan_strings`` (ASCII + UTF-16LE) and ``scan_byte_patterns``
(opcode lookup).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mx_mcp.anti_analysis._static_evidence import (
    BytePatternHit,
    StringHit,
    scan_byte_patterns,
    scan_strings,
)


# ============================================================================
# scan_strings
# ============================================================================


def test_scan_strings_finds_ascii_match(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00\x00IsDebuggerPresent\x00\x00")
    hits = scan_strings(pe, ("IsDebuggerPresent",))
    assert len(hits) == 1
    assert hits[0].encoding == "ascii"
    assert hits[0].offset == 2
    assert hits[0].needle == "IsDebuggerPresent"


def test_scan_strings_finds_utf16le_match(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00" + "frida-agent".encode("utf-16le"))
    hits = scan_strings(pe, ("frida-agent",))
    encodings = {h.encoding for h in hits}
    assert "utf16le" in encodings


def test_scan_strings_finds_both_encodings(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(
        b"VBoxService" + b"\x00\x00" + "VBoxService".encode("utf-16le"),
    )
    hits = scan_strings(pe, ("VBoxService",))
    assert {h.encoding for h in hits} == {"ascii", "utf16le"}


def test_scan_strings_returns_empty_on_no_hit(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"clean binary\x00\x00")
    hits = scan_strings(pe, ("IsDebuggerPresent",))
    assert hits == []


def test_scan_strings_finds_multiple_offsets(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"FOO" + b"X" * 16 + b"FOO")
    hits = scan_strings(pe, ("FOO",))
    offsets = [h.offset for h in hits if h.encoding == "ascii"]
    assert offsets == [0, 19]


def test_scan_strings_empty_needle_list(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"anything")
    assert scan_strings(pe, ()) == []


def test_scan_strings_raises_on_unreadable(tmp_path: Path):
    """OSError from a missing file propagates to the caller."""
    pe = tmp_path / "missing.bin"
    with pytest.raises(OSError):
        scan_strings(pe, ("x",))


# ============================================================================
# scan_byte_patterns
# ============================================================================


def test_scan_byte_patterns_finds_cpuid_opcode(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x90\x90\x0f\xa2\x90")    # NOP NOP CPUID NOP
    hits = scan_byte_patterns(pe, ((b"\x0f\xa2", "CPUID"),))
    assert len(hits) == 1
    assert hits[0].label == "CPUID"
    assert hits[0].offset == 2


def test_scan_byte_patterns_returns_empty_on_no_match(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x90" * 32)
    hits = scan_byte_patterns(pe, ((b"\x0f\xa2", "CPUID"),))
    assert hits == []


def test_scan_byte_patterns_handles_multiple_patterns(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x0f\xa2\x90\x0f\x31")    # CPUID, RDTSC
    hits = scan_byte_patterns(
        pe,
        (
            (b"\x0f\xa2", "CPUID"),
            (b"\x0f\x31", "RDTSC"),
        ),
    )
    labels = sorted({h.label for h in hits})
    assert labels == ["CPUID", "RDTSC"]


def test_scan_byte_patterns_skips_empty_needle(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x0f\xa2")
    hits = scan_byte_patterns(pe, ((b"", "empty"), (b"\x0f\xa2", "CPUID")))
    assert [h.label for h in hits] == ["CPUID"]


def test_scan_byte_patterns_finds_overlapping_independent_matches(tmp_path: Path):
    pe = tmp_path / "x.bin"
    # Two adjacent CPUID opcodes — both must surface.
    pe.write_bytes(b"\x0f\xa2\x0f\xa2")
    hits = scan_byte_patterns(pe, ((b"\x0f\xa2", "CPUID"),))
    assert [h.offset for h in hits] == [0, 2]


def test_scan_byte_patterns_empty_pattern_list(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x0f\xa2")
    assert scan_byte_patterns(pe, ()) == []


# ============================================================================
# Dataclass round-trips
# ============================================================================


def test_string_hit_is_hashable_frozen():
    h = StringHit(needle="x", encoding="ascii", offset=0)
    {h}   # passes if hashable
    with pytest.raises(AttributeError):
        h.offset = 5  # type: ignore[misc]


def test_byte_pattern_hit_is_hashable_frozen():
    h = BytePatternHit(pattern=b"\x0f\xa2", label="CPUID", offset=0)
    {h}
    with pytest.raises(AttributeError):
        h.offset = 5  # type: ignore[misc]
