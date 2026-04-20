"""Tests for the minimal PE reader.

Two surfaces under test:

* ``read_entry_point_rva`` — entry-point reader used by static invariants.
  Validated against the real ``traced_fixture`` plus synthetic error PEs.
* ``read_section_bytes`` — RVA-window reader used by benchmarks. Mostly
  exercised via handcrafted fake-PE bytes so we can prove round-trip on
  every edge (zero-fill tail, out-of-range RVA, zero size) without
  depending on the session-scoped builder fixture.
"""

from __future__ import annotations

import pytest

from mx_mcp.common.pe_reader import (
    NotAPeError,
    SectionNotFoundError,
    read_entry_point_rva,
    read_section_bytes,
)


# ============================================================================
# read_entry_point_rva — existing coverage (unchanged).
# ============================================================================


def test_reads_entry_point_from_fixture(traced_fixture):
    ep = read_entry_point_rva(traced_fixture.binary)
    assert ep > 0
    assert ep < 0xFFFFFFFF


def test_raises_on_non_pe(tmp_path):
    junk = tmp_path / "junk.exe"
    junk.write_bytes(b"not a PE at all")
    with pytest.raises(NotAPeError):
        read_entry_point_rva(junk)


def test_raises_on_missing_pe_signature(tmp_path):
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x80).to_bytes(4, "little")
    buf[0x80:0x84] = b"XXXX"
    fake = tmp_path / "fake.exe"
    fake.write_bytes(bytes(buf))
    with pytest.raises(NotAPeError):
        read_entry_point_rva(fake)


# ============================================================================
# read_section_bytes — new surface.
#
# We handcraft a minimal PE with a configurable section table. It's
# *not* a loadable binary — it has just enough DOS+PE+SectionTable
# structure for the reader's parse path. This keeps the tests
# self-contained and fast.
# ============================================================================


def _build_fake_pe(
    sections: list[tuple[str, bytes, int]],
    *,
    e_lfanew: int = 0x80,
    opt_header_size: int = 0xE0,
) -> bytes:
    """Assemble a fake PE.

    ``sections`` is ``[(name, raw_bytes, virtual_address), ...]``. Raw
    data is laid out sequentially starting at
    ``e_lfanew + 4 + 20 + opt_header_size + 40*num_sections`` — i.e.
    immediately after the section table. ``virtual_size`` equals
    ``len(raw_bytes)``. Everything else (optional header fields, reloc
    pointers, …) is zero.
    """
    header_end = e_lfanew + 4 + 20 + opt_header_size + 40 * len(sections)
    buf = bytearray(header_end)
    # DOS stub
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    # PE signature + FileHeader
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    # FileHeader.NumberOfSections at +2
    buf[e_lfanew + 4 + 2:e_lfanew + 4 + 4] = len(sections).to_bytes(2, "little")
    # FileHeader.SizeOfOptionalHeader at +16
    buf[e_lfanew + 4 + 16:e_lfanew + 4 + 18] = opt_header_size.to_bytes(2, "little")

    sect_off = e_lfanew + 4 + 20 + opt_header_size
    raw_cursor = header_end
    section_rows: list[bytes] = []
    for name, raw, va in sections:
        entry = bytearray(40)
        # Name (padded to 8 bytes with NULs)
        name_bytes = name.encode("ascii")[:8]
        entry[0:len(name_bytes)] = name_bytes
        entry[8:12] = len(raw).to_bytes(4, "little")         # VirtualSize
        entry[12:16] = va.to_bytes(4, "little")              # VirtualAddress
        entry[16:20] = len(raw).to_bytes(4, "little")        # SizeOfRawData
        entry[20:24] = raw_cursor.to_bytes(4, "little")      # PointerToRawData
        # reloc / linenumber / characteristics left zero
        section_rows.append(bytes(entry))
        raw_cursor += len(raw)

    for i, row in enumerate(section_rows):
        buf[sect_off + 40 * i:sect_off + 40 * (i + 1)] = row

    # Append raw section data in the declared order.
    for _, raw, _ in sections:
        buf.extend(raw)

    return bytes(buf)


def test_read_section_bytes_happy_path(tmp_path):
    payload = bytes(range(256)) * 4  # 1024 deterministic bytes
    pe = _build_fake_pe([(".text", payload, 0x1000)])
    path = tmp_path / "ok.exe"
    path.write_bytes(pe)

    got = read_section_bytes(path, 0x1000, 256)
    assert got == payload[:256]


def test_read_section_bytes_partial_offset(tmp_path):
    payload = bytes(range(256))
    pe = _build_fake_pe([(".text", payload, 0x2000)])
    path = tmp_path / "off.exe"
    path.write_bytes(pe)

    got = read_section_bytes(path, 0x2010, 16)
    assert got == payload[0x10:0x20]


def test_read_section_bytes_zero_size_returns_empty(tmp_path):
    pe = _build_fake_pe([(".text", b"\x90" * 32, 0x3000)])
    path = tmp_path / "zs.exe"
    path.write_bytes(pe)
    assert read_section_bytes(path, 0x3000, 0) == b""


def test_read_section_bytes_zero_fills_past_raw(tmp_path):
    """Window extends past ``SizeOfRawData`` — tail is zero-filled to
    match how the loader would present a BSS-like region."""
    raw = b"\xAB" * 16
    pe = _build_fake_pe([(".text", raw, 0x4000)])
    path = tmp_path / "zf.exe"
    path.write_bytes(pe)

    got = read_section_bytes(path, 0x4000, 32)
    assert got == raw + b"\x00" * 16


def test_read_section_bytes_multi_section_lookup(tmp_path):
    pe = _build_fake_pe([
        (".text", b"\x11" * 16, 0x1000),
        (".data", b"\x22" * 16, 0x2000),
        (".vm",   b"\x33" * 16, 0x3000),
    ])
    path = tmp_path / "multi.exe"
    path.write_bytes(pe)

    assert read_section_bytes(path, 0x1000, 4) == b"\x11\x11\x11\x11"
    assert read_section_bytes(path, 0x2000, 4) == b"\x22\x22\x22\x22"
    assert read_section_bytes(path, 0x3004, 4) == b"\x33\x33\x33\x33"


def test_read_section_bytes_unknown_rva_raises(tmp_path):
    pe = _build_fake_pe([(".text", b"\x90" * 16, 0x1000)])
    path = tmp_path / "miss.exe"
    path.write_bytes(pe)
    with pytest.raises(SectionNotFoundError):
        read_section_bytes(path, 0x9000, 4)


def test_read_section_bytes_negative_size_rejected(tmp_path):
    pe = _build_fake_pe([(".text", b"\x00" * 16, 0x1000)])
    path = tmp_path / "neg.exe"
    path.write_bytes(pe)
    with pytest.raises(ValueError):
        read_section_bytes(path, 0x1000, -1)


def test_read_section_bytes_real_pe_roundtrip(traced_fixture):
    """End-to-end check on an actual builder-produced PE: reading the
    entry point's section must yield non-empty bytes."""
    ep = read_entry_point_rva(traced_fixture.binary)
    got = read_section_bytes(traced_fixture.binary, ep, 64)
    assert len(got) == 64
    # Entry-point region is code — not all zeros, not all 0xCC.
    assert got != b"\x00" * 64
    assert got != b"\xCC" * 64
