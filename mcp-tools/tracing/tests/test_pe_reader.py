"""Tests for the minimal PE entry-point reader."""

from __future__ import annotations

import pytest

from mx_tracing.pe_reader import NotAPeError, read_entry_point_rva


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
    # Valid DOS header pointing to garbage.
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    # e_lfanew → 0x80, where we put "junk" instead of "PE\0\0"
    buf[0x3C:0x40] = (0x80).to_bytes(4, "little")
    buf[0x80:0x84] = b"XXXX"
    fake = tmp_path / "fake.exe"
    fake.write_bytes(bytes(buf))
    with pytest.raises(NotAPeError):
        read_entry_point_rva(fake)
