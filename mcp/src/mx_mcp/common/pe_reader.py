"""Minimal PE header reader.

Two surfaces:

* :func:`read_entry_point_rva` — ``AddressOfEntryPoint`` for static
  invariants (e.g. ``oep_is_stub``).
* :func:`read_section_bytes` — resolves an ``(rva, size)`` window to
  a raw file slice. Benchmarks that measure sidecar-reported sections
  (CFF bytecode, VM bytecode, encrypted string blob) use it to pull
  exactly those bytes off disk without depending on a full PE library.

Both helpers read only the headers (first ~64 KiB) plus the requested
window — nothing else. Scope is intentionally narrow: anything more
complex belongs behind a ``pefile`` dependency, not in this file.

Layout (PE32+/PE32, little-endian):
  DOS header at 0:
    +0x3C uint32  e_lfanew  — file offset of the PE signature.
  PE header at ``e_lfanew``:
    +0     char[4]  signature                                   ("PE\\0\\0").
    +4     IMAGE_FILE_HEADER                                    (20 bytes).
           +2  uint16 NumberOfSections
           +16 uint16 SizeOfOptionalHeader
    +24    IMAGE_OPTIONAL_HEADER.Magic                          (uint16).
           +16 (offset 40 from PE sig) uint32 AddressOfEntryPoint.
  Section table (``NumberOfSections`` entries, 40 bytes each) at:
    ``e_lfanew + 4 + 20 + SizeOfOptionalHeader``.

  Per-section entry (IMAGE_SECTION_HEADER, 40 bytes):
    +0  char[8]  Name
    +8  uint32   VirtualSize
    +12 uint32   VirtualAddress
    +16 uint32   SizeOfRawData
    +20 uint32   PointerToRawData
    +24 …        (reloc/linenumber pointers — ignored)
    +36 uint32   Characteristics
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path


_LOG = logging.getLogger(__name__)

_DOS_MAGIC = b"MZ"
_PE_SIG = b"PE\x00\x00"

# Offsets inside the PE header (from the "PE\0\0" signature start).
_OPTIONAL_ENTRY_POINT_OFFSET = 40
_FILE_HEADER_NUMBER_OF_SECTIONS_OFFSET = 4 + 2     # +4 after sig, then +2 inside FileHeader
_FILE_HEADER_OPTIONAL_SIZE_OFFSET = 4 + 16         # +4 after sig, then +16 inside FileHeader

# Section-table entry layout.
_SECT_ENTRY_SIZE = 40
_SECT_OFF_VIRTUAL_SIZE = 8
_SECT_OFF_VIRTUAL_ADDRESS = 12
_SECT_OFF_SIZE_OF_RAW_DATA = 16
_SECT_OFF_POINTER_TO_RAW_DATA = 20

# How many bytes of the file we sniff to locate the section table.
# Headers sit well under 64 KiB in every real-world PE; this bound
# keeps the reader cheap while covering anything we'll meet.
_HEADER_PREFIX_BYTES = 0x10000


class NotAPeError(ValueError):
    """Raised when a file does not look like a PE image."""


class SectionNotFoundError(LookupError):
    """Raised when no PE section covers the requested RVA."""


@dataclass(frozen=True, slots=True)
class _SectionRow:
    """Parsed IMAGE_SECTION_HEADER — only the fields we need."""

    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int

    def contains_rva(self, rva: int) -> bool:
        vsz = max(self.virtual_size, self.size_of_raw_data)
        return self.virtual_address <= rva < self.virtual_address + vsz


# ============================================================================
# Public helpers
# ============================================================================


def read_entry_point_rva(binary_path: Path) -> int:
    """Return ``AddressOfEntryPoint`` (RVA) of a PE file."""
    with binary_path.open("rb") as f:
        header = f.read(0x400)
    _require_dos_magic(binary_path, header)
    e_lfanew = _e_lfanew(header)
    _require_pe_signature(binary_path, header, e_lfanew)
    ep_offset = e_lfanew + _OPTIONAL_ENTRY_POINT_OFFSET
    if ep_offset + 4 > len(header):
        raise NotAPeError(
            f"{binary_path}: entry-point field lies past the prefix we read"
        )
    return int.from_bytes(header[ep_offset:ep_offset + 4], "little")


def read_section_bytes(
    binary_path: Path, rva: int, size: int,
) -> bytes:
    """Return ``size`` bytes starting at ``rva`` from the on-disk PE.

    Resolves RVA → raw file offset via the section table. When the
    requested window extends past the section's raw data on disk, the
    returned buffer is padded with ``\\x00`` so callers always get
    exactly ``size`` bytes — matches how the loader would observe
    an image-loaded section (BSS tail zero-filled).

    Raises:
        NotAPeError: header malformed, or section table lies past the
            header prefix we sniff.
        SectionNotFoundError: no section covers ``rva``.
        ValueError: ``size`` is negative.
    """
    if size < 0:
        raise ValueError(f"size must be ≥ 0, got {size}")
    if size == 0:
        return b""

    with binary_path.open("rb") as f:
        header = f.read(_HEADER_PREFIX_BYTES)
        _require_dos_magic(binary_path, header)
        e_lfanew = _e_lfanew(header)
        _require_pe_signature(binary_path, header, e_lfanew)

        section = _find_section_for_rva(binary_path, header, e_lfanew, rva)

        # RVA window on disk: clamp to whatever the section actually
        # has in ``SizeOfRawData`` — the rest is runtime-zeroed BSS
        # that we synthesise here for caller convenience.
        delta = rva - section.virtual_address
        raw_start = section.pointer_to_raw_data + delta
        raw_end = section.pointer_to_raw_data + section.size_of_raw_data
        want_end = raw_start + size

        on_disk_len = max(0, min(raw_end, want_end) - raw_start)
        tail_zeros = size - on_disk_len

        f.seek(raw_start)
        data = f.read(on_disk_len) if on_disk_len > 0 else b""

    if tail_zeros > 0:
        _LOG.debug(
            "read_section_bytes %s rva=0x%X size=%d: %d on-disk, %d zero-filled",
            binary_path.name, rva, size, on_disk_len, tail_zeros,
        )
        data = data + b"\x00" * tail_zeros

    return data


# ============================================================================
# Private parsers
# ============================================================================


def _require_dos_magic(path: Path, header: bytes) -> None:
    if len(header) < 0x40 or header[:2] != _DOS_MAGIC:
        raise NotAPeError(f"{path}: DOS MZ magic missing")


def _e_lfanew(header: bytes) -> int:
    return int.from_bytes(header[0x3C:0x40], "little")


def _require_pe_signature(path: Path, header: bytes, e_lfanew: int) -> None:
    if e_lfanew + 4 > len(header):
        raise NotAPeError(
            f"{path}: e_lfanew={e_lfanew:#x} points past the prefix we read "
            f"({len(header)} bytes)"
        )
    if header[e_lfanew:e_lfanew + 4] != _PE_SIG:
        raise NotAPeError(f"{path}: PE signature missing at {e_lfanew:#x}")


def _find_section_for_rva(
    path: Path, header: bytes, e_lfanew: int, rva: int,
) -> _SectionRow:
    """Locate the section whose virtual window covers ``rva``.

    Raises ``SectionNotFoundError`` if none matches; ``NotAPeError`` if
    the section table lies past the header prefix we read (extremely
    unusual — would need a >64 KiB optional header).
    """
    num_sections = int.from_bytes(
        header[e_lfanew + _FILE_HEADER_NUMBER_OF_SECTIONS_OFFSET:
               e_lfanew + _FILE_HEADER_NUMBER_OF_SECTIONS_OFFSET + 2],
        "little",
    )
    opt_size = int.from_bytes(
        header[e_lfanew + _FILE_HEADER_OPTIONAL_SIZE_OFFSET:
               e_lfanew + _FILE_HEADER_OPTIONAL_SIZE_OFFSET + 2],
        "little",
    )
    sect_table_off = e_lfanew + 4 + 20 + opt_size
    table_end = sect_table_off + num_sections * _SECT_ENTRY_SIZE
    if table_end > len(header):
        raise NotAPeError(
            f"{path}: section table [{sect_table_off:#x}..{table_end:#x}) "
            f"exceeds header prefix ({len(header)} bytes)"
        )

    for i in range(num_sections):
        entry = header[
            sect_table_off + i * _SECT_ENTRY_SIZE:
            sect_table_off + (i + 1) * _SECT_ENTRY_SIZE
        ]
        row = _parse_section_row(entry)
        if row.contains_rva(rva):
            return row

    raise SectionNotFoundError(
        f"{path}: no section covers RVA {rva:#x} "
        f"(scanned {num_sections} section(s))"
    )


def _parse_section_row(entry: bytes) -> _SectionRow:
    name = entry[:8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return _SectionRow(
        name=name,
        virtual_size=int.from_bytes(
            entry[_SECT_OFF_VIRTUAL_SIZE:_SECT_OFF_VIRTUAL_SIZE + 4], "little",
        ),
        virtual_address=int.from_bytes(
            entry[_SECT_OFF_VIRTUAL_ADDRESS:_SECT_OFF_VIRTUAL_ADDRESS + 4], "little",
        ),
        size_of_raw_data=int.from_bytes(
            entry[_SECT_OFF_SIZE_OF_RAW_DATA:_SECT_OFF_SIZE_OF_RAW_DATA + 4], "little",
        ),
        pointer_to_raw_data=int.from_bytes(
            entry[_SECT_OFF_POINTER_TO_RAW_DATA:_SECT_OFF_POINTER_TO_RAW_DATA + 4], "little",
        ),
    )
