"""Minimal PE header reader — entry point RVA only.

Used by static invariants (``oep_is_stub``) that need to ask "where
does the loader jump first?" without depending on a full PE library.
Avoids the extra ``pefile`` dependency for a 4-byte field read.

Layout (PE32+/PE32, little-endian):
  DOS header at 0:
    +0x3C uint32  e_lfanew  — file offset of the PE signature.
  PE header at `e_lfanew`:
    +0     char[4]  signature  ("PE\\0\\0").
    +4     IMAGE_FILE_HEADER              (20 bytes).
    +24    IMAGE_OPTIONAL_HEADER.Magic     (uint16).
           ... [16 bytes of linker / size fields] ...
    +40    IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint (uint32).
"""

from __future__ import annotations

from pathlib import Path


_DOS_MAGIC = b"MZ"
_PE_SIG = b"PE\x00\x00"
_OPTIONAL_ENTRY_POINT_OFFSET = 40  # from start of PE signature


class NotAPeError(ValueError):
    """Raised when a file does not look like a PE image."""


def read_entry_point_rva(binary_path: Path) -> int:
    """Return ``AddressOfEntryPoint`` (RVA) of a PE file.

    Reads only the first 0x400 bytes — enough for any real headers.
    """
    with binary_path.open("rb") as f:
        header = f.read(0x400)

    if len(header) < 0x40 or header[:2] != _DOS_MAGIC:
        raise NotAPeError(f"{binary_path}: DOS MZ magic missing")

    e_lfanew = int.from_bytes(header[0x3C:0x40], "little")
    if e_lfanew + _OPTIONAL_ENTRY_POINT_OFFSET + 4 > len(header):
        raise NotAPeError(
            f"{binary_path}: e_lfanew={e_lfanew:#x} points past the prefix "
            f"we read ({len(header)} bytes)"
        )

    if header[e_lfanew:e_lfanew + 4] != _PE_SIG:
        raise NotAPeError(f"{binary_path}: PE signature missing at {e_lfanew:#x}")

    ep_offset = e_lfanew + _OPTIONAL_ENTRY_POINT_OFFSET
    return int.from_bytes(header[ep_offset:ep_offset + 4], "little")
