"""PE → Unicorn memory map.

Strict scope: the function below maps every PE section into a fresh
Unicorn instance and returns a small descriptor the runner uses to
start emulation. We do *not* synthesise a PEB / TEB, do *not* load
ntdll, do *not* resolve imports. A protected stub that walks PEB or
calls into ntdll will trip an unmapped-fetch shortly after start —
that *is* the defence signal the OEP-reach benchmark measures.

## Layout

We map a single contiguous range starting at the PE's preferred
``ImageBase`` (the optional-header field) sized to ``SizeOfImage``
rounded up to the page size. Section bytes are written from disk at
each section's ``VirtualAddress``. Sections with no on-disk bytes
(BSS / aligned tails) leave the page zero-filled — Unicorn pages
zero-init by default.

Two auxiliary regions get mapped for the runner to use:

* **Stack** — a single page, ``rsp`` pre-set to the top minus a
  scratch slot so the first ``push`` does not under-shoot.
* **TLS / scratch** — small page near the stack used for any
  caller-side scribbling before the run starts.

These auxiliaries sit outside the PE's declared range so a hook
that snapshots ``RIP`` cannot accidentally map a stack address back
to a PE section.

## Image-base randomisation

Real Windows ASLRs the image — Unicorn does not. Some packers
encode RIP-relative ``lea`` to recover their own base; mapping the
image at its declared ``ImageBase`` makes those compute-the-base
sequences resolve to the same address the protector expects. We
deliberately do not opt into ASLR-style randomisation here: it
adds variance to a fast-tier metric that wants determinism.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mx_mcp.common.pe_reader import (
    NotAPeError,
)


_LOG = logging.getLogger(__name__)


# 4 KiB Windows page size. Unicorn requires ``mem_map`` regions to be
# a multiple of this; we round up section ranges to suit.
PAGE_SIZE = 0x1000

# Stack + scratch geometry. Sized once and shared between the two
# runners so address layout is deterministic across benchmarks.
STACK_REGION_BASE = 0x70000000
STACK_REGION_SIZE = 0x40000     # 256 KiB — generous for a single
                                # handler / packer-stub stack frame.
SCRATCH_REGION_BASE = 0x71000000
SCRATCH_REGION_SIZE = 0x10000   # 64 KiB.


# Offsets inside the PE optional header (relative to ``e_lfanew``).
# Mirrors the offsets in :mod:`mx_mcp.common.pe_reader`; duplicated
# here so the loader does not reach into a sibling module's private
# constants.
_PE_SIG_OFF = 0
_FILE_HEADER_NUM_SECTIONS_OFF = 4 + 2
_FILE_HEADER_OPT_SIZE_OFF = 4 + 16
_OPT_MAGIC_OFF = 4 + 20             # IMAGE_OPTIONAL_HEADER.Magic
_OPT_ENTRY_POINT_OFF = 4 + 20 + 16  # AddressOfEntryPoint
_OPT_IMAGE_BASE_PE32_OFF = 4 + 20 + 28
_OPT_IMAGE_BASE_PE32P_OFF = 4 + 20 + 24  # 8-byte field
_OPT_SIZE_OF_IMAGE_OFF = 4 + 20 + 56

_PE32_MAGIC = 0x10B
_PE32P_MAGIC = 0x20B

_DOS_MAGIC = b"MZ"
_PE_SIG = b"PE\x00\x00"
_HEADER_PREFIX_BYTES = 0x10000


@dataclass(frozen=True, slots=True)
class SectionMap:
    """One mapped PE section."""

    name: str
    base: int
    size: int


@dataclass(frozen=True, slots=True)
class LoadedPE:
    """Result of mapping a PE into a Unicorn instance.

    ``mu`` is the live ``Uc`` the runner drives; ``image_base`` and
    ``entry_point`` are absolute virtual addresses inside that
    Unicorn's address space. ``image_size`` is the rounded-up extent
    of the mapped image so the runner can sanity-check stops.

    ``sections`` retains a list of mapped section descriptors so
    benchmark evidence can name which section each instruction-hit
    landed in.
    """

    mu: Any  # Uc — kept untyped to avoid a hard dep on the package
    image_base: int
    image_size: int
    entry_point: int
    sections: tuple[SectionMap, ...]
    stack_top: int


# ============================================================================
# Public loader
# ============================================================================


def load_pe(uc_module, binary_path: Path) -> LoadedPE:
    """Map ``binary_path`` into a fresh ``Uc`` x86-64 emulator.

    ``uc_module`` is the imported ``unicorn`` module (passed in
    rather than imported here so the runner can swap a fake module
    in tests without monkey-patching the loader).

    Raises:
        NotAPeError: header malformed.
        OSError: file unreadable.

    Returns a :class:`LoadedPE` ready for ``mu.emu_start(...)``.
    """
    raw = binary_path.read_bytes()
    if len(raw) < 0x40 or raw[:2] != _DOS_MAGIC:
        raise NotAPeError(f"{binary_path}: DOS magic missing")
    e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
    if raw[e_lfanew:e_lfanew + 4] != _PE_SIG:
        raise NotAPeError(f"{binary_path}: PE signature missing")

    optional_magic = int.from_bytes(
        raw[e_lfanew + _OPT_MAGIC_OFF:e_lfanew + _OPT_MAGIC_OFF + 2], "little",
    )
    if optional_magic == _PE32P_MAGIC:
        image_base = int.from_bytes(
            raw[e_lfanew + _OPT_IMAGE_BASE_PE32P_OFF:
                e_lfanew + _OPT_IMAGE_BASE_PE32P_OFF + 8],
            "little",
        )
    elif optional_magic == _PE32_MAGIC:
        image_base = int.from_bytes(
            raw[e_lfanew + _OPT_IMAGE_BASE_PE32_OFF:
                e_lfanew + _OPT_IMAGE_BASE_PE32_OFF + 4],
            "little",
        )
    else:
        raise NotAPeError(
            f"{binary_path}: unsupported optional-header magic {optional_magic:#x}"
        )

    entry_rva = int.from_bytes(
        raw[e_lfanew + _OPT_ENTRY_POINT_OFF:
            e_lfanew + _OPT_ENTRY_POINT_OFF + 4],
        "little",
    )
    size_of_image = int.from_bytes(
        raw[e_lfanew + _OPT_SIZE_OF_IMAGE_OFF:
            e_lfanew + _OPT_SIZE_OF_IMAGE_OFF + 4],
        "little",
    )

    # Build a Uc, map the image + auxiliaries, then write section
    # bytes. Order matters: ``mem_map`` allocates pages; ``mem_write``
    # only succeeds on already-mapped ranges.
    mu = uc_module.Uc(uc_module.UC_ARCH_X86, uc_module.UC_MODE_64)

    image_size_aligned = _align_up(size_of_image, PAGE_SIZE)
    mu.mem_map(
        image_base, image_size_aligned,
        uc_module.UC_PROT_READ | uc_module.UC_PROT_WRITE | uc_module.UC_PROT_EXEC,
    )
    mu.mem_map(
        STACK_REGION_BASE, STACK_REGION_SIZE,
        uc_module.UC_PROT_READ | uc_module.UC_PROT_WRITE,
    )
    mu.mem_map(
        SCRATCH_REGION_BASE, SCRATCH_REGION_SIZE,
        uc_module.UC_PROT_READ | uc_module.UC_PROT_WRITE,
    )

    # Headers — keep the MZ/PE/section table visible inside the
    # mapped image so a stub that reads its own headers (for
    # rip-relative base recovery, IAT lookup) does not trip
    # immediately. Bound by the optional header's
    # ``SizeOfHeaders`` if it lies inside our prefix; otherwise
    # write the on-disk prefix verbatim.
    header_prefix = raw[: min(len(raw), _HEADER_PREFIX_BYTES, image_size_aligned)]
    mu.mem_write(image_base, header_prefix)

    sections = _parse_section_table(raw, e_lfanew)
    section_map: list[SectionMap] = []
    for sect in sections:
        if sect.size_of_raw_data > 0:
            file_off = sect.pointer_to_raw_data
            data = raw[file_off:file_off + sect.size_of_raw_data]
            mu.mem_write(image_base + sect.virtual_address, data)
        section_map.append(SectionMap(
            name=sect.name,
            base=image_base + sect.virtual_address,
            size=max(sect.virtual_size, sect.size_of_raw_data),
        ))

    # Stack pointer one slot below the top so the first ``push``
    # does not underflow into the next region.
    stack_top = STACK_REGION_BASE + STACK_REGION_SIZE - 0x100
    mu.reg_write(uc_module.x86_const.UC_X86_REG_RSP, stack_top)
    mu.reg_write(uc_module.x86_const.UC_X86_REG_RBP, stack_top)

    _LOG.debug(
        "loaded %s: image_base=0x%X size=0x%X EP=0x%X sections=%d",
        binary_path.name, image_base, image_size_aligned,
        image_base + entry_rva, len(section_map),
    )

    return LoadedPE(
        mu=mu,
        image_base=image_base,
        image_size=image_size_aligned,
        entry_point=image_base + entry_rva,
        sections=tuple(section_map),
        stack_top=stack_top,
    )


# ============================================================================
# Section-table parser — small enough to live with the loader without
# adding a third file.
# ============================================================================


@dataclass(frozen=True, slots=True)
class _SectionRow:
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int


def _parse_section_table(raw: bytes, e_lfanew: int) -> list[_SectionRow]:
    """Read every IMAGE_SECTION_HEADER from the PE.

    Mirrors the equivalent helper in :mod:`mx_mcp.common.pe_reader`
    — duplicated to keep ``emulation.unicorn.loader`` standalone
    without an inter-module import.
    """
    num_sections = int.from_bytes(
        raw[e_lfanew + _FILE_HEADER_NUM_SECTIONS_OFF:
            e_lfanew + _FILE_HEADER_NUM_SECTIONS_OFF + 2],
        "little",
    )
    opt_size = int.from_bytes(
        raw[e_lfanew + _FILE_HEADER_OPT_SIZE_OFF:
            e_lfanew + _FILE_HEADER_OPT_SIZE_OFF + 2],
        "little",
    )
    table_off = e_lfanew + 4 + 20 + opt_size

    rows: list[_SectionRow] = []
    for i in range(num_sections):
        entry = raw[table_off + i * 40: table_off + (i + 1) * 40]
        if len(entry) < 40:
            break
        rows.append(_SectionRow(
            name=entry[:8].split(b"\x00", 1)[0].decode("ascii", errors="replace"),
            virtual_size=int.from_bytes(entry[8:12], "little"),
            virtual_address=int.from_bytes(entry[12:16], "little"),
            size_of_raw_data=int.from_bytes(entry[16:20], "little"),
            pointer_to_raw_data=int.from_bytes(entry[20:24], "little"),
        ))
    return rows


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


__all__ = [
    "LoadedPE",
    "PAGE_SIZE",
    "SCRATCH_REGION_BASE",
    "STACK_REGION_BASE",
    "SectionMap",
    "load_pe",
]
