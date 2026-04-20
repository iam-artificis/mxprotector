"""Pydantic schema for the ``<output>.mxtrace.json`` sidecar.

Source of truth is the builder-side contract in
``include/mxprotector/analysis/trace_hints.hpp`` (schema v1). Drift
between the C++ writer and this module must be caught by the fixture
round-trip test (``tests/test_sidecar.py``).

Forward compatibility: additive changes within the same major are
silently ignored by pydantic's default ``extra='ignore'``. Breaking
changes must bump ``schema_version``; this module then rejects the
old major with a ``ValidationError`` so the two sides do not drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


CURRENT_SCHEMA_VERSION = 1

# ``Uint32`` mirrors C++ ``std::uint32_t`` — rva/size/characteristics
# are all 0..0xFFFFFFFF, and pydantic rejects anything outside the
# range with a clear error message.
Uint32 = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]


# ============================================================================
# Leaf label models
# ============================================================================


class SectionHint(BaseModel):
    name: str
    rva: Uint32
    size: Uint32
    characteristics: Uint32


class BuildInfo(BaseModel):
    input: str
    output: str
    level: str
    timestamp: str


class CffStateLabel(BaseModel):
    id: Uint32
    dispatcher_entry_rva: Uint32
    source_bb_rva: Uint32
    kind: str


class CffPredicateLabel(BaseModel):
    id: Uint32
    rva: Uint32
    kind: str


class VmHandlerLabel(BaseModel):
    id: Uint32
    rva: Uint32
    size: Uint32
    opcode: str


class GuardRegionLabel(BaseModel):
    id: Uint32
    rva: Uint32
    size: Uint32


class StringSlotLabel(BaseModel):
    id: Uint32
    desc_rva: Uint32
    plaintext_len: Uint32


# ============================================================================
# Grouped hint sections
# ============================================================================


class CffHints(BaseModel):
    dispatcher_rva: Uint32 = 0
    state_var_rva: Uint32 = 0
    states: list[CffStateLabel] = Field(default_factory=list)
    predicates: list[CffPredicateLabel] = Field(default_factory=list)


class VmHints(BaseModel):
    dispatcher_rva: Uint32 = 0
    handler_table_rva: Uint32 = 0
    handlers: list[VmHandlerLabel] = Field(default_factory=list)


class GuardHints(BaseModel):
    regions: list[GuardRegionLabel] = Field(default_factory=list)


class StringHints(BaseModel):
    slots: list[StringSlotLabel] = Field(default_factory=list)


class IatHints(BaseModel):
    rva: Uint32 = 0
    size: Uint32 = 0


# ============================================================================
# Top-level
# ============================================================================


class Sidecar(BaseModel):
    schema_version: int
    build: BuildInfo
    sections: dict[str, SectionHint]
    cff: CffHints
    vm: VmHints
    guard: GuardHints
    strings: StringHints
    iat: IatHints

    @field_validator("schema_version")
    @classmethod
    def _validate_version(cls, v: int) -> int:
        if v != CURRENT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version={v} "
                f"(this MCP understands v{CURRENT_SCHEMA_VERSION}). "
                f"Rebuild the MCP or the builder so they agree."
            )
        return v


# ============================================================================
# IO helpers
# ============================================================================


class SidecarNotFoundError(FileNotFoundError):
    """Raised when a sidecar file is missing next to a protected PE."""


def sidecar_path_for(binary_path: Path) -> Path:
    """Returns the canonical sidecar path next to a protected PE.

    The builder writes ``<output>.mxtrace.json`` (suffix appended, not
    replaced), so ``protected.exe`` maps to ``protected.exe.mxtrace.json``.
    """
    return binary_path.with_name(binary_path.name + ".mxtrace.json")


def load_sidecar(path: Path) -> Sidecar:
    """Load and validate the sidecar at ``path``.

    Raises:
        SidecarNotFoundError: if the file does not exist — callers
            should treat this as "rebuild with ``--trace-hints``".
        pydantic.ValidationError: on schema drift.
    """
    if not path.exists():
        raise SidecarNotFoundError(
            f"sidecar not found: {path} "
            "— rebuild the PE with mxprotector_builder --trace-hints"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    return Sidecar.model_validate(data)
