"""MCP tool: return the sections recorded in a sidecar with roles.

Requires the protected PE to have been built with ``--trace-hints``.
Roles (``vm``/``cff``/``packer``/``strings``/``guard``) come from the
sidecar; built-in section names (``.text``, ``.rdata``, …) come through
as their literal name in the ``role`` field.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from mx_mcp.common.sidecar import load_sidecar, sidecar_path_for
from mx_mcp.common.tool_base import ITool, register_tool


# PE ``Characteristics`` flag decode — subset that matters for RE.
_SCN_FLAGS: tuple[tuple[int, str], ...] = (
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"),
    (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
)


def _decode_characteristics(c: int) -> list[str]:
    return [name for mask, name in _SCN_FLAGS if c & mask]


def _resolve(path_str: str, workspace_root: Path) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (workspace_root / p).resolve()


class ListSectionsInput(BaseModel):
    binary_path: str = Field(
        description=(
            "Path to the protected PE (absolute or relative to the workspace "
            "root). The PE must have been built with --trace-hints."
        )
    )
    sidecar_path: str | None = Field(
        None,
        description=(
            "Optional explicit sidecar path; defaults to "
            "<binary_path>.mxtrace.json."
        ),
    )


class SectionEntry(BaseModel):
    role: str
    name: str
    rva: int
    size: int
    characteristics: int
    flags: list[str]


class ListSectionsOutput(BaseModel):
    binary_path: str
    sidecar_path: str
    schema_version: int
    level: str
    timestamp: str
    sections: list[SectionEntry]


@register_tool
class ListSectionsTool(ITool[ListSectionsInput, ListSectionsOutput]):
    name = "list_sections"
    description = (
        "Load the .mxtrace.json sidecar of a protected PE and return its "
        "sections keyed by logical role (vm/cff/packer/strings/guard or the "
        "raw section name). Requires --trace-hints at build time."
    )
    input_schema = ListSectionsInput
    output_schema = ListSectionsOutput

    async def run(
        self, args: ListSectionsInput, session
    ) -> ListSectionsOutput:
        binary = _resolve(args.binary_path, session.workspace_root)
        sidecar = (
            _resolve(args.sidecar_path, session.workspace_root)
            if args.sidecar_path
            else sidecar_path_for(binary)
        )

        doc = load_sidecar(sidecar)

        entries = [
            SectionEntry(
                role=role,
                name=s.name,
                rva=s.rva,
                size=s.size,
                characteristics=s.characteristics,
                flags=_decode_characteristics(s.characteristics),
            )
            for role, s in doc.sections.items()
        ]

        return ListSectionsOutput(
            binary_path=str(binary),
            sidecar_path=str(sidecar),
            schema_version=doc.schema_version,
            level=doc.build.level,
            timestamp=doc.build.timestamp,
            sections=entries,
        )
