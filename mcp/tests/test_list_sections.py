"""list_sections tool round-trip."""

from __future__ import annotations

import asyncio

import pytest

from mx_mcp.dynamic.frida.session import Session
from mx_mcp.static.sidecar_tools.list_sections import (
    ListSectionsInput,
    ListSectionsOutput,
    ListSectionsTool,
)


def test_list_sections_on_fixture(traced_fixture, repo_root):
    session = Session(workspace_root=repo_root)
    tool = ListSectionsTool()
    args = ListSectionsInput(binary_path=str(traced_fixture.binary))

    result = asyncio.run(tool.run(args, session))

    assert isinstance(result, ListSectionsOutput)
    assert result.schema_version == 1
    assert result.level == "strong"
    assert len(result.sections) > 0

    roles = {s.role for s in result.sections}
    assert "vm" in roles
    assert "packer" in roles

    # .text is always present in MSVC-built binaries and must have
    # MEM_EXECUTE in its decoded flags.
    text = next((s for s in result.sections if s.role == ".text"), None)
    assert text is not None
    assert "MEM_EXECUTE" in text.flags


def test_list_sections_missing_sidecar_raises(tmp_path, repo_root):
    from mx_mcp.common.sidecar import SidecarNotFoundError

    session = Session(workspace_root=repo_root)
    tool = ListSectionsTool()

    fake = tmp_path / "no_sidecar.exe"
    fake.write_bytes(b"MZ\x00\x00")
    args = ListSectionsInput(binary_path=str(fake))

    with pytest.raises(SidecarNotFoundError):
        asyncio.run(tool.run(args, session))


def test_tool_input_schema_json_schema_has_required():
    schema = ListSectionsTool.input_schema.model_json_schema()
    assert "binary_path" in schema["properties"]
    assert "binary_path" in schema.get("required", [])
