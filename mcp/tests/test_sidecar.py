"""Sidecar schema round-trip against a freshly built fixture."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mx_mcp.common.sidecar import (
    CURRENT_SCHEMA_VERSION,
    Sidecar,
    load_sidecar,
    sidecar_path_for,
)


def test_fixture_sidecar_loads_cleanly(traced_fixture):
    doc = load_sidecar(traced_fixture.sidecar)
    assert doc.schema_version == CURRENT_SCHEMA_VERSION
    assert doc.build.level == "strong"
    assert doc.build.timestamp.endswith("Z")
    assert len(doc.sections) > 0


def test_fixture_has_role_mapped_sections(traced_fixture):
    doc = load_sidecar(traced_fixture.sidecar)
    roles = set(doc.sections.keys())
    # `strong` level enables VM + CFF + packer + strings.
    assert "vm" in roles
    assert "cff" in roles
    assert "packer" in roles
    assert "strings" in roles


def test_fixture_sidecar_is_valid_json(traced_fixture):
    text = traced_fixture.sidecar.read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["schema_version"] == CURRENT_SCHEMA_VERSION


def test_sidecar_path_for_appends_suffix(tmp_path):
    exe = tmp_path / "a.exe"
    assert sidecar_path_for(exe).name == "a.exe.mxtrace.json"
    dll = tmp_path / "b.dll"
    assert sidecar_path_for(dll).name == "b.dll.mxtrace.json"


def test_unknown_schema_version_rejected():
    bad = _minimal_sidecar_dict(schema_version=999)
    with pytest.raises(ValidationError):
        Sidecar.model_validate(bad)


def test_additive_fields_are_ignored_within_major():
    """Schema is forward-compatible for additive changes."""
    forward = _minimal_sidecar_dict()
    forward["future_top_level"] = 42
    forward["build"]["future_build_field"] = "ok"
    doc = Sidecar.model_validate(forward)
    assert doc.build.input == "x"


def test_missing_sidecar_raises_named_error(tmp_path):
    from mx_mcp.common.sidecar import SidecarNotFoundError
    with pytest.raises(SidecarNotFoundError):
        load_sidecar(tmp_path / "does_not_exist.mxtrace.json")


# ============================================================================
# protected_functions — new top-level list used by normalised benchmarks.
# ============================================================================


def test_protected_functions_defaults_to_empty_list():
    """Backward compatibility: sidecars produced before the builder
    started emitting this list must still parse cleanly, with the new
    field defaulting to ``[]``."""
    doc = Sidecar.model_validate(_minimal_sidecar_dict())
    assert doc.protected_functions == []


def test_protected_functions_round_trip_all_kinds():
    data = _minimal_sidecar_dict()
    data["protected_functions"] = [
        {"rva": 0x1000, "size": 64,  "kind": "cff"},
        {"rva": 0x2000, "size": 128, "kind": "vm"},
        {"rva": 0x3000, "size": 256, "kind": "guard"},
    ]
    doc = Sidecar.model_validate(data)
    assert len(doc.protected_functions) == 3
    kinds = {pf.kind for pf in doc.protected_functions}
    assert kinds == {"cff", "vm", "guard"}
    assert doc.protected_functions[0].rva == 0x1000
    assert doc.protected_functions[1].size == 128


def test_protected_functions_rva_bounds_enforced():
    """RVA field uses Uint32 — negative or out-of-range values rejected."""
    data = _minimal_sidecar_dict()
    data["protected_functions"] = [
        {"rva": -1, "size": 64, "kind": "cff"},
    ]
    with pytest.raises(ValidationError):
        Sidecar.model_validate(data)


def test_fixture_sidecar_has_protected_functions_list(traced_fixture):
    """The fixture build runs strong-level protection (CFF + VM). The
    sidecar must include a non-empty ``protected_functions`` list with
    at least one ``cff`` or ``vm`` entry."""
    doc = load_sidecar(traced_fixture.sidecar)
    assert len(doc.protected_functions) > 0
    kinds = {pf.kind for pf in doc.protected_functions}
    assert kinds & {"cff", "vm"}, (
        f"expected at least one cff/vm entry, got kinds={kinds}"
    )


def _minimal_sidecar_dict(*, schema_version: int = 1) -> dict:
    return {
        "schema_version": schema_version,
        "build": {
            "input": "x", "output": "y", "level": "strong",
            "timestamp": "2026-04-20T12:00:00Z",
        },
        "sections": {},
        "cff": {
            "dispatcher_rva": 0, "state_var_rva": 0,
            "states": [], "predicates": [],
        },
        "vm": {
            "dispatcher_rva": 0, "handler_table_rva": 0, "handlers": [],
        },
        "guard": {"regions": []},
        "strings": {"slots": []},
        "iat": {"rva": 0, "size": 0},
    }
