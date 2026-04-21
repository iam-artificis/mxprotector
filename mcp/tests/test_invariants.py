"""Invariant registry + individual evaluator + aggregator round-trip.

Two test surfaces:
  1. Isolated evaluator tests on synthetic contexts — fast, no spawn.
  2. Aggregator test on ``traced_fixture`` — full flow, spawns Frida.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from mx_mcp.common.events import Event
from mx_mcp.common.invariant_base import (
    InvariantContext,
    VerdictStatus,
    all_invariants,
)
from mx_mcp.common.sidecar import (
    BuildInfo,
    CffHints,
    GuardHints,
    IatHints,
    SectionHint,
    Sidecar,
    StringHints,
    VmHints,
)
from mx_mcp.dynamic.frida.session import Session
from mx_mcp.invariants.no_protector_metadata_leaked import (
    NoProtectorMetadataLeakedInvariant,
)
from mx_mcp.invariants.oep_is_stub import OepIsStubInvariant
from mx_mcp.invariants.packer_decrypted import PackerDecryptedInvariant
from mx_mcp.tools.verify_protection_invariants import (
    VerifyInvariantsInput,
    VerifyInvariantsOutput,
    VerifyProtectionInvariantsTool,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_contains_phase3_invariants():
    names = [cls.name for cls in all_invariants()]
    assert "packer_decrypted" in names
    assert "oep_is_stub" in names


def test_registry_contains_p5_invariant():
    names = [cls.name for cls in all_invariants()]
    assert "no_protector_metadata_leaked" in names


# ---------------------------------------------------------------------------
# Synthetic-context evaluator tests
# ---------------------------------------------------------------------------


def _minimal_sidecar(
    *, with_packer: bool = True, packer_rva: int = 0x1000, packer_size: int = 0x1000
) -> Sidecar:
    sections: dict[str, SectionHint] = {}
    if with_packer:
        sections["packer"] = SectionHint(
            name=".pk", rva=packer_rva, size=packer_size, characteristics=0x60000020
        )
    return Sidecar(
        schema_version=1,
        build=BuildInfo(input="in", output="out", level="strong", timestamp="t"),
        sections=sections,
        cff=CffHints(),
        vm=VmHints(),
        guard=GuardHints(),
        strings=StringHints(),
        iat=IatHints(),
    )


def test_packer_decrypted_passes_on_hit():
    sc = _minimal_sidecar()
    evts = [
        Event(kind="section_access", t_ms=1,
              payload={"role": "packer", "operation": "execute", "offset": 0}),
        Event(kind="api_call", t_ms=2, payload={"mod": "ntdll.dll", "fn": "NtClose"}),
    ]
    v = PackerDecryptedInvariant().evaluate(
        InvariantContext(events=evts, sidecar=sc, binary_path=Path("x.exe"))
    )
    assert v.status is VerdictStatus.PASS
    assert v.evidence["section_access_count"] == 1
    assert "execute" in v.evidence["operations"]


def test_packer_decrypted_skips_when_no_packer_section():
    sc = _minimal_sidecar(with_packer=False)
    v = PackerDecryptedInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=Path("x.exe"))
    )
    assert v.status is VerdictStatus.SKIP


def test_packer_decrypted_fails_when_section_present_but_no_events():
    sc = _minimal_sidecar()
    # Events exist but none target the packer role.
    evts = [
        Event(kind="section_access", t_ms=1,
              payload={"role": "strings", "operation": "read", "offset": 0})
    ]
    v = PackerDecryptedInvariant().evaluate(
        InvariantContext(events=evts, sidecar=sc, binary_path=Path("x.exe"))
    )
    assert v.status is VerdictStatus.FAIL


def test_oep_is_stub_passes_when_entry_in_range(traced_fixture):
    # Build a synthetic sidecar whose packer range covers the real EP
    # of the traced_fixture binary. The invariant is static — it reads
    # the PE header directly.
    from mx_mcp.common.pe_reader import read_entry_point_rva
    ep = read_entry_point_rva(traced_fixture.binary)
    sc = _minimal_sidecar(packer_rva=ep - 0x10, packer_size=0x100)
    v = OepIsStubInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=traced_fixture.binary)
    )
    assert v.status is VerdictStatus.PASS
    assert v.evidence["entry_point_rva"] == ep


def test_oep_is_stub_fails_when_entry_outside_packer(traced_fixture):
    from mx_mcp.common.pe_reader import read_entry_point_rva
    ep = read_entry_point_rva(traced_fixture.binary)
    # Packer placed far away from the actual EP.
    sc = _minimal_sidecar(packer_rva=ep + 0x100000, packer_size=0x100)
    v = OepIsStubInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=traced_fixture.binary)
    )
    assert v.status is VerdictStatus.FAIL


def test_oep_is_stub_skips_when_no_packer_section():
    sc = _minimal_sidecar(with_packer=False)
    v = OepIsStubInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=Path("/nonexistent"))
    )
    assert v.status is VerdictStatus.SKIP


# ---------------------------------------------------------------------------
# no_protector_metadata_leaked
# ---------------------------------------------------------------------------


def test_no_metadata_leaked_passes_on_clean_binary(tmp_path):
    binary = tmp_path / "clean.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 64 + b"KERNEL32.DLL\x00")
    sc = _minimal_sidecar()
    v = NoProtectorMetadataLeakedInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=binary)
    )
    assert v.status is VerdictStatus.PASS
    assert v.evidence["total_hits"] == 0


def test_no_metadata_leaked_fails_on_mxprotector_hit(tmp_path):
    binary = tmp_path / "leak.exe"
    binary.write_bytes(b"\x00" * 32 + b"MxProtector" + b"\x00" * 32)
    sc = _minimal_sidecar()
    v = NoProtectorMetadataLeakedInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=binary)
    )
    assert v.status is VerdictStatus.FAIL
    assert v.evidence["total_hits"] == 1
    assert v.evidence["distinct_literals"] == 1
    breakdown = v.evidence["breakdown"]
    assert breakdown[0]["literal"] == "MxProtector"
    assert breakdown[0]["first_offsets"][0]["offset"] == 32


def test_no_metadata_leaked_fails_on_pass_name_leak(tmp_path):
    binary = tmp_path / "passleak.exe"
    binary.write_bytes(b"abc" + b"VirtualizationPass" + b"def")
    sc = _minimal_sidecar()
    v = NoProtectorMetadataLeakedInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=binary)
    )
    assert v.status is VerdictStatus.FAIL
    literals = {b["literal"] for b in v.evidence["breakdown"]}
    assert "VirtualizationPass" in literals


def test_no_metadata_leaked_fails_on_utf16_hit(tmp_path):
    binary = tmp_path / "utf16.exe"
    binary.write_bytes(b"\x00" * 16 + "PackerPass".encode("utf-16le"))
    sc = _minimal_sidecar()
    v = NoProtectorMetadataLeakedInvariant().evaluate(
        InvariantContext(events=[], sidecar=sc, binary_path=binary)
    )
    assert v.status is VerdictStatus.FAIL
    encodings = {
        off["encoding"]
        for b in v.evidence["breakdown"]
        for off in b["first_offsets"]
    }
    assert encodings == {"utf16le"}


def test_no_metadata_leaked_handles_missing_file(tmp_path):
    sc = _minimal_sidecar()
    v = NoProtectorMetadataLeakedInvariant().evaluate(
        InvariantContext(
            events=[], sidecar=sc,
            binary_path=tmp_path / "does_not_exist.exe",
        )
    )
    assert v.status is VerdictStatus.FAIL
    assert "could not read" in v.message


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def test_aggregator_on_fixture_passes_both(traced_fixture, repo_root):
    session = Session(workspace_root=repo_root)
    tool = VerifyProtectionInvariantsTool()
    args = VerifyInvariantsInput(
        binary_path=str(traced_fixture.binary),
        timeout_s=20.0,
    )
    out = asyncio.run(tool.run(args, session))
    assert isinstance(out, VerifyInvariantsOutput)
    assert out.overall_status == "pass", out.model_dump()
    statuses = {r.name: r.status for r in out.invariants}
    assert statuses["packer_decrypted"] == "pass"
    assert statuses["oep_is_stub"] == "pass"


def test_aggregator_only_filter_skips_frida_for_static_only(traced_fixture, repo_root):
    session = Session(workspace_root=repo_root)
    tool = VerifyProtectionInvariantsTool()
    args = VerifyInvariantsInput(
        binary_path=str(traced_fixture.binary),
        only=["oep_is_stub"],
    )
    out = asyncio.run(tool.run(args, session))
    # oep_is_stub has probes=[], so the tool must not spawn Frida.
    assert out.ran_under_frida is False
    assert out.enabled_probes == []
    assert len(out.invariants) == 1
    assert out.invariants[0].name == "oep_is_stub"
    assert out.invariants[0].status == "pass"


def test_aggregator_rejects_unknown_invariant(traced_fixture, repo_root):
    session = Session(workspace_root=repo_root)
    tool = VerifyProtectionInvariantsTool()
    args = VerifyInvariantsInput(
        binary_path=str(traced_fixture.binary),
        only=["nope_does_not_exist"],
    )
    with pytest.raises(ValueError, match="unknown invariant"):
        asyncio.run(tool.run(args, session))
