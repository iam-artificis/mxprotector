"""End-to-end checks that passes actually populate TraceHints.

These are pytest integration tests: build the fixture at strong level
with ``--trace-hints``, load the sidecar via the pydantic schema,
assert that CFF + VM slots were populated by their respective passes.

The tests are flag-aware: for --no-cfg-flattening / --no-vm builds
the corresponding slot must stay empty (leak-guard).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mx_tracing.sidecar import load_sidecar


def _build(
    builder_exe: Path,
    input_pe: Path,
    output: Path,
    *,
    level: str,
    extra: list[str] | None = None,
) -> None:
    cmd = [
        str(builder_exe),
        "-i", str(input_pe),
        "-o", str(output),
        "-l", level,
        "--trace-hints",
    ]
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 0, (
        f"builder failed ({proc.returncode}):\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    sidecar = Path(f"{output}.mxtrace.json")
    assert sidecar.exists(), (
        f"sidecar not produced; stdout:\n{proc.stdout}"
    )


def test_cff_states_populated_at_strong(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    output = tmp_path / "cff.exe"
    _build(builder_exe, input_pe, output, level="strong")
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))

    # strong → CFF enabled → at least one trampolined function with
    # placements. dispatcher_rva must sit inside the cff section.
    assert doc.cff.dispatcher_rva > 0, "cff dispatcher_rva not set"
    assert len(doc.cff.states) > 0, "cff.states still empty"

    # Every state must have dispatcher_entry_rva within the cff section
    # range (section start + size, exclusive).
    cff_section = doc.sections.get("cff")
    assert cff_section is not None
    start = cff_section.rva
    end = cff_section.rva + cff_section.size
    for st in doc.cff.states:
        assert start <= st.dispatcher_entry_rva < end, (
            f"state {st.id} dispatcher_entry_rva {st.dispatcher_entry_rva:#x} "
            f"outside cff section [{start:#x}..{end:#x})"
        )

    # At least one original-kind state is expected (real basic blocks
    # must have been flattened; a fixture of pure bogus is pathological).
    kinds = {st.kind for st in doc.cff.states}
    assert "original" in kinds, f"no original states, only kinds={kinds}"


def test_vm_handlers_populated_at_strong(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    output = tmp_path / "vm.exe"
    _build(builder_exe, input_pe, output, level="strong")
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))

    assert doc.vm.dispatcher_rva > 0, "vm dispatcher_rva not set"
    assert len(doc.vm.handlers) > 0, "vm.handlers still empty"

    # Each handler's RVA must lie inside the VM section.
    vm_section = doc.sections.get("vm")
    assert vm_section is not None
    start = vm_section.rva
    end = vm_section.rva + vm_section.size
    for h in doc.vm.handlers:
        assert start <= h.rva < end, (
            f"handler {h.id} rva {h.rva:#x} outside vm section "
            f"[{start:#x}..{end:#x})"
        )
        assert h.size > 0
        # Phase 4B uses "region_{N}" labels — schema allows any string;
        # the label just needs to be non-empty.
        assert h.opcode.strip() != ""


def test_cff_slot_empty_when_flattening_off(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    output = tmp_path / "no_cff.exe"
    _build(
        builder_exe, input_pe, output,
        level="strong",
        extra=["--no-cfg-flattening"],
    )
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    assert doc.cff.dispatcher_rva == 0, "CFF dispatcher leaked with --no-cfg-flattening"
    assert doc.cff.states == [], "CFF states leaked with --no-cfg-flattening"


def test_vm_slot_empty_when_vm_off(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    output = tmp_path / "no_vm.exe"
    _build(
        builder_exe, input_pe, output,
        level="strong",
        extra=["--no-vm"],
    )
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    assert doc.vm.dispatcher_rva == 0, "VM dispatcher leaked with --no-vm"
    assert doc.vm.handlers == [], "VM handlers leaked with --no-vm"


@pytest.mark.parametrize("flag", ["--no-cfg-flattening", "--no-vm"])
def test_full_build_still_succeeds_with_sidecar_flag(
    flag: str,
    tmp_path: Path,
    builder_exe: Path,
    input_pe: Path,
) -> None:
    """Guard against regressions where --trace-hints + a disable flag
    trigger an uncaught path (e.g. set_cff_dispatcher called even when
    no trampolines were created)."""
    output = tmp_path / f"combo{flag.replace('-', '_')}.exe"
    _build(builder_exe, input_pe, output, level="strong", extra=[flag])
    # Just ensure the sidecar parses and is well-formed.
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    assert doc.schema_version == 1


# ===========================================================================
# Phase 4C — Guard / Strings / IAT
# ===========================================================================


def test_iat_populated_at_strong(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    """test_vm_showcase is MSVC-built → DataDirectory[IAT] is populated."""
    output = tmp_path / "iat.exe"
    _build(builder_exe, input_pe, output, level="strong")
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    assert doc.iat.rva > 0,  "IAT rva not populated from DataDirectory"
    assert doc.iat.size > 0, "IAT size not populated from DataDirectory"


def test_strings_slots_populated_when_strings_enabled(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    """test_vm_showcase has no MX_STR candidates — but the string pass
    can still pick up regular string literals in `printf` format args.
    We only assert slot count is non-negative + the field exists; the
    stronger check is that set_iat on a non-string fixture still gives
    empty slots (leak-guard below)."""
    output = tmp_path / "str.exe"
    _build(builder_exe, input_pe, output, level="strong",
           extra=["--strings=stub"])
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    # strings=stub + this fixture — slots may be 0 or more; the
    # contract is "field exists and parses". Empty is valid.
    assert isinstance(doc.strings.slots, list)


def test_strings_slot_empty_when_strings_off(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    output = tmp_path / "no_str.exe"
    _build(builder_exe, input_pe, output, level="strong",
           extra=["--strings=off"])
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    assert doc.strings.slots == [], (
        f"strings leaked with --strings=off: {doc.strings.slots}"
    )


def test_guard_slot_empty_without_markers(
    tmp_path: Path, builder_exe: Path, input_pe: Path
) -> None:
    """test_vm_showcase has no MX_GUARD markers — guard.regions must
    stay empty."""
    output = tmp_path / "no_guard.exe"
    _build(builder_exe, input_pe, output, level="strong")
    doc = load_sidecar(Path(f"{output}.mxtrace.json"))
    assert doc.guard.regions == [], (
        f"guard regions leaked: {doc.guard.regions}"
    )
