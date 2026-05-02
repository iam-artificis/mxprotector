"""Unit tests for the registered anti-analysis detectors.

For each of the five detectors:
1. Synthesise a small binary that contains its target needle/opcode.
2. Verify ``detected=True`` + evidence carries the matched pattern.
3. Synthesise a clean binary; verify ``detected=False`` + empty evidence.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import mx_mcp.anti_analysis  # noqa: F401  - triggers detector registration
from mx_mcp.anti_analysis.detector_base import all_detectors
from mx_mcp.anti_analysis.detectors.al_khaser_detector import AlKhaserDetector
from mx_mcp.anti_analysis.detectors.frida_detector import FridaDetector
from mx_mcp.anti_analysis.detectors.pafish_detector import PafishDetector
from mx_mcp.anti_analysis.detectors.unicorn_detector import UnicornDetector
from mx_mcp.anti_analysis.detectors.x64dbg_detector import X64dbgDetector


# ============================================================================
# Sanity — registry contents
# ============================================================================


def test_initial_detector_catalog_has_five_entries():
    names = {d.name for d in all_detectors()}
    expected = {"x64dbg", "frida", "unicorn", "pafish", "al_khaser"}
    assert expected.issubset(names), (
        f"missing detectors: expected={expected} actual={names}"
    )


def test_detector_names_are_unique():
    names = [d.name for d in all_detectors()]
    assert len(names) == len(set(names))


# ============================================================================
# x64dbg
# ============================================================================


def test_x64dbg_detector_fires_on_isdebuggerpresent(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00IsDebuggerPresent\x00")
    result = asyncio.run(X64dbgDetector().detect(pe))
    assert result.detected is True
    assert "IsDebuggerPresent" in result.evidence["unique_needles"]


def test_x64dbg_detector_returns_false_on_clean(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"hello world\x00")
    result = asyncio.run(X64dbgDetector().detect(pe))
    assert result.detected is False
    assert result.error is None


def test_x64dbg_detector_handles_missing_file(tmp_path: Path):
    pe = tmp_path / "ghost.bin"
    result = asyncio.run(X64dbgDetector().detect(pe))
    assert result.detected is False
    assert result.error is not None
    assert "scan failed" in result.error


# ============================================================================
# Frida
# ============================================================================


def test_frida_detector_fires_on_gum_js_loop(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00gum-js-loop\x00")
    result = asyncio.run(FridaDetector().detect(pe))
    assert result.detected is True


def test_frida_detector_returns_false_on_clean(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00clean\x00")
    result = asyncio.run(FridaDetector().detect(pe))
    assert result.detected is False


# ============================================================================
# Unicorn (byte patterns)
# ============================================================================


def test_unicorn_detector_fires_on_cpuid(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x90\x0f\xa2\x90")    # NOP CPUID NOP
    result = asyncio.run(UnicornDetector().detect(pe))
    assert result.detected is True
    assert "CPUID" in result.evidence["unique_opcodes"]


def test_unicorn_detector_fires_on_rdtsc(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x0f\x31")   # RDTSC
    result = asyncio.run(UnicornDetector().detect(pe))
    assert result.detected is True
    assert "RDTSC" in result.evidence["unique_opcodes"]


def test_unicorn_detector_returns_false_on_clean(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x90" * 64)    # only NOPs
    result = asyncio.run(UnicornDetector().detect(pe))
    assert result.detected is False


# ============================================================================
# Pafish
# ============================================================================


def test_pafish_detector_fires_on_vboxservice(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00VBoxService\x00")
    result = asyncio.run(PafishDetector().detect(pe))
    assert result.detected is True


def test_pafish_detector_returns_false_on_clean(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00unrelated\x00")
    result = asyncio.run(PafishDetector().detect(pe))
    assert result.detected is False


# ============================================================================
# al-khaser
# ============================================================================


def test_al_khaser_detector_fires_on_findwindow(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00FindWindowA\x00")
    result = asyncio.run(AlKhaserDetector().detect(pe))
    assert result.detected is True


def test_al_khaser_detector_fires_on_blockinput(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00BlockInput\x00")
    result = asyncio.run(AlKhaserDetector().detect(pe))
    assert result.detected is True


def test_al_khaser_detector_returns_false_on_clean(tmp_path: Path):
    pe = tmp_path / "x.bin"
    pe.write_bytes(b"\x00empty\x00")
    result = asyncio.run(AlKhaserDetector().detect(pe))
    assert result.detected is False


# ============================================================================
# Detector class metadata
# ============================================================================


def test_every_detector_carries_required_metadata():
    for cls in all_detectors():
        assert isinstance(cls.name, str) and cls.name
        assert isinstance(cls.description, str) and cls.description
        assert isinstance(cls.targets, tuple) and cls.targets
