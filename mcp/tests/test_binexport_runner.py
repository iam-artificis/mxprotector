"""Unit tests for diffing.bindiff.binexport_runner.

Every external dependency (IDA subprocess) is mocked at the module
level so tests are hermetic — they run on any host regardless of
whether IDA / BinExport is installed.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from mx_mcp.diffing.bindiff import binexport_runner as br
from mx_mcp.diffing.bindiff.binexport_runner import (
    BinExportResult,
    run_binexport,
)
from mx_mcp.static.ida.runner import IdaNotFoundError


# ============================================================================
# Helpers
# ============================================================================


def _touch_binary(tmp_path: Path, name: str = "in.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(b"\x4d\x5a")
    return p


def _ok_proc(stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=stdout, stderr=stderr,
    )


def _install_ida_path(monkeypatch, tmp_path: Path) -> Path:
    """Make the IDA resolver return a fake exe at a known location."""
    fake = tmp_path / "idat64.exe"
    fake.write_bytes(b"\x4d\x5a")
    monkeypatch.setattr(br, "resolve_ida_path", lambda override=None: fake)
    return fake


def _install_subprocess(
    monkeypatch, *, proc=None, raises=None, write_output_at: Path | None = None,
    output_contents: bytes = b"BinExport protobuf stub",
) -> list[list[str]]:
    """Capture the exact argv passed to IDA.

    Optional: write a stub output file when the subprocess "runs" so
    the runner's post-invocation existence check passes. Or inject
    an exception to simulate timeout / OSError."""
    captured: list[list[str]] = []

    def fake(cmd, timeout_s, cwd):
        captured.append(list(cmd))
        if raises is not None:
            raise raises
        if write_output_at is not None:
            write_output_at.write_bytes(output_contents)
        return proc if proc is not None else _ok_proc()

    monkeypatch.setattr(br, "_run_subprocess", fake)
    return captured


# ============================================================================
# Happy path
# ============================================================================


def test_run_binexport_happy_path_produces_output(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    out = tmp_path / "pure.BinExport"
    _install_ida_path(monkeypatch, tmp_path)
    captured = _install_subprocess(
        monkeypatch,
        write_output_at=out,
    )

    result = asyncio.run(run_binexport(binary, out))

    assert isinstance(result, BinExportResult)
    assert result.ok is True
    assert result.output_path == out
    assert result.error is None

    # Command shape: idat64.exe -A -OBinExportAutoAction:BinExportBinary
    #                -OBinExportModule:<out> <binary>
    assert len(captured) == 1
    cmd = captured[0]
    assert cmd[1] == "-A"
    assert "-OBinExportAutoAction:BinExportBinary" in cmd
    assert any(c.startswith("-OBinExportModule:") and str(out) in c for c in cmd)
    assert str(binary) in cmd


# ============================================================================
# Error paths
# ============================================================================


def test_missing_input_binary_soft_fails(tmp_path: Path):
    result = asyncio.run(run_binexport(
        tmp_path / "nope.exe", tmp_path / "out.BinExport",
    ))
    assert result.ok is False
    assert "input binary missing" in (result.error or "")


def test_missing_ida_soft_fails(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    def raise_missing(override=None):
        raise IdaNotFoundError("no idat64.exe on PATH")
    monkeypatch.setattr(br, "resolve_ida_path", raise_missing)

    result = asyncio.run(run_binexport(binary, tmp_path / "out.BinExport"))
    assert result.ok is False
    assert "IDA not found" in (result.error or "")


def test_ida_driver_file_missing_soft_fails(tmp_path: Path, monkeypatch):
    """resolve_ida_path returns a path that doesn't exist on disk —
    guard catches it before we try subprocess."""
    binary = _touch_binary(tmp_path)
    ghost = tmp_path / "ghost_idat.exe"  # never created
    monkeypatch.setattr(br, "resolve_ida_path", lambda override=None: ghost)

    result = asyncio.run(run_binexport(binary, tmp_path / "out.BinExport"))
    assert result.ok is False
    assert "IDA driver missing" in (result.error or "")


def test_ida_nonzero_exit_soft_fails(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    _install_ida_path(monkeypatch, tmp_path)
    _install_subprocess(
        monkeypatch,
        proc=subprocess.CompletedProcess(
            args=[], returncode=2, stdout="x", stderr="kaput",
        ),
    )
    result = asyncio.run(run_binexport(binary, tmp_path / "out.BinExport"))
    assert result.ok is False
    assert "IDA exit=2" in (result.error or "")
    assert "kaput" in result.stderr_tail


def test_ida_timeout_soft_fails(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    _install_ida_path(monkeypatch, tmp_path)
    _install_subprocess(
        monkeypatch,
        raises=subprocess.TimeoutExpired(cmd=["ida"], timeout=1.0),
    )
    result = asyncio.run(run_binexport(
        binary, tmp_path / "out.BinExport", timeout_s=1.0,
    ))
    assert result.ok is False
    assert "timed out" in (result.error or "")


def test_ida_exits_zero_but_plugin_did_not_run(tmp_path: Path, monkeypatch):
    """IDA's exit code says nothing about whether BinExport fired.
    Absent output file is the signal we use for 'plugin missing /
    misconfigured' — surface it as a dedicated error message."""
    binary = _touch_binary(tmp_path)
    _install_ida_path(monkeypatch, tmp_path)
    _install_subprocess(monkeypatch)  # no output file written

    result = asyncio.run(run_binexport(binary, tmp_path / "out.BinExport"))
    assert result.ok is False
    assert "no output file" in (result.error or "")
    assert "plugins/" in (result.error or "")


def test_run_binexport_never_raises_on_any_failure(tmp_path: Path, monkeypatch):
    """Contract: run_binexport is fail-closed. Every inner exception
    must translate into a structured error, not propagate."""
    _install_ida_path(monkeypatch, tmp_path)
    _install_subprocess(
        monkeypatch,
        raises=OSError("random OS failure"),
    )
    binary = _touch_binary(tmp_path)
    # Must not raise.
    result = asyncio.run(run_binexport(binary, tmp_path / "out.BinExport"))
    assert result.ok is False
    assert "failed to start" in (result.error or "")
