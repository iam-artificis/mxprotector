"""Unit tests for common.builder.

All subprocess interaction is mocked via ``monkeypatch`` on the
module-level ``_run_subprocess`` seam, so tests do not require an
actual builder binary or MSVC toolchain.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from mx_mcp.common import builder as builder_mod
from mx_mcp.common.builder import (
    BUILDER_PATH_ENV,
    DEFAULT_BUILDER_REL,
    BuilderError,
    ProtectedBuild,
    build_protected,
    resolve_builder_path,
)


# ============================================================================
# resolve_builder_path
# ============================================================================


def test_resolve_builder_path_default(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(BUILDER_PATH_ENV, raising=False)
    resolved = resolve_builder_path(tmp_path)
    assert resolved == tmp_path / DEFAULT_BUILDER_REL


def test_resolve_builder_path_env_override(tmp_path: Path, monkeypatch):
    override = tmp_path / "custom_builder.exe"
    monkeypatch.setenv(BUILDER_PATH_ENV, str(override))
    assert resolve_builder_path(tmp_path) == override


# ============================================================================
# Helpers for mocking
# ============================================================================


def _ok_proc(stdout: str = "ok", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=stdout, stderr=stderr,
    )


def _install_fake_runner(
    monkeypatch,
    proc: subprocess.CompletedProcess | Exception,
    *,
    produce_output: bool = True,
    output_path: Path | None = None,
    sidecar_path: Path | None = None,
) -> list[list[str]]:
    """Install a fake ``_run_subprocess`` that optionally creates the
    expected output + sidecar files (the real builder produces them as
    a side effect — the test double must too).

    Returns a list that captures the ``cmd`` of each invocation.
    """
    captured: list[list[str]] = []

    def fake(cmd: list[str], timeout_s: float, cwd: str | None):
        captured.append(list(cmd))
        if isinstance(proc, Exception):
            raise proc
        if produce_output and output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"\x4d\x5a")
        if sidecar_path is not None:
            sidecar_path.write_text('{"schema_version": 1}', encoding="utf-8")
        return proc

    monkeypatch.setattr(builder_mod, "_run_subprocess", fake)
    return captured


def _touch_builder(tmp_path: Path) -> Path:
    p = tmp_path / "mxprotector_builder.exe"
    p.write_bytes(b"\x4d\x5a")
    return p


def _touch_input(tmp_path: Path) -> Path:
    p = tmp_path / "in.exe"
    p.write_bytes(b"\x4d\x5a")
    return p


# ============================================================================
# Happy path
# ============================================================================


def test_build_protected_happy_path(tmp_path: Path, monkeypatch):
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"
    sidecar = tmp_path / "out.exe.mxtrace.json"

    captured = _install_fake_runner(
        monkeypatch, _ok_proc(), output_path=output, sidecar_path=sidecar,
    )

    result = asyncio.run(build_protected(
        unprotected=unprotected, output=output, builder_path=builder,
    ))

    assert isinstance(result, ProtectedBuild)
    assert result.protected_binary == output
    assert result.sidecar_path == sidecar
    assert result.stdout_tail == "ok"

    # Invocation shape.
    cmd = captured[0]
    assert cmd[0] == str(builder)
    assert "-i" in cmd and str(unprotected) in cmd
    assert "-o" in cmd and str(output) in cmd
    assert "-l" in cmd and "strong" in cmd
    assert "--trace-hints" in cmd


def test_build_protected_without_trace_hints(tmp_path: Path, monkeypatch):
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"

    captured = _install_fake_runner(monkeypatch, _ok_proc(), output_path=output)

    result = asyncio.run(build_protected(
        unprotected=unprotected, output=output, builder_path=builder,
        trace_hints=False,
    ))

    assert result.sidecar_path is None
    assert "--trace-hints" not in captured[0]


def test_build_protected_forwards_extra_args(tmp_path: Path, monkeypatch):
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"

    captured = _install_fake_runner(monkeypatch, _ok_proc(), output_path=output)

    asyncio.run(build_protected(
        unprotected=unprotected, output=output, builder_path=builder,
        level="maximum", extra_args=["--no-vm", "--debug-sections"],
    ))

    cmd = captured[0]
    assert "maximum" in cmd
    assert "--no-vm" in cmd
    assert "--debug-sections" in cmd


def test_build_protected_sidecar_missing_gracefully(tmp_path: Path, monkeypatch):
    """trace_hints=True but builder produced no sidecar → sidecar_path=None."""
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"

    _install_fake_runner(monkeypatch, _ok_proc(), output_path=output, sidecar_path=None)

    result = asyncio.run(build_protected(
        unprotected=unprotected, output=output, builder_path=builder,
    ))
    assert result.sidecar_path is None


# ============================================================================
# Error paths
# ============================================================================


def test_build_protected_missing_input_raises(tmp_path: Path):
    builder = _touch_builder(tmp_path)
    with pytest.raises(FileNotFoundError, match="input binary not found"):
        asyncio.run(build_protected(
            unprotected=tmp_path / "no_such.exe",
            output=tmp_path / "out.exe",
            builder_path=builder,
        ))


def test_build_protected_missing_builder_raises(tmp_path: Path):
    unprotected = _touch_input(tmp_path)
    with pytest.raises(BuilderError, match="builder not found"):
        asyncio.run(build_protected(
            unprotected=unprotected,
            output=tmp_path / "out.exe",
            builder_path=tmp_path / "no_builder.exe",
        ))


def test_build_protected_nonzero_returncode_raises(tmp_path: Path, monkeypatch):
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"

    bad_proc = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="x", stderr="boom: bad PE",
    )
    _install_fake_runner(monkeypatch, bad_proc, produce_output=False)

    with pytest.raises(BuilderError, match="exit=1"):
        asyncio.run(build_protected(
            unprotected=unprotected, output=output, builder_path=builder,
        ))


def test_build_protected_no_output_file_raises(tmp_path: Path, monkeypatch):
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"

    # Runner reports success but does not write the output.
    _install_fake_runner(monkeypatch, _ok_proc(), produce_output=False)

    with pytest.raises(BuilderError, match="output file missing"):
        asyncio.run(build_protected(
            unprotected=unprotected, output=output, builder_path=builder,
        ))


def test_build_protected_timeout_raises(tmp_path: Path, monkeypatch):
    builder = _touch_builder(tmp_path)
    unprotected = _touch_input(tmp_path)
    output = tmp_path / "out.exe"

    timeout = subprocess.TimeoutExpired(cmd=["x"], timeout=1.0)
    _install_fake_runner(monkeypatch, timeout, produce_output=False)

    with pytest.raises(BuilderError, match="timed out"):
        asyncio.run(build_protected(
            unprotected=unprotected, output=output, builder_path=builder,
            timeout_s=1.0,
        ))
