"""Unit tests for static.ida.runner.

All subprocess interaction is mocked via monkeypatch on the
``_run_subprocess`` seam. The fake ``_run_subprocess`` also writes
the expected output JSON so the runner's post-processing code path
gets exercised.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mx_mcp.static.ida import runner as runner_mod
from mx_mcp.static.ida.runner import (
    IDA_OUTPUT_ENV,
    IDA_PATH_ENV,
    IdaNotFoundError,
    IdaRunResult,
    resolve_ida_path,
    run_ida_script,
)


# ============================================================================
# resolve_ida_path — precedence order
# ============================================================================


def test_resolve_override_wins(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(IDA_PATH_ENV, str(tmp_path / "ENV_IDA.exe"))
    override = tmp_path / "OVERRIDE_IDA.exe"
    assert resolve_ida_path(override) == override


def test_resolve_env_directory_appends_driver(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(IDA_PATH_ENV, str(tmp_path))  # a directory
    assert resolve_ida_path() == tmp_path / "idat64.exe"


def test_resolve_env_file_used_verbatim(tmp_path: Path, monkeypatch):
    exe = tmp_path / "something.exe"
    exe.write_bytes(b"")
    monkeypatch.setenv(IDA_PATH_ENV, str(exe))
    assert resolve_ida_path() == exe


def test_resolve_path_lookup(monkeypatch):
    monkeypatch.delenv(IDA_PATH_ENV, raising=False)
    calls: list[str] = []

    def fake_which(name: str) -> str | None:
        calls.append(name)
        if name == "idat64.exe":
            return None
        if name == "idat.exe":
            return "/usr/local/bin/idat"
        return None

    monkeypatch.setattr(runner_mod.shutil, "which", fake_which)
    resolved = resolve_ida_path()
    # Path normalises separators per-platform; compare via Path, not str.
    assert resolved == Path("/usr/local/bin/idat")
    assert calls == ["idat64.exe", "idat.exe"]


def test_resolve_fallback_when_no_which(monkeypatch):
    monkeypatch.delenv(IDA_PATH_ENV, raising=False)
    monkeypatch.setattr(runner_mod.shutil, "which", lambda name: None)
    assert resolve_ida_path() == Path("idat64.exe")


# ============================================================================
# run_ida_script — mock fixture helpers
# ============================================================================


def _touch(path: Path, content: bytes = b"\x4d\x5a") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _install_fake_run(
    monkeypatch,
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    output_payload: dict[str, Any] | None | str = None,
    raise_timeout: bool = False,
) -> list[dict[str, Any]]:
    """Install a fake ``_run_subprocess`` capturing invocations.

    ``output_payload``:
        * dict — valid JSON written to the IDA output file.
        * str  — written raw (useful to test malformed JSON).
        * None — output file NOT written.
    """
    captured: list[dict[str, Any]] = []

    def fake(cmd: list[str], timeout_s: float, cwd: str, env: dict[str, str]):
        captured.append({"cmd": list(cmd), "cwd": cwd, "env": dict(env), "timeout": timeout_s})
        if raise_timeout:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout_s)
        if output_payload is not None:
            out_path = Path(env[IDA_OUTPUT_ENV])
            if isinstance(output_payload, dict):
                out_path.write_text(json.dumps(output_payload), encoding="utf-8")
            else:
                out_path.write_text(output_payload, encoding="utf-8")
        return subprocess.CompletedProcess(
            args=cmd, returncode=returncode, stdout=stdout, stderr=stderr,
        )

    monkeypatch.setattr(runner_mod, "_run_subprocess", fake)
    return captured


def _fixture_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    ida = _touch(tmp_path / "idat64.exe")
    script = _touch(tmp_path / "script.py")
    binary = _touch(tmp_path / "sample.exe")
    return ida, script, binary


# ============================================================================
# Missing inputs
# ============================================================================


def test_missing_binary_raises_filenotfound(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="input binary not found"):
        asyncio.run(run_ida_script(
            binary=tmp_path / "no.exe",
            script=tmp_path / "script.py",
            ida_path=tmp_path / "idat64.exe",
        ))


def test_missing_ida_raises_idanotfound(tmp_path: Path):
    binary = _touch(tmp_path / "sample.exe")
    with pytest.raises(IdaNotFoundError, match="IDA driver not found"):
        asyncio.run(run_ida_script(
            binary=binary,
            script=tmp_path / "script.py",
            ida_path=tmp_path / "no_ida.exe",
        ))


def test_missing_script_raises_filenotfound(tmp_path: Path):
    ida = _touch(tmp_path / "idat64.exe")
    binary = _touch(tmp_path / "sample.exe")
    with pytest.raises(FileNotFoundError, match="IDAPython script not found"):
        asyncio.run(run_ida_script(
            binary=binary,
            script=tmp_path / "no_script.py",
            ida_path=ida,
        ))


# ============================================================================
# Invocation shape + output reading
# ============================================================================


def test_happy_path_parses_output(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    payload = {"schema_version": 1, "functions": [{"ea": 0x1000, "mc_blocks": 3}]}
    captured = _install_fake_run(monkeypatch, output_payload=payload, stdout="IDA hi")

    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida,
    ))

    assert isinstance(result, IdaRunResult)
    assert result.ok is True
    assert result.output == payload
    assert result.error is None
    assert result.stdout_tail == "IDA hi"

    # Command shape.
    cmd = captured[0]["cmd"]
    assert cmd[0] == str(ida)
    assert "-A" in cmd
    assert any(c.startswith("-S") and str(script) in c for c in cmd)
    # Binary path passed is the *copy* inside the workdir, not the original.
    assert cmd[-1].endswith(binary.name)
    assert cmd[-1] != str(binary)

    # Env propagation.
    env = captured[0]["env"]
    assert IDA_OUTPUT_ENV in env
    assert env[IDA_OUTPUT_ENV].endswith("mx_mcp_ida_output.json")


def test_extra_env_merged(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    captured = _install_fake_run(monkeypatch, output_payload={"schema_version": 1})
    asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida,
        extra_env={"MX_CFF_MODE": "strict"},
    ))
    assert captured[0]["env"]["MX_CFF_MODE"] == "strict"


# ============================================================================
# Error paths
# ============================================================================


def test_nonzero_returncode_reports_error(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    _install_fake_run(
        monkeypatch, returncode=7, output_payload={"schema_version": 1},
    )
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida,
    ))
    assert result.ok is False
    assert result.error is not None and "exit=7" in result.error


def test_missing_output_reports_error(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    _install_fake_run(monkeypatch, output_payload=None)  # no output file
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida,
    ))
    assert result.ok is False
    assert result.output is None
    assert "no output JSON" in (result.error or "")


def test_malformed_output_reports_error(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    _install_fake_run(monkeypatch, output_payload="not json {")
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida,
    ))
    assert result.ok is False
    assert "output json parse" in (result.error or "")


def test_timeout_reports_error(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    _install_fake_run(monkeypatch, raise_timeout=True)
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida, timeout_s=1.0,
    ))
    assert result.ok is False
    assert "timed out" in (result.error or "")


# ============================================================================
# Workdir behaviour
# ============================================================================


def test_default_workdir_cleaned_up(tmp_path: Path, monkeypatch):
    """Owned workdir is torn down on success."""
    ida, script, binary = _fixture_paths(tmp_path)
    _install_fake_run(monkeypatch, output_payload={"schema_version": 1})
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida,
    ))
    assert result.workdir is None


def test_keep_database_retains_workdir(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    _install_fake_run(monkeypatch, output_payload={"schema_version": 1})
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida, keep_database=True,
    ))
    assert result.workdir is not None
    assert result.workdir.exists()


def test_external_workdir_not_deleted(tmp_path: Path, monkeypatch):
    ida, script, binary = _fixture_paths(tmp_path)
    wd = tmp_path / "mywork"
    _install_fake_run(monkeypatch, output_payload={"schema_version": 1})
    result = asyncio.run(run_ida_script(
        binary=binary, script=script, ida_path=ida, workdir=wd,
    ))
    # Caller-owned workdir is always retained even without keep_database.
    assert result.workdir == wd
    assert wd.exists()
