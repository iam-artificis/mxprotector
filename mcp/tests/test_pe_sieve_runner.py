"""Unit tests for unpacking.pe_sieve.runner.

Every external surface is mocked so tests are hermetic:

* ``launch_process`` / ``terminate_process`` / ``is_alive`` — patched
  at the runner module so we simulate a live/dead child without
  spawning real subprocesses.
* ``_run_subprocess`` — patched for the pe-sieve invocation itself,
  lets us inject success / non-zero exit / timeout / bad JSON.
* ``resolve_pesieve_path`` — patched separately for path-resolution
  tests (or let fire for the happy-path suite by setting
  ``MX_MCP_PESIEVE_PATH``).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from mx_mcp.unpacking.pe_sieve import runner as runner_mod
from mx_mcp.unpacking.pe_sieve.runner import (
    PESIEVE_PATH_ENV,
    PesieveNotFoundError,
    PesieveRunResult,
    resolve_pesieve_path,
    run_pesieve,
)


# ============================================================================
# Path resolution
# ============================================================================


def test_resolve_uses_explicit_override(tmp_path: Path):
    fake_exe = tmp_path / "pe-sieve64.exe"
    fake_exe.write_bytes(b"\x4d\x5a")
    assert resolve_pesieve_path(fake_exe) == fake_exe


def test_resolve_env_var_pointing_at_exe(tmp_path: Path, monkeypatch):
    fake_exe = tmp_path / "pe-sieve64.exe"
    fake_exe.write_bytes(b"\x4d\x5a")
    monkeypatch.setenv(PESIEVE_PATH_ENV, str(fake_exe))
    assert resolve_pesieve_path() == fake_exe


def test_resolve_env_var_pointing_at_directory(tmp_path: Path, monkeypatch):
    """Env may point at either the exe or its folder."""
    (tmp_path / "pe-sieve64.exe").write_bytes(b"\x4d\x5a")
    monkeypatch.setenv(PESIEVE_PATH_ENV, str(tmp_path))
    assert resolve_pesieve_path() == tmp_path / "pe-sieve64.exe"


def test_resolve_missing_raises(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(PESIEVE_PATH_ENV, raising=False)
    monkeypatch.setattr(runner_mod.shutil, "which", lambda _n: None)
    with pytest.raises(PesieveNotFoundError):
        resolve_pesieve_path()


def test_resolve_env_var_to_nonexistent_exe(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(PESIEVE_PATH_ENV, str(tmp_path / "nope.exe"))
    with pytest.raises(PesieveNotFoundError, match="not found at"):
        resolve_pesieve_path()


# ============================================================================
# Helpers for the scan tests
# ============================================================================


def _ok_report_stdout(pid: int = 1234, implanted_pe: int = 0, dumped: int = 0) -> str:
    return json.dumps({
        "scan_report": {
            "pid": pid,
            "main_image_path": "C:\\t.exe",
            "scanned": {
                "total": 10, "skipped": 0,
                "modified": {
                    "total": 1 if implanted_pe or dumped else 0,
                    "implanted_pe": implanted_pe,
                },
                "errors": 0,
            },
        },
        "dump_report": {
            "pid": pid,
            "output_dir": f"process_{pid}",
            "dumped": {"total": dumped, "dumped": dumped},
            "dumps": [],
        },
    })


def _ok_proc(stdout: str = "", stderr: str = "", rc: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout=stdout, stderr=stderr,
    )


def _install_launch_mock(
    monkeypatch,
    *,
    alive: bool = True,
    poll_exit: int | None = None,
    pid: int = 1234,
    stdout_tail: str = "",
    stderr_tail: str = "",
) -> list[SimpleNamespace]:
    """Install fakes for launch_process + is_alive + terminate_process.

    Returns the call-capture list (one per launch).
    """
    calls: list[SimpleNamespace] = []

    def fake_launch(binary, workdir, **kwargs):
        child = SimpleNamespace(
            pid=pid,
            popen=SimpleNamespace(poll=lambda: poll_exit),
            stdout_path=workdir / "child_stdout.txt",
            stderr_path=workdir / "child_stderr.txt",
        )
        # Seed the tail files for the "exited before scan" formatter.
        child.stdout_path.write_text(stdout_tail, encoding="utf-8")
        child.stderr_path.write_text(stderr_tail, encoding="utf-8")
        calls.append(SimpleNamespace(binary=binary, workdir=workdir, handle=child))
        return child

    monkeypatch.setattr(runner_mod, "launch_process", fake_launch)
    monkeypatch.setattr(runner_mod, "is_alive", lambda child: alive)
    monkeypatch.setattr(runner_mod, "terminate_process", lambda *a, **kw: 0)
    return calls


def _install_pesieve_path(monkeypatch, tmp_path: Path) -> Path:
    exe = tmp_path / "pe-sieve64.exe"
    exe.write_bytes(b"\x4d\x5a")
    monkeypatch.setenv(PESIEVE_PATH_ENV, str(exe))
    return exe


# ============================================================================
# Happy path
# ============================================================================


def test_run_pesieve_happy_path(tmp_path: Path, monkeypatch):
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True, pid=1234)

    captured_cmd: list[list[str]] = []

    def fake_run(cmd, timeout_s, cwd):
        captured_cmd.append(cmd)
        return _ok_proc(stdout=_ok_report_stdout(pid=1234, implanted_pe=1, dumped=2))

    monkeypatch.setattr(runner_mod, "_run_subprocess", fake_run)

    # Pre-seed a fake dump directory so _collect_dump_files finds PE files.
    dump_dir = tmp_path / "work" / "process_1234"
    dump_dir.mkdir(parents=True)
    (dump_dir / "a.exe").write_bytes(b"MZ")
    (dump_dir / "b.dll").write_bytes(b"MZ")
    (dump_dir / "scan_report.json").write_text("{}", encoding="utf-8")  # ignored

    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")

    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work",
        decrypt_wait_ms=1,  # keep the test fast
    ))

    assert isinstance(result, PesieveRunResult)
    assert result.ok is True
    assert result.report is not None
    assert result.report.pid == 1234
    assert result.report.dumped_count == 2
    # Dump file collection finds .exe / .dll, ignores JSON.
    assert {p.name for p in result.dump_files} == {"a.exe", "b.dll"}

    # Command line shape.
    assert len(captured_cmd) == 1
    cmd = captured_cmd[0]
    assert "/pid" in cmd and "1234" in cmd
    assert "/json" in cmd
    assert "/quiet" in cmd


# ============================================================================
# Error paths — every failure mode lands as ok=False with an error
# ============================================================================


def test_run_pesieve_missing_exe_soft_fails(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(PESIEVE_PATH_ENV, raising=False)
    monkeypatch.setattr(runner_mod.shutil, "which", lambda _n: None)

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))
    assert result.ok is False
    assert "pe-sieve not found" in (result.error or "")
    assert result.report is None


def test_run_pesieve_child_exits_before_scan(tmp_path: Path, monkeypatch):
    """Common failure: the protected binary exits (normally or via
    anti-debug) before the decrypt wait elapses → scan cannot run."""
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(
        monkeypatch, alive=False, poll_exit=0,
        stdout_tail="child printed this",
    )

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))

    assert result.ok is False
    assert "exited before scan" in (result.error or "")
    assert "child printed this" in (result.error or "")
    assert result.report is None


def test_run_pesieve_nonzero_hard_error_exit(tmp_path: Path, monkeypatch):
    """Exit codes > 2 (or negative) indicate a real scan failure — bad
    PID, missing privileges, internal crash. The runner reports them
    as failure and includes the stderr tail for diagnostics."""
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True)
    monkeypatch.setattr(
        runner_mod, "_run_subprocess",
        lambda cmd, t, cwd: _ok_proc(rc=5, stdout="", stderr="boom"),
    )

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))

    assert result.ok is False
    assert "exit=5" in (result.error or "")
    assert "boom" in result.stderr_tail


def test_run_pesieve_exit_2_is_findings_not_failure(tmp_path: Path, monkeypatch):
    """pe-sieve returns exit=2 when it detected suspicious
    modifications and produced a dump — that is *signal*, not error.
    The runner must parse the report and report ok=True."""
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True, pid=1234)
    monkeypatch.setattr(
        runner_mod, "_run_subprocess",
        lambda cmd, t, cwd: _ok_proc(
            rc=2, stdout=_ok_report_stdout(pid=1234, dumped=1),
        ),
    )
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "process_1234").mkdir()

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))

    assert result.ok is True
    assert result.report is not None
    assert result.report.dumped_count == 1


def test_run_pesieve_exit_1_also_parses_report(tmp_path: Path, monkeypatch):
    """Exit=1 (info-level findings) — also treated as success."""
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True, pid=1234)
    monkeypatch.setattr(
        runner_mod, "_run_subprocess",
        lambda cmd, t, cwd: _ok_proc(rc=1, stdout=_ok_report_stdout(pid=1234)),
    )
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "process_1234").mkdir()

    result = asyncio.run(run_pesieve(
        binary=tmp_path / "t.exe", workdir=tmp_path / "work",
        decrypt_wait_ms=1,
    ))
    assert result.ok is True


def test_run_pesieve_timeout(tmp_path: Path, monkeypatch):
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True)

    def raise_timeout(cmd, t, cwd):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=t)

    monkeypatch.setattr(runner_mod, "_run_subprocess", raise_timeout)

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work",
        decrypt_wait_ms=1, scan_timeout_s=0.1,
    ))

    assert result.ok is False
    assert "timed out" in (result.error or "")


def test_run_pesieve_bad_json_falls_back_to_report_file(
    tmp_path: Path, monkeypatch,
):
    """When stdout JSON is unparseable, the runner looks at
    ``<workdir>/process_<pid>/scan_report.json`` as the canonical
    source."""
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True, pid=99)

    monkeypatch.setattr(
        runner_mod, "_run_subprocess",
        lambda c, t, cwd: _ok_proc(stdout="<not json>", stderr=""),
    )
    # Write a valid report file where the runner will look.
    (tmp_path / "work" / "process_99").mkdir(parents=True)
    (tmp_path / "work" / "process_99" / "scan_report.json").write_text(
        _ok_report_stdout(pid=99), encoding="utf-8",
    )

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    result = asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))

    assert result.ok is True
    assert result.report is not None
    assert result.report.pid == 99


def test_run_pesieve_no_json_anywhere(tmp_path: Path, monkeypatch):
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True, pid=7)

    monkeypatch.setattr(
        runner_mod, "_run_subprocess",
        lambda c, t, cwd: _ok_proc(stdout="", stderr=""),
    )
    # No scan_report.json file either.
    result = asyncio.run(run_pesieve(
        binary=tmp_path / "t.exe",
        workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))

    assert result.ok is False
    assert "no parseable JSON" in (result.error or "")


def test_run_pesieve_child_launch_failure(tmp_path: Path, monkeypatch):
    _install_pesieve_path(monkeypatch, tmp_path)

    def failing_launch(binary, workdir, **kwargs):
        raise FileNotFoundError(f"launch target not found: {binary}")

    monkeypatch.setattr(runner_mod, "launch_process", failing_launch)
    monkeypatch.setattr(runner_mod, "terminate_process", lambda *a, **kw: 0)

    result = asyncio.run(run_pesieve(
        binary=tmp_path / "gone.exe",
        workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))
    assert result.ok is False
    assert "child launch" in (result.error or "")


# ============================================================================
# Termination discipline
# ============================================================================


def test_run_pesieve_terminates_child_on_scan_failure(
    tmp_path: Path, monkeypatch,
):
    """Even when pe-sieve exits with a hard error, the child must still
    be killed — otherwise benchmark runs leak processes."""
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True)

    terminate_calls: list[int] = []
    monkeypatch.setattr(
        runner_mod, "terminate_process",
        lambda child, *a, **kw: terminate_calls.append(child.pid) or 0,
    )
    monkeypatch.setattr(
        runner_mod, "_run_subprocess",
        lambda c, t, cwd: _ok_proc(rc=5, stderr="err"),
    )

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work", decrypt_wait_ms=1,
    ))

    assert len(terminate_calls) == 1


def test_run_pesieve_terminates_child_on_timeout(
    tmp_path: Path, monkeypatch,
):
    _install_pesieve_path(monkeypatch, tmp_path)
    _install_launch_mock(monkeypatch, alive=True)

    terminate_calls: list[int] = []
    monkeypatch.setattr(
        runner_mod, "terminate_process",
        lambda child, *a, **kw: terminate_calls.append(child.pid) or 0,
    )

    def raise_timeout(c, t, cwd):
        raise subprocess.TimeoutExpired(cmd=c, timeout=t)

    monkeypatch.setattr(runner_mod, "_run_subprocess", raise_timeout)

    binary = tmp_path / "t.exe"
    binary.write_bytes(b"MZ")
    asyncio.run(run_pesieve(
        binary=binary, workdir=tmp_path / "work",
        decrypt_wait_ms=1, scan_timeout_s=0.1,
    ))
    assert len(terminate_calls) == 1
