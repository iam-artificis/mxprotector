"""Unit tests for unpacking.pe_sieve.process_controller.

Exercises the real subprocess plumbing against Python itself as the
target child. Each test uses ``sys.executable`` + a ``-c`` snippet so
the tests run identically on every host that has Python installed.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from mx_mcp.unpacking.pe_sieve.process_controller import (
    LaunchedProcess,
    ProcessLaunchError,
    is_alive,
    launch_process,
    poll_exit_code,
    terminate_process,
)


# ============================================================================
# Helpers
# ============================================================================


def _python(code: str, workdir: Path) -> LaunchedProcess:
    """Launch ``sys.executable -c <code>`` under the controller."""
    # Use ``launch_process`` indirectly: it expects a single binary
    # path + args list, which mirrors how we launch a protected PE
    # in production. Python-as-target keeps the test hermetic.
    return launch_process(
        Path(sys.executable),
        workdir,
        args=["-c", code],
        no_window=False,  # quieter in CI; the child is a python, not a PE
    )


# ============================================================================
# launch + liveness
# ============================================================================


def test_launch_short_lived_child_exits_quickly(tmp_path: Path):
    proc = _python("pass", tmp_path)
    try:
        exit_code = proc.popen.wait(timeout=5.0)
        assert exit_code == 0
        assert is_alive(proc) is False
        assert poll_exit_code(proc) == 0
    finally:
        terminate_process(proc)


def test_launch_long_running_child_reports_alive(tmp_path: Path):
    proc = _python("import time; time.sleep(10)", tmp_path)
    try:
        # Give the interpreter a moment to actually start. ``is_alive``
        # reads Popen.poll() which only reflects an actual exit.
        time.sleep(0.3)
        assert is_alive(proc) is True
        assert poll_exit_code(proc) is None
    finally:
        terminate_process(proc, grace_s=1.0)


def test_launch_creates_capture_files(tmp_path: Path):
    proc = _python(
        "import sys; print('hi'); print('err', file=sys.stderr)",
        tmp_path,
    )
    try:
        proc.popen.wait(timeout=5.0)
    finally:
        terminate_process(proc)

    assert proc.stdout_path.exists()
    assert proc.stderr_path.exists()
    assert b"hi" in proc.stdout_path.read_bytes()
    assert b"err" in proc.stderr_path.read_bytes()


def test_launch_target_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="launch target"):
        launch_process(tmp_path / "no_such.exe", tmp_path)


def test_launch_invalid_target_raises_launch_error(tmp_path: Path):
    """A file that exists but is not an executable raises
    ProcessLaunchError (OS refuses to start it)."""
    bogus = tmp_path / "not_executable.txt"
    bogus.write_text("text, not a program", encoding="utf-8")
    # On both Windows and POSIX ``subprocess`` will refuse this with
    # either OSError or ``PermissionError`` — both classified as
    # ProcessLaunchError by the wrapper.
    with pytest.raises((ProcessLaunchError, OSError)):
        launch_process(bogus, tmp_path)


# ============================================================================
# terminate — graceful + kill-escalation
# ============================================================================


def test_terminate_already_dead_child_is_idempotent(tmp_path: Path):
    proc = _python("pass", tmp_path)
    proc.popen.wait(timeout=5.0)
    # First call succeeds normally, second is a no-op (poll already
    # returns an exit code); neither raises.
    assert terminate_process(proc) == 0
    assert terminate_process(proc) == 0


def test_terminate_stops_long_running_child(tmp_path: Path):
    """Typical packer-benchmark shape — launch something that sleeps,
    scan it, terminate it. The terminate call must return cleanly."""
    proc = _python("import time; time.sleep(30)", tmp_path)
    try:
        time.sleep(0.3)
        assert is_alive(proc) is True
    finally:
        code = terminate_process(proc, grace_s=1.0)
    # Non-zero is fine — we killed it, the exact code is OS-specific.
    assert code is not None
    assert is_alive(proc) is False


def test_terminate_escalates_when_child_ignores_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """When ``grace_s`` elapses without exit, ``terminate_process``
    escalates to ``Popen.kill``. We verify the escalation path fires
    by patching ``terminate`` to a no-op so only ``kill`` can end
    the child."""
    proc = _python("import time; time.sleep(30)", tmp_path)
    time.sleep(0.3)
    assert is_alive(proc) is True

    original_terminate = proc.popen.terminate
    called = {"terminate": 0, "kill": 0}

    def fake_terminate():
        called["terminate"] += 1
        # deliberately do nothing

    original_kill = proc.popen.kill

    def tracking_kill():
        called["kill"] += 1
        original_kill()

    monkeypatch.setattr(proc.popen, "terminate", fake_terminate)
    monkeypatch.setattr(proc.popen, "kill", tracking_kill)

    exit_code = terminate_process(proc, grace_s=0.2)

    assert called["terminate"] == 1
    assert called["kill"] == 1
    assert exit_code is not None
    assert is_alive(proc) is False

    # Restore to avoid surprises on session teardown.
    monkeypatch.setattr(proc.popen, "terminate", original_terminate)
