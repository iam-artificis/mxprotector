"""Child-process lifecycle for the pe-sieve runner.

Separated from :mod:`runner` so pe-sieve knowledge stays in one place
and general subprocess plumbing (launch, liveness probe, graceful
terminate with kill-escalation) stays in another.

## Contract

All public helpers are *synchronous* — subprocess APIs are blocking
by nature and hiding that behind ``async`` would cost clarity
without a win. The runner wraps everything in ``asyncio.to_thread``
at its own layer.

## Windows-first

The protected test binaries we launch are built for Windows. On
Windows we set ``CREATE_NO_WINDOW`` so no console pops up during
benchmark runs; on non-Windows the flag is a harmless zero. Nothing
else here is platform-specific — ``Popen.terminate`` / ``kill`` map
cleanly to either signal family.

## Kill safety

:func:`terminate_process` is a strict sequence:

1. ``Popen.terminate()`` — ``TerminateProcess`` on Windows,
   ``SIGTERM`` elsewhere.
2. Grace period controlled by ``grace_s`` (default 2 s).
3. ``Popen.kill()`` if still running — ``TerminateProcess`` on
   Windows (same call; signal already equivalent to SIGKILL) /
   ``SIGKILL`` elsewhere.
4. Final short wait to reap the zombie.

Every function leaves the process in a known-dead state on return
even when called from an exception handler.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


_LOG = logging.getLogger(__name__)


# Windows-only flag; on other platforms ``subprocess`` does not
# define ``CREATE_NO_WINDOW`` so we fall back to zero (= no effect).
_CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_DEFAULT_GRACE_S: float = 2.0
_POST_KILL_WAIT_S: float = 1.0


class ProcessLaunchError(RuntimeError):
    """Raised when a child process cannot be started at all."""


@dataclass(frozen=True, slots=True)
class LaunchedProcess:
    """Opaque handle to a running child process.

    ``popen`` is retained for :func:`terminate_process` and liveness
    checks. ``stdout_path`` / ``stderr_path`` give the post-mortem a
    place to read from when the benchmark wants to diagnose a hang
    or an unexpected exit.
    """

    pid: int
    popen: subprocess.Popen
    stdout_path: Path
    stderr_path: Path


# ============================================================================
# Public helpers
# ============================================================================


def launch_process(
    binary: Path,
    workdir: Path,
    *,
    args: list[str] | None = None,
    no_window: bool = True,
) -> LaunchedProcess:
    """Launch ``binary`` as a child process; return a handle.

    stdout / stderr are tee'd to ``<workdir>/child_stdout.txt`` and
    ``child_stderr.txt``. Files are created even when the child writes
    nothing, so callers reading them back never need an exists check.

    ``no_window=True`` (Windows) suppresses a console popup — critical
    for benchmark runs that fire many short-lived protected binaries.

    Raises:
        FileNotFoundError: ``binary`` does not exist on disk.
        ProcessLaunchError: subprocess could not be started (missing
            DLL, PE format error, etc.).
    """
    if not binary.exists():
        raise FileNotFoundError(f"launch target not found: {binary}")
    workdir.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [str(binary), *(args or [])]
    stdout_path = workdir / "child_stdout.txt"
    stderr_path = workdir / "child_stderr.txt"

    flags = _CREATE_NO_WINDOW if no_window else 0

    _LOG.debug("launch %s in %s (flags=0x%X)", binary.name, workdir, flags)
    try:
        stdout_f = stdout_path.open("wb")
        stderr_f = stderr_path.open("wb")
    except OSError as e:
        raise ProcessLaunchError(
            f"failed to open stdout/stderr capture files under {workdir}: {e}"
        ) from e

    try:
        popen = subprocess.Popen(
            cmd,
            stdout=stdout_f,
            stderr=stderr_f,
            stdin=subprocess.DEVNULL,
            cwd=str(workdir),
            creationflags=flags if sys.platform.startswith("win") else 0,
            close_fds=True,
        )
    except (OSError, ValueError) as e:
        stdout_f.close()
        stderr_f.close()
        raise ProcessLaunchError(
            f"failed to launch {binary.name}: {type(e).__name__}: {e}"
        ) from e

    # ``Popen`` inherits the file descriptors; the parent handles can
    # close immediately without disturbing the child's writes.
    stdout_f.close()
    stderr_f.close()

    _LOG.info("child launched: pid=%d binary=%s", popen.pid, binary.name)
    return LaunchedProcess(
        pid=popen.pid,
        popen=popen,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def is_alive(proc: LaunchedProcess) -> bool:
    """True when the child is still running."""
    return proc.popen.poll() is None


def poll_exit_code(proc: LaunchedProcess) -> int | None:
    """Return the exit code if the child has finished, else ``None``."""
    return proc.popen.poll()


def terminate_process(
    proc: LaunchedProcess,
    *,
    grace_s: float = _DEFAULT_GRACE_S,
) -> int:
    """Terminate the child; escalate to kill if it refuses to die.

    Returns the eventual exit code (``-1`` as a sentinel if wait
    failed — shouldn't happen after a kill). Never raises for
    already-dead children; a caller can always run
    ``terminate_process`` from a ``finally`` block without guarding.
    """
    code = proc.popen.poll()
    if code is not None:
        return code

    # 1. Gentle terminate — SIGTERM on POSIX, TerminateProcess on Windows.
    try:
        proc.popen.terminate()
    except OSError as e:
        _LOG.debug("terminate(pid=%d) raised %s; escalating", proc.pid, e)

    try:
        code = proc.popen.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        code = None

    if code is not None:
        return code

    # 2. Escalate to kill — SIGKILL on POSIX; TerminateProcess-again on Windows.
    _LOG.info(
        "child pid=%d did not exit within %.1fs; escalating to kill",
        proc.pid, grace_s,
    )
    try:
        proc.popen.kill()
    except OSError as e:
        _LOG.debug("kill(pid=%d) raised %s", proc.pid, e)

    try:
        return proc.popen.wait(timeout=_POST_KILL_WAIT_S)
    except subprocess.TimeoutExpired:
        _LOG.warning(
            "child pid=%d still not reaped after kill; leaving as-is", proc.pid,
        )
        return -1
