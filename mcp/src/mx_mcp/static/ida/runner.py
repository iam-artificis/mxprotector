"""IDA headless runner — subprocess wrapper for ``idat64.exe -A -S<script>``.

## Invocation

IDA Pro 8+ ships two drivers: ``idat.exe`` (32-bit) and ``idat64.exe``
(64-bit). Since MxProtector produces x64 PEs exclusively we default
to ``idat64.exe``. Path resolution precedence:

1. ``override`` argument if supplied.
2. ``MX_MCP_IDA_PATH`` environment variable (may point to either the
   directory holding the drivers or to a specific driver file).
3. ``shutil.which("idat64.exe")`` / ``shutil.which("idat")``.
4. Literal ``"idat64.exe"`` — lets ``subprocess`` fail cleanly with a
   ``FileNotFoundError`` if nothing else resolves.

## Isolation

IDA creates a fleet of ``.i64`` / ``.id0`` / ``.id1`` / ``.nam`` / ``.til``
database files next to the input binary. To keep these out of the
corpus directory the runner copies the binary into a per-invocation
temp workdir and runs IDA there. The workdir is deleted on completion
unless ``keep_database=True`` (useful for debugging).

## Output channel

The runner exports ``MX_MCP_IDA_OUTPUT`` to the child process,
pointing to a JSON file inside the workdir. IDAPython scripts read
that env var and ``json.dump`` their result to it. After IDA exits,
the runner reads and parses the file; missing / malformed output
flips ``ok=False`` with a readable ``error``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_LOG = logging.getLogger(__name__)


IDA_PATH_ENV = "MX_MCP_IDA_PATH"
IDA_OUTPUT_ENV = "MX_MCP_IDA_OUTPUT"
DEFAULT_IDA_TIMEOUT_S = 180.0
DEFAULT_DRIVER_BASENAME = "idat64.exe"
FALLBACK_DRIVER_BASENAME = "idat.exe"


class IdaNotFoundError(FileNotFoundError):
    """Raised when the ``idat64.exe`` executable cannot be located.

    Distinguished from a generic ``FileNotFoundError`` so callers can
    treat "IDA missing" (skip) differently from "binary missing" (error).
    """


@dataclass(frozen=True, slots=True)
class IdaRunResult:
    """Outcome of one IDA script invocation."""

    ok: bool
    duration_ms: int
    stdout_tail: str
    stderr_tail: str
    output: dict[str, Any] | None
    error: str | None = None
    workdir: Path | None = None  # kept only when keep_database=True


# ============================================================================
# Path resolution
# ============================================================================


def resolve_ida_path(override: str | Path | None = None) -> Path:
    """Return the path to the ``idat64.exe`` driver.

    Precedence: ``override`` arg › ``MX_MCP_IDA_PATH`` env › ``PATH``
    lookup for ``idat64.exe`` / ``idat.exe`` › literal ``idat64.exe``.
    Does not verify existence — ``run_ida_script`` raises
    ``IdaNotFoundError`` on actual miss.

    If the resolved candidate is a directory, ``idat64.exe`` is
    appended — matches the common "IDA install dir" form of the env
    variable.
    """
    candidate = override
    if candidate is None:
        from_env = os.environ.get(IDA_PATH_ENV)
        if from_env:
            candidate = from_env

    if candidate is not None:
        p = Path(candidate)
        if p.is_dir():
            return p / DEFAULT_DRIVER_BASENAME
        return p

    for name in (DEFAULT_DRIVER_BASENAME, FALLBACK_DRIVER_BASENAME):
        which = shutil.which(name)
        if which:
            return Path(which)
    return Path(DEFAULT_DRIVER_BASENAME)


# ============================================================================
# Subprocess seam — overridden by tests via monkeypatch.
# ============================================================================


def _run_subprocess(
    cmd: list[str],
    timeout_s: float,
    cwd: str,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
        cwd=cwd,
        env=env,
    )


def _tail(text: str, limit: int = 2048) -> str:
    return text if len(text) <= limit else text[-limit:]


# ============================================================================
# Public API
# ============================================================================


async def run_ida_script(
    binary: Path,
    script: Path,
    *,
    ida_path: str | Path | None = None,
    workdir: Path | None = None,
    timeout_s: float = DEFAULT_IDA_TIMEOUT_S,
    keep_database: bool = False,
    extra_env: dict[str, str] | None = None,
) -> IdaRunResult:
    """Run an IDAPython script against ``binary``.

    The script is expected to write its JSON result to the path given
    by the ``MX_MCP_IDA_OUTPUT`` env var. Additional env vars may be
    passed through ``extra_env``; the runner merges them with the
    current process env so the IDA child sees both.

    Returns an ``IdaRunResult`` regardless of outcome — callers inspect
    ``.ok`` and ``.error`` rather than catching exceptions. Two
    exceptions still propagate: ``FileNotFoundError`` when the input
    binary is missing and ``IdaNotFoundError`` when IDA itself is not
    installed (cleaner than embedding a process-launch ENOENT in
    ``.error``).
    """
    if not binary.exists():
        raise FileNotFoundError(f"input binary not found: {binary}")

    ida_exe = resolve_ida_path(ida_path)
    if not ida_exe.exists():
        raise IdaNotFoundError(
            f"IDA driver not found at {ida_exe}. "
            f"Set ${IDA_PATH_ENV} or pass ida_path=."
        )
    if not script.exists():
        raise FileNotFoundError(f"IDAPython script not found: {script}")

    # Per-invocation workdir — IDA creates several database files next
    # to the input binary and we don't want those polluting the caller's
    # directory.
    owned_workdir = workdir is None
    wd = workdir or Path(tempfile.mkdtemp(prefix="mx_mcp_ida_"))
    wd.mkdir(parents=True, exist_ok=True)

    binary_copy = wd / binary.name
    shutil.copy2(binary, binary_copy)

    output_path = wd / "mx_mcp_ida_output.json"

    # ``-S<script>`` is a single argv token per IDA's CLI parser. No
    # shell involved — subprocess with list args passes each token
    # verbatim to CreateProcess.
    cmd: list[str] = [
        str(ida_exe),
        "-A",
        f"-S{script}",
        str(binary_copy),
    ]

    env = dict(os.environ)
    env[IDA_OUTPUT_ENV] = str(output_path)
    if extra_env:
        env.update(extra_env)

    _LOG.info(
        "run IDA: %s on %s (workdir=%s)",
        script.name, binary.name, wd,
    )
    t0 = time.monotonic()

    try:
        proc = await asyncio.to_thread(
            _run_subprocess, cmd, timeout_s, str(wd), env,
        )
    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - t0) * 1000)
        if owned_workdir and not keep_database:
            shutil.rmtree(wd, ignore_errors=True)
        return IdaRunResult(
            ok=False,
            duration_ms=duration_ms,
            stdout_tail="",
            stderr_tail="",
            output=None,
            error=f"IDA timed out after {timeout_s}s",
        )

    duration_ms = int((time.monotonic() - t0) * 1000)

    output: dict[str, Any] | None = None
    output_error: str | None = None
    if output_path.exists():
        try:
            output = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            output_error = f"output json parse: {e}"

    ok = (proc.returncode == 0) and (output is not None) and (output_error is None)
    error: str | None = None
    if not ok:
        if output_error:
            error = output_error
        elif proc.returncode != 0:
            error = f"IDA exit={proc.returncode}"
        else:
            error = "IDA completed but produced no output JSON"

    retained_workdir: Path | None = None
    if keep_database or not owned_workdir:
        retained_workdir = wd
    else:
        shutil.rmtree(wd, ignore_errors=True)

    return IdaRunResult(
        ok=ok,
        duration_ms=duration_ms,
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
        output=output,
        error=error,
        workdir=retained_workdir,
    )
