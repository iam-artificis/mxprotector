"""IDA headless → ``.BinExport`` export.

The first half of the BinDiff pipeline: convert one PE into the
BinExport protobuf that ``bindiff.exe`` consumes. IDA Pro (via the
BinExport plugin) is the only supported disassembler in the MVP.

## Contract

Verified invocation (BinExport 12 + IDA Pro 8.3):

```
idat64.exe -A -OBinExportAutoAction:BinExportBinary \\
           -OBinExportModule:<out.BinExport> <input.exe>
```

Both ``-O`` options are required together:

* ``BinExportAutoAction`` tells the plugin which action to fire
  automatically (``BinExportBinary`` is the disk-to-disk mode we want).
* ``BinExportModule`` carries the output path — the plugin writes
  the protobuf there when auto-analysis finishes.

``-B`` (IDA's batch mode) deliberately *not* used: it exits before
the plugin's auto-action gets a chance to run, leaving no output.
``-A`` alone is the right balance — autonomous (no dialogs) but
still runs plugin hooks to completion.

## Path resolution

Reuses :func:`resolve_ida_path` from the existing IDA runner so the
``MX_MCP_IDA_PATH`` env var governs both script-driven and
BinExport-driven IDA invocations.

## Side effects

IDA writes a ``.i64`` database plus a handful of sibling files
(``.id0``, ``.id1``, ``.nam``, ``.til``) *next to the input binary*
during analysis. Callers usually hand us a path inside a temp
directory that gets cleaned up whole — the runner does not
second-guess that. The ``cleanup`` helper at the bottom of this
module exists for callers that reuse the binary location.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from mx_mcp.static.ida.runner import (
    IdaNotFoundError,
    resolve_ida_path,
)


_LOG = logging.getLogger(__name__)


DEFAULT_BINEXPORT_TIMEOUT_S = 300.0


# ============================================================================
# Errors
# ============================================================================


class BinExportError(RuntimeError):
    """Raised when an unexpected BinExport runtime condition occurs.

    Mostly dormant — the runner prefers soft failures via
    :class:`BinExportResult` (``ok=False``). Reserved for
    contract-breaks the caller should never see (e.g. impossible
    argument combinations).
    """


# ============================================================================
# Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class BinExportResult:
    """Outcome of one BinExport run.

    ``output_path`` is populated only when the plugin actually wrote
    the file. Plugin mis-configurations (wrong option name, plugin
    not installed in IDA's ``plugins/`` directory) usually surface as
    ``ok=False`` with the subprocess succeeding but no file on disk —
    IDA has no standard exit code for "plugin didn't run".
    """

    ok: bool
    duration_ms: int
    output_path: Path | None
    error: str | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""


# ============================================================================
# Subprocess seam — module-level so tests override via monkeypatch.
# ============================================================================


def _run_subprocess(
    cmd: list[str], timeout_s: float, cwd: str | None,
) -> subprocess.CompletedProcess[str]:
    """Blocking subprocess invocation. Tests monkeypatch this.

    UTF-8 is forced because IDA emits UTF-8 by default on 8+; mixed
    cp1251 output on RU-locale hosts would otherwise break the reader
    thread.
    """
    return subprocess.run(
        cmd,
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        timeout=timeout_s, cwd=cwd,
    )


# ============================================================================
# Public entry point
# ============================================================================


async def run_binexport(
    binary: Path,
    output_path: Path,
    *,
    ida_path: str | Path | None = None,
    timeout_s: float = DEFAULT_BINEXPORT_TIMEOUT_S,
) -> BinExportResult:
    """Export ``binary`` to a BinExport protobuf at ``output_path``.

    Never raises — every failure mode surfaces as
    ``BinExportResult(ok=False, error=...)`` so higher-level
    orchestration can aggregate errors uniformly.

    Pre-conditions a well-behaved caller enforces:

    * ``binary`` exists on disk.
    * ``output_path.parent`` exists (the runner does *not* create
      parent directories; callers typically already own the workdir).
    """
    t0 = time.monotonic()

    if not binary.exists():
        return BinExportResult(
            ok=False, duration_ms=0, output_path=None,
            error=f"input binary missing: {binary}",
        )

    try:
        ida_exe = resolve_ida_path(ida_path)
    except IdaNotFoundError as e:
        return BinExportResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            output_path=None,
            error=f"IDA not found: {e}",
        )

    if not ida_exe.exists():
        return BinExportResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            output_path=None,
            error=f"IDA driver missing at {ida_exe}",
        )

    cmd = [
        str(ida_exe),
        "-A",
        "-OBinExportAutoAction:BinExportBinary",
        f"-OBinExportModule:{output_path}",
        str(binary),
    ]
    _LOG.info(
        "BinExport: %s → %s (timeout %.0fs)",
        binary.name, output_path.name, timeout_s,
    )

    try:
        proc = await asyncio.to_thread(
            _run_subprocess, cmd, timeout_s, str(binary.parent),
        )
    except subprocess.TimeoutExpired:
        return BinExportResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            output_path=None,
            error=f"BinExport timed out after {timeout_s}s on {binary.name}",
        )
    except OSError as e:
        return BinExportResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            output_path=None,
            error=f"BinExport subprocess failed to start: {e}",
        )

    duration_ms = int((time.monotonic() - t0) * 1000)

    if proc.returncode != 0:
        return BinExportResult(
            ok=False, duration_ms=duration_ms, output_path=None,
            error=f"IDA exit={proc.returncode}",
            stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
        )

    # IDA returning zero does *not* guarantee the plugin actually ran.
    # A missing / mis-installed BinExport plugin leaves no trace in
    # the exit code — we check the output file as the real signal.
    if not output_path.exists():
        return BinExportResult(
            ok=False, duration_ms=duration_ms, output_path=None,
            error=(
                "BinExport produced no output file at "
                f"{output_path} — verify the plugin is installed in "
                "IDA's plugins/ directory"
            ),
            stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
        )

    size = output_path.stat().st_size
    _LOG.info(
        "BinExport %s done in %dms (%d B written)",
        binary.name, duration_ms, size,
    )
    return BinExportResult(
        ok=True, duration_ms=duration_ms,
        output_path=output_path,
        stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
    )


# ============================================================================
# Small helpers
# ============================================================================


def _tail(text: str, limit: int = 1024) -> str:
    return text if len(text) <= limit else text[-limit:]
