"""pe-sieve subprocess orchestration.

Single public entry point :func:`run_pesieve` does:

1. Resolve ``pe-sieve64.exe`` via ``override`` arg › env
   ``MX_MCP_PESIEVE_PATH`` › ``PATH`` lookup.
2. Launch the target binary as a child (:mod:`process_controller`).
3. Sleep ``decrypt_wait_ms`` so the packer has time to unwrap its
   encrypted sections in-memory — pe-sieve's whole value is that it
   scans *after* decryption.
4. Run ``pe-sieve64.exe /pid <child-pid> /json /dir <workdir>`` with a
   hard timeout.
5. Parse the summary JSON (stdout, falling back to the
   ``scan_report.json`` pe-sieve writes to its output directory).
6. Collect any PE files pe-sieve dumped — a non-empty dump directory
   is the main "attacker won" signal the benchmark scores on.
7. Terminate the child unconditionally (``finally`` block wrapping
   the whole flow — zombies never leave the function).

## Error handling

:func:`run_pesieve` is **never-raises**: every failure mode returns a
:class:`PesieveRunResult` with ``ok=False`` and an error string.
This matches the rest of the MCP's "fail-closed" discipline — the
caller always gets a typed result even when pe-sieve is missing, the
child crashes, or JSON parsing fails.

## Subprocess seam

``_run_subprocess`` is a module-level function so tests override it
via ``monkeypatch.setattr``. The same idiom is used for every other
subprocess-backed runner in the MCP (see
``static.ida.runner._run_subprocess``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from mx_mcp.unpacking.pe_sieve.process_controller import (
    LaunchedProcess,
    ProcessLaunchError,
    is_alive,
    launch_process,
    terminate_process,
)
from mx_mcp.unpacking.pe_sieve.report import (
    PesieveParseError,
    PesieveReport,
    parse_report,
)


_LOG = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================


PESIEVE_PATH_ENV = "MX_MCP_PESIEVE_PATH"
DEFAULT_EXE_BASENAME = "pe-sieve64.exe"

DEFAULT_DECRYPT_WAIT_MS = 1500
DEFAULT_SCAN_TIMEOUT_S = 30.0

# pe-sieve dumps land in a subdirectory named ``process_<pid>``.
# We also accept whatever pe-sieve reports in ``dumped.dir`` when
# that field is populated.
_DEFAULT_DUMP_DIRNAME_TEMPLATE = "process_{pid}"


# ============================================================================
# Errors
# ============================================================================


class PesieveNotFoundError(FileNotFoundError):
    """Raised when ``pe-sieve64.exe`` cannot be resolved.

    The :func:`run_pesieve` wrapper catches this and converts to a
    ``PesieveRunResult(ok=False)`` — the class is still exported so
    callers that *want* the hard error (e.g. an invariant check in
    CI) can inspect it directly.
    """


# ============================================================================
# Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class PesieveRunResult:
    """Outcome of one ``run_pesieve`` invocation.

    ``report`` is populated only when the scan produced parseable
    JSON. ``dump_files`` is always a list (possibly empty) of
    absolute paths to PE files pe-sieve wrote under ``workdir``.
    """

    ok: bool
    duration_ms: int
    report: PesieveReport | None
    dump_files: list[Path] = field(default_factory=list)
    error: str | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""


# ============================================================================
# Path resolution
# ============================================================================


def resolve_pesieve_path(override: Path | str | None = None) -> Path:
    """Return the path to ``pe-sieve64.exe``.

    Precedence: ``override`` arg › ``MX_MCP_PESIEVE_PATH`` env ›
    ``shutil.which("pe-sieve64.exe")`` / ``shutil.which("pe-sieve64")``.

    If the resolved candidate is a directory, ``pe-sieve64.exe`` is
    appended so callers can point the env var at either the exe or
    the folder containing it. Existence is verified; missing files
    raise :class:`PesieveNotFoundError`.
    """
    candidate = _first_pesieve_candidate(override)
    if candidate is None:
        raise PesieveNotFoundError(
            f"pe-sieve not found on PATH. Set ${PESIEVE_PATH_ENV} or "
            f"pass pesieve_path= to run_pesieve()."
        )

    path = Path(candidate)
    if path.is_dir():
        path = path / DEFAULT_EXE_BASENAME

    if not path.exists():
        raise PesieveNotFoundError(f"pe-sieve not found at {path}")
    return path


def _first_pesieve_candidate(
    override: Path | str | None,
) -> str | Path | None:
    if override is not None:
        return override
    env = os.environ.get(PESIEVE_PATH_ENV)
    if env:
        return env
    for basename in ("pe-sieve64.exe", "pe-sieve64", "pe-sieve.exe", "pe-sieve"):
        found = shutil.which(basename)
        if found:
            return found
    return None


# ============================================================================
# Subprocess seam
# ============================================================================


def _run_subprocess(
    cmd: list[str], timeout_s: float, cwd: str | None,
) -> subprocess.CompletedProcess[str]:
    """Blocking subprocess invocation. Tests monkeypatch.

    UTF-8 is forced so pe-sieve's Windows-default cp1251 stderr on
    RU locales does not blow up the reader thread.
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


async def run_pesieve(
    binary: Path,
    *,
    workdir: Path,
    pesieve_path: Path | str | None = None,
    decrypt_wait_ms: int = DEFAULT_DECRYPT_WAIT_MS,
    scan_timeout_s: float = DEFAULT_SCAN_TIMEOUT_S,
    child_args: list[str] | None = None,
) -> PesieveRunResult:
    """Launch ``binary``, wait for decryption, run pe-sieve against it.

    Never raises. On any failure returns ``PesieveRunResult(ok=False,
    error=...)`` so the benchmark layer can aggregate per-entry
    errors uniformly.

    ``workdir`` is the parent directory for pe-sieve output; each
    call uses it directly (pe-sieve itself creates a
    ``process_<pid>/`` subfolder inside).
    """
    t0 = time.monotonic()

    try:
        exe = resolve_pesieve_path(pesieve_path)
    except PesieveNotFoundError as e:
        return PesieveRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None, error=str(e),
        )

    workdir.mkdir(parents=True, exist_ok=True)

    try:
        child = launch_process(binary, workdir, args=child_args)
    except (FileNotFoundError, ProcessLaunchError) as e:
        return PesieveRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None, error=f"child launch: {type(e).__name__}: {e}",
        )

    try:
        return await _scan_child_then_terminate(
            child=child, exe=exe, workdir=workdir,
            decrypt_wait_ms=decrypt_wait_ms,
            scan_timeout_s=scan_timeout_s,
            t0=t0,
        )
    finally:
        # Terminate is idempotent for an already-dead child — safe to
        # call regardless of how we exited the scan stage.
        terminate_process(child)


# ============================================================================
# Scan stage — split out so ``finally`` in ``run_pesieve`` always runs
# the terminate even on unexpected exceptions in the scan logic.
# ============================================================================


async def _scan_child_then_terminate(
    *,
    child: LaunchedProcess,
    exe: Path,
    workdir: Path,
    decrypt_wait_ms: int,
    scan_timeout_s: float,
    t0: float,
) -> PesieveRunResult:
    """Happy path body: sleep for decrypt, scan, parse, collect."""
    await asyncio.sleep(decrypt_wait_ms / 1000.0)

    if not is_alive(child):
        exit_code = child.popen.poll()
        return PesieveRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None,
            error=(
                f"child exited before scan (exit={exit_code}); "
                f"stdout_tail={_read_tail(child.stdout_path)!r} "
                f"stderr_tail={_read_tail(child.stderr_path)!r}"
            ),
        )

    cmd = _build_pesieve_cmd(exe, pid=child.pid, workdir=workdir)
    try:
        proc = await asyncio.to_thread(
            _run_subprocess, cmd, scan_timeout_s, str(workdir),
        )
    except subprocess.TimeoutExpired:
        return PesieveRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None,
            error=f"pe-sieve scan timed out after {scan_timeout_s}s",
        )
    except OSError as e:
        return PesieveRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None, error=f"pe-sieve invocation: {e}",
        )

    duration_ms = int((time.monotonic() - t0) * 1000)

    if proc.returncode != 0:
        return PesieveRunResult(
            ok=False, duration_ms=duration_ms, report=None,
            error=f"pe-sieve exit={proc.returncode}",
            stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
        )

    report = _parse_report_with_fallback(proc.stdout, workdir, child.pid)
    if report is None:
        return PesieveRunResult(
            ok=False, duration_ms=duration_ms, report=None,
            error="pe-sieve produced no parseable JSON (stdout empty and report file missing)",
            stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
        )

    dump_files = _collect_dump_files(workdir, report)

    return PesieveRunResult(
        ok=True, duration_ms=duration_ms, report=report,
        dump_files=dump_files,
        stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
    )


# ============================================================================
# Private helpers — CLI + parsing + dump collection
# ============================================================================


def _build_pesieve_cmd(
    exe: Path, *, pid: int, workdir: Path,
) -> list[str]:
    """Compose the pe-sieve command line.

    * ``/pid <N>`` — target.
    * ``/json`` — structured summary on stdout.
    * ``/dir <path>`` — where to write dumps + the per-module report.
    * ``/quiet`` — suppress the interactive banner / status spam.
    """
    return [
        str(exe),
        "/pid", str(pid),
        "/json",
        "/dir", str(workdir),
        "/quiet",
    ]


def _parse_report_with_fallback(
    stdout: str, workdir: Path, pid: int,
) -> PesieveReport | None:
    """Try the JSON summary on stdout first, fall back to the
    on-disk ``scan_report.json`` pe-sieve writes alongside dumps.

    Different pe-sieve versions place the JSON summary in slightly
    different places; supporting both removes a whole class of
    version-drift bugs.
    """
    stdout = stdout.strip()
    if stdout:
        try:
            return parse_report(stdout)
        except PesieveParseError as e:
            _LOG.debug("pe-sieve stdout JSON unparseable: %s", e)

    candidate = workdir / _DEFAULT_DUMP_DIRNAME_TEMPLATE.format(pid=pid) / "scan_report.json"
    if candidate.exists():
        try:
            return parse_report(candidate.read_text(encoding="utf-8"))
        except PesieveParseError as e:
            _LOG.debug("pe-sieve %s unparseable: %s", candidate, e)
    return None


def _collect_dump_files(workdir: Path, report: PesieveReport) -> list[Path]:
    """Enumerate PE files pe-sieve wrote in the output directory.

    Preferred source: the directory pe-sieve itself reports in
    ``report.dumped.dir``. Fall back to the default
    ``process_<pid>`` convention when that field is unset (older
    pe-sieve versions). Any file with a PE-ish extension under that
    directory counts.
    """
    dump_dir = _resolve_dump_dir(workdir, report)
    if not dump_dir.exists():
        return []
    return sorted(
        p for p in dump_dir.iterdir()
        if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys"}
    )


def _resolve_dump_dir(workdir: Path, report: PesieveReport) -> Path:
    if report.dumped.dir:
        reported = Path(report.dumped.dir)
        # pe-sieve's ``dumped.dir`` is usually relative; make absolute
        # against ``workdir`` when so.
        if not reported.is_absolute():
            reported = workdir / reported
        return reported
    return workdir / _DEFAULT_DUMP_DIRNAME_TEMPLATE.format(pid=report.pid)


def _tail(text: str, limit: int = 2048) -> str:
    return text if len(text) <= limit else text[-limit:]


def _read_tail(path: Path, limit: int = 1024) -> str:
    if not path.exists():
        return ""
    try:
        return _tail(path.read_text(encoding="utf-8", errors="replace"), limit)
    except OSError:
        return ""
