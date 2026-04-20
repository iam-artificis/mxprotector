"""``bindiff.exe`` subprocess wrapper.

Second half of the BinDiff pipeline: given two ``.BinExport`` files,
invoke BinDiff and parse its output into :class:`BinDiffReport`.

## CLI shape (verified against BinDiff 8)

```
bindiff.exe --primary=A.BinExport --secondary=B.BinExport \\
            --output_dir=<dir> --output_format=log,bin
```

Output artefacts in ``<dir>``:

* ``<primary-stem>_vs_<secondary-stem>.BinDiff`` — SQLite database
  loadable by the IDA plugin. Preserved for evidence / later UI use.
* ``<primary-stem>_vs_<secondary-stem>.results`` — the statistics
  table parsed by :mod:`report`.

Both artefacts are returned by path; the runner does not delete
them — callers own the ``output_dir`` lifetime.

## Path resolution

``MX_MCP_BINDIFF_PATH`` env var points at ``bindiff.exe`` (or a
directory containing it). Falls back to ``shutil.which`` then to the
literal basename so ``subprocess`` fails cleanly when nothing
resolves.

## Exit codes

BinDiff 8 returns 0 on successful diff regardless of how similar /
different the inputs were — the similarity signal lives in stdout,
not the exit code. Non-zero therefore always means a real failure
(missing BinExport file, permissions, internal crash).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from mx_mcp.diffing.bindiff.report import BinDiffReport, parse_report


_LOG = logging.getLogger(__name__)


BINDIFF_PATH_ENV = "MX_MCP_BINDIFF_PATH"
DEFAULT_EXE_BASENAME = "bindiff.exe"

DEFAULT_BINDIFF_TIMEOUT_S = 120.0


# ============================================================================
# Errors
# ============================================================================


class BinDiffNotFoundError(FileNotFoundError):
    """Raised when ``bindiff.exe`` cannot be resolved.

    :func:`run_bindiff` catches this and converts to a
    ``BinDiffRunResult(ok=False)``; the class is exported so callers
    that want the hard-error variant (e.g. CI pre-flight) can.
    """


# ============================================================================
# Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class BinDiffRunResult:
    """Outcome of one ``bindiff.exe`` invocation.

    ``report`` is populated only when stdout parsed cleanly; callers
    wanting richer detail read ``report.results`` (sourced from the
    ``.results`` file) directly.

    ``bindiff_db_path`` and ``results_path`` are informational — the
    runner does not need them after parsing, but they are returned so
    callers can archive them as evidence.
    """

    ok: bool
    duration_ms: int
    report: BinDiffReport | None
    bindiff_db_path: Path | None = None
    results_path: Path | None = None
    error: str | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""


# ============================================================================
# Path resolution
# ============================================================================


def resolve_bindiff_path(override: Path | str | None = None) -> Path:
    """Return the path to ``bindiff.exe``.

    Precedence: ``override`` arg › ``MX_MCP_BINDIFF_PATH`` env ›
    ``shutil.which("bindiff.exe")`` / ``shutil.which("bindiff")``.

    Accepts both a direct exe path and a directory containing it.
    Existence is verified; missing files raise
    :class:`BinDiffNotFoundError`.
    """
    candidate = _first_bindiff_candidate(override)
    if candidate is None:
        raise BinDiffNotFoundError(
            f"bindiff.exe not found on PATH. Set ${BINDIFF_PATH_ENV} or "
            f"pass bindiff_path= to run_bindiff()."
        )

    path = Path(candidate)
    if path.is_dir():
        path = path / DEFAULT_EXE_BASENAME

    if not path.exists():
        raise BinDiffNotFoundError(f"bindiff.exe not found at {path}")
    return path


def _first_bindiff_candidate(
    override: Path | str | None,
) -> str | Path | None:
    if override is not None:
        return override
    env = os.environ.get(BINDIFF_PATH_ENV)
    if env:
        return env
    for basename in ("bindiff.exe", "bindiff"):
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
    """Blocking subprocess invocation. Tests override via monkeypatch."""
    return subprocess.run(
        cmd,
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        timeout=timeout_s, cwd=cwd,
    )


# ============================================================================
# Public entry point
# ============================================================================


async def run_bindiff(
    primary: Path,
    secondary: Path,
    *,
    output_dir: Path,
    bindiff_path: Path | str | None = None,
    timeout_s: float = DEFAULT_BINDIFF_TIMEOUT_S,
) -> BinDiffRunResult:
    """Diff two ``.BinExport`` files via ``bindiff.exe``.

    Never raises — all failure modes return ``ok=False`` with an
    explanatory ``error``. ``output_dir`` must exist before the call;
    the runner leaves artefact cleanup to the caller because the
    ``.BinDiff`` + ``.results`` files are valuable for evidence.

    Pre-conditions:

    * ``primary`` and ``secondary`` exist and point at ``.BinExport``
      files; ``run_bindiff`` does not verify the format beyond the
      existence check.
    * ``output_dir`` exists on disk.
    """
    t0 = time.monotonic()

    for label, path in (("primary", primary), ("secondary", secondary)):
        if not path.exists():
            return BinDiffRunResult(
                ok=False, duration_ms=0, report=None,
                error=f"{label} BinExport missing: {path}",
            )

    if not output_dir.is_dir():
        return BinDiffRunResult(
            ok=False, duration_ms=0, report=None,
            error=f"output_dir missing: {output_dir}",
        )

    try:
        exe = resolve_bindiff_path(bindiff_path)
    except BinDiffNotFoundError as e:
        return BinDiffRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None, error=str(e),
        )

    cmd = _build_cmd(exe, primary=primary, secondary=secondary, output_dir=output_dir)

    try:
        proc = await asyncio.to_thread(
            _run_subprocess, cmd, timeout_s, str(output_dir),
        )
    except subprocess.TimeoutExpired:
        return BinDiffRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None,
            error=f"bindiff timed out after {timeout_s}s",
        )
    except OSError as e:
        return BinDiffRunResult(
            ok=False, duration_ms=int((time.monotonic() - t0) * 1000),
            report=None, error=f"bindiff subprocess failed to start: {e}",
        )

    duration_ms = int((time.monotonic() - t0) * 1000)

    if proc.returncode != 0:
        return BinDiffRunResult(
            ok=False, duration_ms=duration_ms, report=None,
            error=f"bindiff exit={proc.returncode}",
            stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
        )

    bindiff_db_path, results_path = _find_output_artifacts(
        output_dir=output_dir, primary=primary, secondary=secondary,
    )

    results_contents = (
        results_path.read_text(encoding="utf-8", errors="replace")
        if results_path is not None and results_path.exists()
        else None
    )
    report = parse_report(
        stdout=proc.stdout, results_file_contents=results_contents,
    )

    # The headline "similarity" line being absent is a soft fail —
    # BinDiff sometimes omits it on degenerate inputs. Surface as
    # ok=False so the benchmark records a clear error instead of
    # writing a None-filled sample.
    if report.similarity is None:
        return BinDiffRunResult(
            ok=False, duration_ms=duration_ms, report=report,
            bindiff_db_path=bindiff_db_path, results_path=results_path,
            error="bindiff produced no parseable Similarity line",
            stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
        )

    _LOG.info(
        "bindiff %s↔%s done in %dms: similarity=%.4f confidence=%.4f",
        primary.stem, secondary.stem, duration_ms,
        report.similarity, report.confidence or 0.0,
    )
    return BinDiffRunResult(
        ok=True, duration_ms=duration_ms, report=report,
        bindiff_db_path=bindiff_db_path, results_path=results_path,
        stdout_tail=_tail(proc.stdout), stderr_tail=_tail(proc.stderr),
    )


# ============================================================================
# Private helpers
# ============================================================================


def _build_cmd(
    exe: Path, *, primary: Path, secondary: Path, output_dir: Path,
) -> list[str]:
    """Compose the ``bindiff.exe`` command line.

    ``output_format=log,bin`` asks BinDiff for both a ``.results``
    text log (for our parser) and a ``.BinDiff`` SQLite database
    (for UI / later inspection).
    """
    return [
        str(exe),
        f"--primary={primary}",
        f"--secondary={secondary}",
        f"--output_dir={output_dir}",
        "--output_format=log,bin",
    ]


def _find_output_artifacts(
    *, output_dir: Path, primary: Path, secondary: Path,
) -> tuple[Path | None, Path | None]:
    """Locate the ``.BinDiff`` + ``.results`` pair BinDiff wrote.

    BinDiff 8 names them ``<primary-stem>_vs_<secondary-stem>.*``
    using the ``.BinExport``-stripped base. ``Path.stem`` on
    ``foo.BinExport`` yields ``foo`` — exactly what BinDiff uses.

    Returns ``(bindiff_db, results)`` with either position ``None``
    when the corresponding file is missing (which would typically
    mean BinDiff crashed mid-write).
    """
    base = f"{primary.stem}_vs_{secondary.stem}"
    bindiff_db = output_dir / f"{base}.BinDiff"
    results = output_dir / f"{base}.results"
    return (
        bindiff_db if bindiff_db.exists() else None,
        results if results.exists() else None,
    )


def _tail(text: str, limit: int = 2048) -> str:
    return text if len(text) <= limit else text[-limit:]
