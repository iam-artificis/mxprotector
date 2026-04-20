"""Builder invocation helper — runs ``mxprotector_builder.exe``.

The first real caller is ``benchmarks/cff_benchmark.py`` which needs a
freshly protected binary per corpus sample. Pulling the invocation
into one reusable function avoids having each benchmark re-discover
the builder path, re-implement timeout handling, and re-parse the
stdout for diagnostics.

## Design

* Pure-subprocess, no asyncio gymnastics besides ``asyncio.to_thread``
  around the blocking ``subprocess.run``.
* ``_run_subprocess`` is a module-level function so tests can
  ``monkeypatch.setattr`` it without touching the public API.
* Raises ``BuilderError`` on any builder-side failure (missing exe,
  non-zero exit, missing output, timeout). Callers treat this as a
  fail-closed outcome per ``MCP.md``.

## Paths

* Builder executable: resolved in order override → env
  ``MX_MCP_BUILDER_PATH`` → default
  ``<workspace_root>/build/src/builder/Release/mxprotector_builder.exe``.
* Sidecar: ``<output>.mxtrace.json`` next to the protected output,
  present iff ``trace_hints`` was set and the builder actually wrote
  it (returned as ``None`` otherwise — benchmarks that need the
  sidecar decide how to react).
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mx_mcp.common.corpus import CorpusEntry


_LOG = logging.getLogger(__name__)


DEFAULT_BUILDER_REL = (
    Path("build") / "src" / "builder" / "Release" / "mxprotector_builder.exe"
)
BUILDER_PATH_ENV = "MX_MCP_BUILDER_PATH"
DEFAULT_BUILDER_TIMEOUT_S = 120.0


class BuilderError(RuntimeError):
    """Raised when ``mxprotector_builder`` fails or the exe is missing."""


@dataclass(frozen=True, slots=True)
class ProtectedBuild:
    """Result of invoking ``mxprotector_builder`` on one input."""

    unprotected_binary: Path
    protected_binary: Path
    sidecar_path: Path | None
    duration_ms: int
    stdout_tail: str
    stderr_tail: str


# ============================================================================
# Path resolution
# ============================================================================


def resolve_builder_path(workspace_root: Path) -> Path:
    """Return the builder executable path.

    Precedence: ``MX_MCP_BUILDER_PATH`` env var ›
    ``<workspace_root>/build/src/builder/Release/mxprotector_builder.exe``.
    Existence is *not* checked here — callers decide the error shape
    (``build_protected`` raises ``BuilderError``).
    """
    override = os.environ.get(BUILDER_PATH_ENV)
    if override:
        return Path(override)
    return workspace_root / DEFAULT_BUILDER_REL


# ============================================================================
# Subprocess seam (module-level for monkeypatch in tests)
# ============================================================================


def _run_subprocess(
    cmd: list[str],
    timeout_s: float,
    cwd: str | None,
) -> subprocess.CompletedProcess[str]:
    """Blocking subprocess invocation. Tests override via monkeypatch.

    UTF-8 decoding is forced because the builder emits via MSVC's
    ``/utf-8`` flag; without the explicit encoding a cp1251 locale
    (typical on RU Windows) blows up on the reader thread.
    """
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
        cwd=cwd,
    )


# ============================================================================
# Helpers
# ============================================================================


def _tail(text: str, limit: int = 2048) -> str:
    return text if len(text) <= limit else text[-limit:]


# ============================================================================
# Public API
# ============================================================================


async def build_protected(
    unprotected: Path,
    output: Path,
    *,
    builder_path: Path,
    level: str = "strong",
    extra_args: list[str] | None = None,
    trace_hints: bool = True,
    timeout_s: float = DEFAULT_BUILDER_TIMEOUT_S,
    workspace_root: Path | None = None,
) -> ProtectedBuild:
    """Run ``mxprotector_builder`` on ``unprotected`` producing ``output``.

    Parameters are explicit on purpose — benchmarks typically vary
    ``level`` + ``extra_args`` and share every other knob.

    Raises:
        FileNotFoundError: ``unprotected`` does not exist on disk.
        BuilderError: builder exe missing, non-zero exit, output
            file not produced, or timeout.
    """
    if not unprotected.exists():
        raise FileNotFoundError(f"input binary not found: {unprotected}")
    if not builder_path.exists():
        raise BuilderError(f"builder not found at {builder_path}")

    output.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        str(builder_path),
        "-i", str(unprotected),
        "-o", str(output),
        "-l", level,
    ]
    if trace_hints:
        cmd.append("--trace-hints")
    if extra_args:
        cmd.extend(extra_args)

    _LOG.info("build %s → %s (level=%s)", unprotected.name, output.name, level)
    t0 = time.monotonic()

    try:
        proc = await asyncio.to_thread(
            _run_subprocess,
            cmd,
            timeout_s,
            str(workspace_root) if workspace_root else None,
        )
    except subprocess.TimeoutExpired as e:
        raise BuilderError(
            f"builder timed out after {timeout_s}s on {unprotected}"
        ) from e

    duration_ms = int((time.monotonic() - t0) * 1000)

    if proc.returncode != 0:
        raise BuilderError(
            f"builder exit={proc.returncode} on {unprotected.name}\n"
            f"stderr tail:\n{_tail(proc.stderr)}"
        )

    if not output.exists():
        raise BuilderError(
            f"builder returned 0 but output file missing: {output}\n"
            f"stdout tail:\n{_tail(proc.stdout)}"
        )

    sidecar: Path | None = None
    if trace_hints:
        candidate = output.parent / f"{output.name}.mxtrace.json"
        if candidate.exists():
            sidecar = candidate

    return ProtectedBuild(
        unprotected_binary=unprotected,
        protected_binary=output,
        sidecar_path=sidecar,
        duration_ms=duration_ms,
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
    )


async def ensure_protected(
    entry: "CorpusEntry",
    *,
    output_dir: Path,
    builder_path: Path,
    level: str = "strong",
    extra_args: list[str] | None = None,
    trace_hints: bool = True,
    timeout_s: float = DEFAULT_BUILDER_TIMEOUT_S,
    workspace_root: Path | None = None,
) -> ProtectedBuild:
    """Return a :class:`ProtectedBuild` for a corpus entry.

    Dispatches on the entry kind:

    * **Pre-protected** (``entry.pre_protected_binary`` set) — returns
      a ``ProtectedBuild`` pointing directly at the preserved artefact.
      No subprocess is invoked; the build-related timing fields report
      ``0 ms`` / empty stdout tails so callers can still log uniform
      timing reports.
    * **Buildable** — forwards to :func:`build_protected`, picking an
      output path of ``{output_dir}/{entry.name}.mx.exe``.

    This is the single entry point benchmarks should call. Inline
    dispatch in each benchmark was the alternative; centralising it
    here keeps every benchmark oblivious to legacy-binary plumbing
    and makes future additions (e.g. signed-build corpus entries)
    one-file changes.

    Raises:
        FileNotFoundError: a declared input path does not exist
            (``pre_protected_binary`` or ``unprotected_binary``).
        BuilderError: fresh-build path failed (see :func:`build_protected`).
    """
    if entry.pre_protected_binary is not None:
        if not entry.pre_protected_binary.exists():
            raise FileNotFoundError(
                f"pre-protected binary missing for '{entry.name}': "
                f"{entry.pre_protected_binary}"
            )
        _LOG.info(
            "use pre-protected %s → %s%s",
            entry.name,
            entry.pre_protected_binary.name,
            " (+sidecar)" if entry.pre_sidecar else "",
        )
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary
                or entry.pre_protected_binary,
            protected_binary=entry.pre_protected_binary,
            sidecar_path=entry.pre_sidecar,
            duration_ms=0,
            stdout_tail="(pre-protected entry — build step skipped)",
            stderr_tail="",
        )

    if entry.unprotected_binary is None:
        # Should be impossible by construction (Corpus.load enforces at
        # least one source path), but guard explicitly — a clear error
        # beats an opaque AttributeError downstream.
        raise BuilderError(
            f"corpus entry '{entry.name}' has neither unprotected nor "
            f"pre-protected source"
        )

    output = output_dir / f"{entry.name}.mx.exe"
    return await build_protected(
        unprotected=entry.unprotected_binary,
        output=output,
        builder_path=builder_path,
        level=level,
        extra_args=extra_args,
        trace_hints=trace_hints,
        timeout_s=timeout_s,
        workspace_root=workspace_root,
    )
