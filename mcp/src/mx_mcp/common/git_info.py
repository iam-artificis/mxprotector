"""Git HEAD state reader.

One small helper that every tool wanting to tag output with a version
calls. Replaces the one-off ``_read_git_commit`` private helpers
scattered across the tools package so the snapshot store and
``record_baseline`` eventually share a single source of truth.

## Contract

:func:`read_git_head` is best-effort. It returns:

* A fully populated :class:`GitHeadInfo` when the directory is a git
  repository and ``git`` is on the PATH.
* ``None`` when git is missing, or the directory is not a git repo,
  or any required subcommand failed. We never raise — callers rely on
  the function always terminating, and partial results would mislead.

The function is deliberately **synchronous**. Typical callers run
three subprocesses totalling < 100 ms; wrapping them in
``asyncio.to_thread`` is a one-liner at the call site when non-
blocking is needed. Keeping this module stdlib-only avoids pulling
``asyncio`` into every ``common/`` consumer.

## Returned fields

``commit_sha`` and ``commit_short`` are always populated when the
reader succeeds. ``branch`` is ``None`` on detached HEAD (``git
rev-parse --abbrev-ref HEAD`` returns the literal string ``HEAD``).
``dirty`` reflects whether ``git status --porcelain`` produced any
output — tracked modifications, staged changes, new / untracked
files, deletions. Submodule state is ignored (our repo has none).
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path


_LOG = logging.getLogger(__name__)


_DEFAULT_SUBCMD_TIMEOUT_S: float = 5.0
_DETACHED_HEAD_SENTINEL: str = "HEAD"
_COMMIT_SHORT_LEN: int = 7


@dataclass(frozen=True, slots=True)
class GitHeadInfo:
    """Snapshot of the repository's HEAD at a point in time."""

    commit_sha: str
    commit_short: str
    branch: str | None
    dirty: bool


def read_git_head(
    workspace_root: Path, *, timeout_s: float = _DEFAULT_SUBCMD_TIMEOUT_S,
) -> GitHeadInfo | None:
    """Read ``workspace_root``'s git HEAD state.

    ``timeout_s`` is applied to *each* subprocess call, not to the
    wall clock — three sequential git invocations on a modern host
    complete well under ten milliseconds combined.

    Returns ``None`` (without raising) when:

    * ``git`` is not on the PATH (``FileNotFoundError`` / ``OSError``).
    * ``workspace_root`` is not a git repository — ``git rev-parse``
      exits non-zero in that case.
    * Any subcommand times out.

    On a detached HEAD, the returned ``GitHeadInfo`` carries
    ``branch=None`` but is otherwise fully populated.
    """
    commit_sha = _run_git(
        ["rev-parse", "HEAD"], workspace_root, timeout_s=timeout_s,
    )
    if commit_sha is None:
        return None

    branch_raw = _run_git(
        ["rev-parse", "--abbrev-ref", "HEAD"],
        workspace_root, timeout_s=timeout_s,
    )
    branch = (
        None if branch_raw is None or branch_raw == _DETACHED_HEAD_SENTINEL
        else branch_raw
    )

    # ``git status --porcelain`` is the canonical "is my tree clean?"
    # probe. Missing file → non-zero exit (already filtered by None).
    status = _run_git(
        ["status", "--porcelain"], workspace_root, timeout_s=timeout_s,
    )
    if status is None:
        return None
    dirty = bool(status)

    return GitHeadInfo(
        commit_sha=commit_sha,
        commit_short=commit_sha[:_COMMIT_SHORT_LEN],
        branch=branch,
        dirty=dirty,
    )


def _run_git(
    args: list[str], cwd: Path, *, timeout_s: float,
) -> str | None:
    """Run ``git <args>`` in ``cwd``; return stripped stdout or ``None``.

    ``None`` is returned for any failure mode (non-zero exit, missing
    executable, timeout). Separated out so the happy path in
    ``read_git_head`` stays three straight-line calls.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError:
        _LOG.debug("git not found on PATH while running %s", args)
        return None
    except OSError as e:
        _LOG.debug("OSError running git %s: %s", args, e)
        return None
    except subprocess.TimeoutExpired:
        _LOG.debug("git %s timed out after %.1fs", args, timeout_s)
        return None

    if proc.returncode != 0:
        _LOG.debug(
            "git %s exited with %d: %s",
            args, proc.returncode, proc.stderr.strip(),
        )
        return None

    return proc.stdout.strip()
