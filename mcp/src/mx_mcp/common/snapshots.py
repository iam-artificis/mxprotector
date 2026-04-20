"""Self-contained snapshot store.

One snapshot = one directory under the store root. Each snapshot
bundles everything needed to **replay** a later benchmark against the
same binaries that produced the recorded metrics:

```
<root>/<snapshot_id>/
├── manifest.json          ← SnapshotManifest (this module)
├── measurement.json       ← opaque JSON payload from the caller
│                            (typically a serialised MeasureDefenseOutput)
└── artifacts/             ← preserved build outputs
    ├── <entry1>.mx.exe
    ├── <entry1>.mx.exe.mxtrace.json
    └── …
```

## Snapshot ID format

Deterministic, filesystem-safe, lexicographically sortable:

```
YYYY-MM-DDTHH-MM-SSZ_<commit7-or-"nogit">[_dirty]
```

Examples: ``2026-04-20T18-05-11Z_a1bfa66``,
``2026-04-21T09-30-00Z_a1bfa66_dirty``,
``2026-04-21T09-31-05Z_nogit``.

The ISO-like prefix means ``sorted(store.list_ids())`` is
automatically chronological. The ``_dirty`` marker distinguishes
snapshots captured against a clean tree from those on an uncommitted
workspace — critical for interpreting regressions ("was that fresh?
or from a work-in-progress tree?").

## Atomicity

:meth:`SnapshotStore.save` writes every artifact into a ``.pending-``
scratch directory first, then renames it to the final ``<id>``.
Either the whole snapshot lands or the scratch directory is scrubbed
in the exception handler — partial snapshots never corrupt
``list_ids``.

## Schema evolution

``SnapshotManifest.schema_version`` is validated on load. Additive
changes (new optional fields with defaults) stay on v1; pydantic's
``extra='ignore'`` lets newer tooling read older manifests. Breaking
changes bump the version and older tooling rejects them with
:class:`SnapshotCorruptError` at load time rather than silently
misreading.

## Non-goals

* This module is **tool-agnostic** — it knows nothing about
  ``MeasureDefenseOutput``. Callers serialise whatever they like into
  ``measurement_payload``; the store persists it verbatim as JSON
  and returns it as ``dict`` on load. Keeps
  ``common/`` independent of the tools / reporting layers.
* No auto-pruning. The MVP keeps everything; deletion is a human
  decision. A future pruning helper can live in a separate module.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, Field, field_validator

from mx_mcp.common.git_info import GitHeadInfo


_LOG = logging.getLogger(__name__)


SNAPSHOT_SCHEMA_VERSION = 1

_PENDING_PREFIX = ".pending-"
_MANIFEST_NAME = "manifest.json"
_MEASUREMENT_NAME = "measurement.json"
_ARTIFACTS_DIR = "artifacts"

# ID grammar: see module docstring. The regex is anchored and rejects
# path traversal + Windows-illegal characters (colon, slash, pipe, …)
# by construction.
_ID_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z"
    r"_(?:[0-9a-f]{7,40}|nogit)"
    r"(?:_dirty)?$"
)

# Artifact filenames must stay inside the artifacts/ directory and
# avoid anything that would break shutil.copy / Path resolution on
# Windows. Excludes backslashes, slashes, drive colons, and navigation.
_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


# ============================================================================
# Exceptions
# ============================================================================


class SnapshotError(Exception):
    """Base for all store-specific errors — callers can catch the family."""


class InvalidSnapshotIdError(SnapshotError, ValueError):
    """``snapshot_id`` does not match the accepted grammar."""


class InvalidArtifactNameError(SnapshotError, ValueError):
    """Artifact filename contains forbidden characters or paths."""


class SnapshotNotFoundError(SnapshotError, FileNotFoundError):
    """No snapshot with the requested id exists in the store."""


class SnapshotExistsError(SnapshotError, FileExistsError):
    """A snapshot with the requested id already exists."""


class SnapshotCorruptError(SnapshotError):
    """Snapshot directory is present but its manifest is missing /
    unparseable / carries a version this MCP does not understand."""


# ============================================================================
# Manifest (pydantic model — on-disk source of truth)
# ============================================================================


class SnapshotManifest(BaseModel):
    """Metadata describing one snapshot.

    All fields are part of the persisted JSON; pydantic's default
    ``extra='ignore'`` means newer tooling may add fields without
    breaking older readers.
    """

    schema_version: int = Field(
        default=SNAPSHOT_SCHEMA_VERSION,
        description="Snapshot-store schema version. See SNAPSHOT_SCHEMA_VERSION.",
    )
    snapshot_id: str = Field(
        description="Directory name of this snapshot; matches the on-disk folder.",
    )
    timestamp: str = Field(
        description="ISO-8601 UTC capture time (e.g. '2026-04-20T18:05:11Z').",
    )
    git_commit: str | None = Field(
        default=None,
        description="Full SHA at capture time; None when git was unavailable.",
    )
    git_branch: str | None = Field(
        default=None,
        description="Branch name; None on detached HEAD or when git was unavailable.",
    )
    git_dirty: bool = Field(
        default=False,
        description="Whether the working tree had uncommitted changes at capture.",
    )
    builder_level: str = Field(
        description="Protection level passed to mxprotector_builder (weak / normal / strong / maximum).",
    )
    builder_args: list[str] = Field(
        default_factory=list,
        description="Extra CLI args forwarded to mxprotector_builder at capture.",
    )
    corpus_path: str = Field(
        description="Corpus root used for this snapshot (absolute path at capture time).",
    )
    artifact_count: int = Field(
        default=0, ge=0,
        description="Number of files expected inside the artifacts/ directory.",
    )

    @field_validator("schema_version")
    @classmethod
    def _check_version(cls, v: int) -> int:
        if v != SNAPSHOT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported snapshot schema_version={v} "
                f"(this MCP reads v{SNAPSHOT_SCHEMA_VERSION})"
            )
        return v


# ============================================================================
# Snapshot ID helper
# ============================================================================


def make_snapshot_id(
    *, timestamp_iso: str, git: GitHeadInfo | None,
) -> str:
    """Compose a canonical snapshot id.

    ``timestamp_iso`` should be an ISO-8601 UTC stamp like
    ``2026-04-20T18:05:11Z``. Colons are replaced with dashes so the
    result is valid as a directory name on Windows. Callers that
    already hold a filesystem-safe stamp may pass it through
    unchanged.
    """
    safe_ts = timestamp_iso.replace(":", "-")
    if git is None:
        body = f"{safe_ts}_nogit"
    else:
        body = f"{safe_ts}_{git.commit_short}"
        if git.dirty:
            body += "_dirty"
    if not _ID_RE.match(body):
        # Should not happen with well-formed inputs; guards against
        # silently-creating-unreadable-IDs regressions.
        raise InvalidSnapshotIdError(
            f"composed id {body!r} violates the accepted grammar"
        )
    return body


# ============================================================================
# Resolved snapshot view (read-only handle)
# ============================================================================


@dataclass(frozen=True, slots=True)
class Snapshot:
    """A resolved snapshot on disk — manifest parsed, paths verified.

    The measurement payload is **not** loaded eagerly (a ``list_ids``
    pass over hundreds of snapshots would otherwise parse many MBs of
    JSON for nothing). Callers that need it invoke
    :meth:`read_measurement`.
    """

    root: Path
    manifest: SnapshotManifest

    @property
    def measurement_path(self) -> Path:
        return self.root / _MEASUREMENT_NAME

    @property
    def artifacts_dir(self) -> Path:
        return self.root / _ARTIFACTS_DIR

    def read_measurement(self) -> dict[str, Any]:
        """Return the raw ``measurement.json`` payload as a dict."""
        try:
            return json.loads(
                self.measurement_path.read_text(encoding="utf-8")
            )
        except FileNotFoundError as e:
            raise SnapshotCorruptError(
                f"snapshot '{self.manifest.snapshot_id}': "
                f"measurement.json missing at {self.measurement_path}"
            ) from e
        except json.JSONDecodeError as e:
            raise SnapshotCorruptError(
                f"snapshot '{self.manifest.snapshot_id}': "
                f"measurement.json is not valid JSON ({e})"
            ) from e

    def artifact_path(self, filename: str) -> Path:
        """Return the path an artifact with ``filename`` would have.

        Existence is not checked — callers interpret missing artifacts
        however makes sense (some benchmarks may not need them).
        """
        _validate_artifact_name(filename)
        return self.artifacts_dir / filename

    def list_artifacts(self) -> list[Path]:
        """Return every file in the artifacts/ directory, sorted by name."""
        if not self.artifacts_dir.exists():
            return []
        return sorted(
            p for p in self.artifacts_dir.iterdir() if p.is_file()
        )


# ============================================================================
# Store
# ============================================================================


class SnapshotStore:
    """Directory-backed snapshot store.

    Construction only captures ``root`` — no I/O. Directories are
    created on first :meth:`save`.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    def save(
        self,
        *,
        manifest: SnapshotManifest,
        measurement_payload: dict[str, Any],
        artifacts: Iterable[tuple[str, Path]] = (),
    ) -> Snapshot:
        """Persist ``manifest`` + ``measurement_payload`` + ``artifacts``.

        ``artifacts`` is an iterable of ``(destination_name, source_path)``
        pairs. Each source file is copied into ``<snapshot>/artifacts/``
        under ``destination_name``. Filenames must match
        ``_ARTIFACT_NAME_RE`` to block traversal.

        The snapshot lands atomically: everything is written to a
        ``.pending-<id>`` scratch directory first, then renamed to
        ``<id>``. On any failure the scratch directory is removed and
        the exception propagates — callers never see a half-written
        snapshot.

        Raises:
            InvalidSnapshotIdError: ``manifest.snapshot_id`` is malformed.
            InvalidArtifactNameError: any destination name is unsafe.
            SnapshotExistsError: a snapshot with this id already exists.
            OSError: filesystem refused the write.
        """
        _validate_snapshot_id(manifest.snapshot_id)

        final_dir = self._root / manifest.snapshot_id
        if final_dir.exists():
            raise SnapshotExistsError(
                f"snapshot '{manifest.snapshot_id}' already exists at {final_dir}"
            )

        # Normalise + validate artifact names up front so we do not
        # partially copy before hitting an invalid one.
        artifacts_list = [(dest, Path(src)) for dest, src in artifacts]
        for dest, _ in artifacts_list:
            _validate_artifact_name(dest)

        declared_count = manifest.artifact_count
        if declared_count != len(artifacts_list):
            raise ValueError(
                f"manifest.artifact_count={declared_count} does not match "
                f"actual artifacts provided ({len(artifacts_list)})"
            )

        self._root.mkdir(parents=True, exist_ok=True)
        pending = self._root / (_PENDING_PREFIX + manifest.snapshot_id)
        # Stale pending from a previous crash — remove before reusing.
        if pending.exists():
            shutil.rmtree(pending)
        pending.mkdir()

        try:
            (pending / _MANIFEST_NAME).write_text(
                manifest.model_dump_json(indent=2) + "\n", encoding="utf-8",
            )
            (pending / _MEASUREMENT_NAME).write_text(
                json.dumps(measurement_payload, indent=2) + "\n",
                encoding="utf-8",
            )
            art_dir = pending / _ARTIFACTS_DIR
            art_dir.mkdir()
            for dest, src in artifacts_list:
                if not src.exists():
                    raise FileNotFoundError(
                        f"artifact source missing: {src} (→ {dest})"
                    )
                shutil.copy2(src, art_dir / dest)
        except BaseException:
            shutil.rmtree(pending, ignore_errors=True)
            raise

        # os.rename is atomic on the same filesystem; Path.rename
        # raises on cross-device moves which we do not want anyway.
        pending.rename(final_dir)

        _LOG.info(
            "saved snapshot '%s' → %s (%d artifact(s))",
            manifest.snapshot_id, final_dir, len(artifacts_list),
        )
        return Snapshot(root=final_dir, manifest=manifest)

    def load(self, snapshot_id: str) -> Snapshot:
        """Return the resolved :class:`Snapshot` for ``snapshot_id``.

        Raises :class:`SnapshotNotFoundError` when the directory does
        not exist, :class:`SnapshotCorruptError` when it exists but
        the manifest is missing / malformed / carries a schema version
        this MCP cannot read.
        """
        _validate_snapshot_id(snapshot_id)
        snap_dir = self._root / snapshot_id
        if not snap_dir.is_dir():
            raise SnapshotNotFoundError(
                f"snapshot '{snapshot_id}' not found at {snap_dir}"
            )
        return _read_snapshot(snap_dir)

    def list_ids(self) -> list[str]:
        """Return every finalised snapshot id, lexicographically sorted.

        Pending directories (``.pending-*``) and any other dotfiles
        are filtered out so a crashed save does not leak into listings.
        """
        if not self._root.is_dir():
            return []
        return sorted(
            p.name for p in self._root.iterdir()
            if p.is_dir() and not p.name.startswith(".")
        )

    def latest(self) -> Snapshot | None:
        """Return the newest snapshot by id (chronological), or ``None``.

        Because ids start with an ISO-8601 UTC prefix, lexicographic
        order matches chronological order exactly.
        """
        ids = self.list_ids()
        if not ids:
            return None
        return self.load(ids[-1])


# ============================================================================
# Private helpers
# ============================================================================


def _validate_snapshot_id(snapshot_id: str) -> None:
    if not _ID_RE.match(snapshot_id):
        raise InvalidSnapshotIdError(
            f"snapshot id {snapshot_id!r} does not match the accepted grammar "
            f"'YYYY-MM-DDTHH-MM-SSZ_<commit7|nogit>[_dirty]'"
        )


def _validate_artifact_name(name: str) -> None:
    if not _ARTIFACT_NAME_RE.match(name):
        raise InvalidArtifactNameError(
            f"artifact name {name!r} must match {_ARTIFACT_NAME_RE.pattern} "
            f"— path separators, drive colons, and '..' are all rejected"
        )


def _read_snapshot(snap_dir: Path) -> Snapshot:
    """Parse a snapshot directory into a :class:`Snapshot`.

    Extracted so :meth:`SnapshotStore.load` and future read-only
    probes share one well-tested validation path.
    """
    manifest_path = snap_dir / _MANIFEST_NAME
    if not manifest_path.exists():
        raise SnapshotCorruptError(
            f"snapshot at {snap_dir} is missing {_MANIFEST_NAME}"
        )
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SnapshotCorruptError(
            f"snapshot at {snap_dir}: manifest is not valid JSON ({e})"
        ) from e
    try:
        manifest = SnapshotManifest.model_validate(raw)
    except Exception as e:  # pydantic ValidationError + our ValueError
        raise SnapshotCorruptError(
            f"snapshot at {snap_dir}: manifest failed validation ({e})"
        ) from e
    if manifest.snapshot_id != snap_dir.name:
        raise SnapshotCorruptError(
            f"snapshot at {snap_dir}: manifest.snapshot_id={manifest.snapshot_id!r} "
            f"does not match directory name {snap_dir.name!r}"
        )
    return Snapshot(root=snap_dir, manifest=manifest)
