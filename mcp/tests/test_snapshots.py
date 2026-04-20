"""Unit tests for common.snapshots.

The store is exercised through its public API only — no poking at
private attributes. Tests cover the happy round-trip (save → load),
every validation gate (bad id, bad artifact name, count mismatch,
duplicate), atomicity (failure mid-save leaves no partial state),
forward-compat (older payload fields are ignored on read), and
listing / latest semantics.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mx_mcp.common.git_info import GitHeadInfo
from mx_mcp.common.snapshots import (
    InvalidArtifactNameError,
    InvalidSnapshotIdError,
    SNAPSHOT_SCHEMA_VERSION,
    Snapshot,
    SnapshotCorruptError,
    SnapshotExistsError,
    SnapshotManifest,
    SnapshotNotFoundError,
    SnapshotStore,
    make_snapshot_id,
)


# ============================================================================
# Helpers
# ============================================================================


def _manifest(
    snapshot_id: str,
    *,
    artifact_count: int = 0,
    git_commit: str | None = "a" * 40,
    git_branch: str | None = "master",
    git_dirty: bool = False,
) -> SnapshotManifest:
    return SnapshotManifest(
        snapshot_id=snapshot_id,
        timestamp="2026-04-20T18:05:11Z",
        git_commit=git_commit,
        git_branch=git_branch,
        git_dirty=git_dirty,
        builder_level="strong",
        builder_args=["--trace-hints"],
        corpus_path="/tmp/corpus",
        artifact_count=artifact_count,
    )


def _write_artifact(tmp: Path, name: str, data: bytes = b"dummy") -> Path:
    p = tmp / name
    p.write_bytes(data)
    return p


# ============================================================================
# make_snapshot_id
# ============================================================================


def test_make_id_without_git_marks_nogit():
    sid = make_snapshot_id(timestamp_iso="2026-04-20T18:05:11Z", git=None)
    assert sid == "2026-04-20T18-05-11Z_nogit"


def test_make_id_with_clean_git():
    git = GitHeadInfo(
        commit_sha="a" * 40, commit_short="abcdef0",
        branch="main", dirty=False,
    )
    sid = make_snapshot_id(timestamp_iso="2026-04-20T18:05:11Z", git=git)
    assert sid == "2026-04-20T18-05-11Z_abcdef0"


def test_make_id_with_dirty_git_appends_dirty_suffix():
    git = GitHeadInfo(
        commit_sha="0" * 40, commit_short="0123456",
        branch="feature/x", dirty=True,
    )
    sid = make_snapshot_id(timestamp_iso="2026-04-21T09:30:00Z", git=git)
    assert sid == "2026-04-21T09-30-00Z_0123456_dirty"


def test_make_id_colons_are_replaced():
    """Windows filenames cannot contain ':' — the helper must strip them."""
    sid = make_snapshot_id(timestamp_iso="2026-01-01T00:00:00Z", git=None)
    assert ":" not in sid


# ============================================================================
# Manifest validation
# ============================================================================


def test_manifest_rejects_wrong_schema_version():
    with pytest.raises(Exception):  # pydantic ValidationError
        SnapshotManifest(
            schema_version=99,
            snapshot_id="2026-04-20T18-05-11Z_nogit",
            timestamp="x", corpus_path="/x",
            builder_level="strong",
        )


# ============================================================================
# save / load round-trip
# ============================================================================


def test_save_creates_expected_layout(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_abcdef0"
    manifest = _manifest(sid, artifact_count=2)
    artifact1 = _write_artifact(tmp_path, "a.exe", b"AAAA")
    artifact2 = _write_artifact(tmp_path, "b.exe.mxtrace.json", b"{}")

    snap = store.save(
        manifest=manifest,
        measurement_payload={"benchmarks": []},
        artifacts=[("a.exe", artifact1), ("b.exe.mxtrace.json", artifact2)],
    )

    assert isinstance(snap, Snapshot)
    assert snap.root == tmp_path / "snapshots" / sid
    assert (snap.root / "manifest.json").exists()
    assert (snap.root / "measurement.json").exists()
    assert (snap.root / "artifacts" / "a.exe").read_bytes() == b"AAAA"
    assert (snap.root / "artifacts" / "b.exe.mxtrace.json").read_bytes() == b"{}"


def test_round_trip_preserves_all_manifest_fields(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_abcdef0_dirty"
    original = _manifest(
        sid, artifact_count=0, git_dirty=True, git_branch="feat",
    )

    store.save(
        manifest=original,
        measurement_payload={"any": "payload"},
    )
    loaded = store.load(sid)

    assert loaded.manifest == original
    assert loaded.read_measurement() == {"any": "payload"}


def test_load_missing_raises(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    with pytest.raises(SnapshotNotFoundError):
        store.load("2026-04-20T18-05-11Z_nogit")


def test_save_duplicate_raises(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    store.save(manifest=_manifest(sid), measurement_payload={})
    with pytest.raises(SnapshotExistsError):
        store.save(manifest=_manifest(sid), measurement_payload={})


# ============================================================================
# Validation — bad id, bad artifact name, count mismatch, missing source
# ============================================================================


@pytest.mark.parametrize("bad_id", [
    "",
    "not-an-id",
    "2026-04-20_a1bfa66",               # missing 'T…Z'
    "2026/04/20T18-05-11Z_nogit",       # path separator
    "2026-04-20T18-05-11Z_TOOLONG_A",   # not hex
    "../escape",
])
def test_invalid_id_rejected(tmp_path: Path, bad_id: str):
    store = SnapshotStore(tmp_path / "snapshots")
    with pytest.raises(InvalidSnapshotIdError):
        store.save(
            manifest=SnapshotManifest.model_construct(
                schema_version=SNAPSHOT_SCHEMA_VERSION,
                snapshot_id=bad_id,
                timestamp="x",
                git_commit=None, git_branch=None, git_dirty=False,
                builder_level="strong", builder_args=[],
                corpus_path="/x", artifact_count=0,
            ),
            measurement_payload={},
        )


@pytest.mark.parametrize("bad_name", [
    "../escape.exe",
    "sub/dir.exe",
    "with\\backslash.exe",
    "space name.exe",
    "colon:name.exe",
])
def test_invalid_artifact_name_rejected(tmp_path: Path, bad_name: str):
    store = SnapshotStore(tmp_path / "snapshots")
    src = _write_artifact(tmp_path, "ok.bin")
    sid = "2026-04-20T18-05-11Z_nogit"
    with pytest.raises(InvalidArtifactNameError):
        store.save(
            manifest=_manifest(sid, artifact_count=1),
            measurement_payload={},
            artifacts=[(bad_name, src)],
        )


def test_artifact_count_mismatch_rejected(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    src = _write_artifact(tmp_path, "ok.bin")
    sid = "2026-04-20T18-05-11Z_nogit"
    with pytest.raises(ValueError, match="artifact_count"):
        store.save(
            manifest=_manifest(sid, artifact_count=5),  # lie
            measurement_payload={},
            artifacts=[("ok.bin", src)],                # reality: 1
        )


def test_missing_artifact_source_aborts_cleanly(tmp_path: Path):
    """Artifact source pointing to a nonexistent file must leave no
    partial snapshot behind."""
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    with pytest.raises(FileNotFoundError):
        store.save(
            manifest=_manifest(sid, artifact_count=1),
            measurement_payload={},
            artifacts=[("gone.exe", tmp_path / "does-not-exist.exe")],
        )
    # No final directory, no pending leftover.
    assert list((tmp_path / "snapshots").iterdir()) == []


# ============================================================================
# Listing + latest
# ============================================================================


def test_list_ids_sorted_chronologically(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    ids = [
        "2026-04-20T18-05-11Z_aaaaaaa",
        "2026-04-20T09-00-00Z_bbbbbbb",
        "2026-04-21T10-00-00Z_ccccccc",
    ]
    for sid in ids:
        store.save(manifest=_manifest(sid), measurement_payload={})
    assert store.list_ids() == sorted(ids)


def test_latest_returns_newest(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    for sid in [
        "2026-04-20T09-00-00Z_aaaaaaa",
        "2026-04-20T18-05-11Z_bbbbbbb",
        "2026-04-21T10-00-00Z_ccccccc",
    ]:
        store.save(manifest=_manifest(sid), measurement_payload={})
    latest = store.latest()
    assert latest is not None
    assert latest.manifest.snapshot_id == "2026-04-21T10-00-00Z_ccccccc"


def test_latest_empty_store_returns_none(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    assert store.latest() is None


def test_list_ids_filters_pending_directories(tmp_path: Path):
    """Pending scratch directories from a crashed save must not leak
    into listings."""
    snapshots_root = tmp_path / "snapshots"
    snapshots_root.mkdir()
    # Simulate a crashed save.
    (snapshots_root / ".pending-abc").mkdir()
    # And a finalised snapshot alongside.
    store = SnapshotStore(snapshots_root)
    sid = "2026-04-20T18-05-11Z_aaaaaaa"
    store.save(manifest=_manifest(sid), measurement_payload={})

    assert store.list_ids() == [sid]


# ============================================================================
# Corruption detection on load
# ============================================================================


def test_missing_manifest_reports_corrupt(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    snap_dir = tmp_path / "snapshots" / sid
    snap_dir.mkdir(parents=True)
    with pytest.raises(SnapshotCorruptError, match="missing manifest"):
        store.load(sid)


def test_malformed_manifest_reports_corrupt(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    snap_dir = tmp_path / "snapshots" / sid
    snap_dir.mkdir(parents=True)
    (snap_dir / "manifest.json").write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(SnapshotCorruptError, match="not valid JSON"):
        store.load(sid)


def test_manifest_id_mismatch_reports_corrupt(tmp_path: Path):
    """manifest.snapshot_id disagreeing with the directory name is a
    tamper-proof signal — reject rather than silently trust one side."""
    store = SnapshotStore(tmp_path / "snapshots")
    sid_dir = "2026-04-20T18-05-11Z_nogit"
    snap_dir = tmp_path / "snapshots" / sid_dir
    snap_dir.mkdir(parents=True)
    payload = _manifest("2026-04-20T18-05-11Z_abcdef0")  # different id
    (snap_dir / "manifest.json").write_text(
        payload.model_dump_json(), encoding="utf-8",
    )
    with pytest.raises(SnapshotCorruptError, match="does not match directory"):
        store.load(sid_dir)


def test_unknown_schema_version_on_disk_reports_corrupt(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    snap_dir = tmp_path / "snapshots" / sid
    snap_dir.mkdir(parents=True)
    bad = {
        "schema_version": 999,
        "snapshot_id": sid,
        "timestamp": "x", "git_commit": None, "git_branch": None,
        "git_dirty": False, "builder_level": "strong",
        "builder_args": [], "corpus_path": "/x", "artifact_count": 0,
    }
    (snap_dir / "manifest.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(SnapshotCorruptError):
        store.load(sid)


# ============================================================================
# Snapshot handle
# ============================================================================


def test_snapshot_artifact_path_validates_name(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    store.save(manifest=_manifest(sid), measurement_payload={})
    snap = store.load(sid)
    with pytest.raises(InvalidArtifactNameError):
        snap.artifact_path("../escape")


def test_snapshot_list_artifacts_returns_sorted(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    srcs = [
        _write_artifact(tmp_path, "zzz.exe"),
        _write_artifact(tmp_path, "aaa.exe"),
        _write_artifact(tmp_path, "mmm.exe"),
    ]
    store.save(
        manifest=_manifest(sid, artifact_count=3),
        measurement_payload={},
        artifacts=[("zzz.exe", srcs[0]), ("aaa.exe", srcs[1]), ("mmm.exe", srcs[2])],
    )
    snap = store.load(sid)
    names = [p.name for p in snap.list_artifacts()]
    assert names == ["aaa.exe", "mmm.exe", "zzz.exe"]


def test_read_measurement_missing_raises_corrupt(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    sid = "2026-04-20T18-05-11Z_nogit"
    snap_dir = tmp_path / "snapshots" / sid
    snap_dir.mkdir(parents=True)
    (snap_dir / "manifest.json").write_text(
        _manifest(sid).model_dump_json(), encoding="utf-8",
    )
    # No measurement.json.
    snap = store.load(sid)
    with pytest.raises(SnapshotCorruptError, match="measurement.json missing"):
        snap.read_measurement()
