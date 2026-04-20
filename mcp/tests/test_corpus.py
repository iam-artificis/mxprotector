"""Unit tests for common.corpus: manifest loading, filtering, validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mx_mcp.common.corpus import (
    CORPUS_SCHEMA_VERSION,
    Corpus,
    CorpusLoadError,
)


def _write_manifest(root: Path, entries: list[dict], version: int = 1) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "corpus.json").write_text(
        json.dumps({"schema_version": version, "entries": entries}),
        encoding="utf-8",
    )


def _touch_binary(root: Path, rel: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x4d\x5a")  # stub MZ — contents don't matter for tests
    return path


# ============================================================================
# load / validation
# ============================================================================


def test_load_rejects_missing_manifest(tmp_path: Path):
    with pytest.raises(CorpusLoadError, match="corpus manifest missing"):
        Corpus.load(tmp_path)


def test_load_rejects_unsupported_schema_version(tmp_path: Path):
    _write_manifest(tmp_path, [], version=999)
    with pytest.raises(CorpusLoadError, match="unsupported corpus schema"):
        Corpus.load(tmp_path)


def test_load_reports_missing_binaries(tmp_path: Path):
    _write_manifest(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": ["vm"]},
        {"name": "b", "binary": "bin/b.exe", "tags": ["cff"]},
    ])
    with pytest.raises(CorpusLoadError, match="corpus binaries missing"):
        Corpus.load(tmp_path)


def test_load_rejects_duplicate_entry_names(tmp_path: Path):
    _touch_binary(tmp_path, "bin/a.exe")
    _write_manifest(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": ["vm"]},
        {"name": "a", "binary": "bin/a.exe", "tags": ["cff"]},
    ])
    with pytest.raises(CorpusLoadError, match="duplicate corpus entry"):
        Corpus.load(tmp_path)


def test_load_rejects_invalid_json(tmp_path: Path):
    (tmp_path / "corpus.json").write_text("not json", encoding="utf-8")
    with pytest.raises(CorpusLoadError, match="failed to parse"):
        Corpus.load(tmp_path)


def test_load_populates_entries(tmp_path: Path):
    _touch_binary(tmp_path, "bin/a.exe")
    _touch_binary(tmp_path, "bin/b.exe")
    _write_manifest(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm", "pure"]},
        {"name": "beta", "binary": "bin/b.exe", "tags": ["cff"]},
    ])
    corpus = Corpus.load(tmp_path)
    assert len(corpus) == 2
    assert {e.name for e in corpus} == {"alpha", "beta"}
    assert corpus.tags() == frozenset({"vm", "pure", "cff"})


# ============================================================================
# Accessors & filtering
# ============================================================================


@pytest.fixture()
def populated_corpus(tmp_path: Path) -> Corpus:
    _touch_binary(tmp_path, "bin/a.exe")
    _touch_binary(tmp_path, "bin/b.exe")
    _touch_binary(tmp_path, "bin/c.exe")
    _write_manifest(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm", "pure"]},
        {"name": "beta",  "binary": "bin/b.exe", "tags": ["cff", "pure"]},
        {"name": "gamma", "binary": "bin/c.exe", "tags": ["vm", "cff", "mixed"]},
    ])
    return Corpus.load(tmp_path)


def test_by_name_returns_entry(populated_corpus: Corpus):
    entry = populated_corpus.by_name("alpha")
    assert entry.name == "alpha"
    assert entry.tags == frozenset({"vm", "pure"})


def test_by_name_raises_keyerror_on_miss(populated_corpus: Corpus):
    with pytest.raises(KeyError):
        populated_corpus.by_name("nope")


def test_with_tags_match_any(populated_corpus: Corpus):
    names = {e.name for e in populated_corpus.with_tags("vm")}
    assert names == {"alpha", "gamma"}


def test_with_tags_match_all(populated_corpus: Corpus):
    names = {e.name for e in populated_corpus.with_tags("vm", "cff", match_all=True)}
    assert names == {"gamma"}


def test_with_tags_empty_returns_all(populated_corpus: Corpus):
    # No tag argument → every entry.
    assert len(populated_corpus.with_tags()) == 3


def test_iter_preserves_manifest_order(populated_corpus: Corpus):
    assert [e.name for e in populated_corpus] == ["alpha", "beta", "gamma"]


def test_schema_version_constant_matches_manifest_acceptance(tmp_path: Path):
    """Guard: if CORPUS_SCHEMA_VERSION bumps, the manifest's Annotated
    bound should bump in lockstep."""
    # Sanity: version 1 is accepted.
    _touch_binary(tmp_path, "bin/a.exe")
    _write_manifest(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": []},
    ], version=CORPUS_SCHEMA_VERSION)
    corpus = Corpus.load(tmp_path)
    assert len(corpus) == 1


# ============================================================================
# Pre-protected entries — legacy binaries the current builder did not
# produce. Benchmarks that do not need a sidecar (P3 pe-sieve and
# later) use them for "then vs now" comparisons.
# ============================================================================


def test_pre_protected_only_entry_loads(tmp_path: Path):
    _touch_binary(tmp_path, "legacy/old.exe.packed")
    _write_manifest(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe.packed",
         "tags": ["packer", "exe"]},
    ])
    corpus = Corpus.load(tmp_path)
    entry = corpus.by_name("legacy")
    assert entry.unprotected_binary is None
    assert entry.pre_protected_binary is not None
    assert entry.pre_protected_binary.name == "old.exe.packed"
    assert entry.pre_sidecar is None
    assert entry.is_pre_protected is True


def test_pre_protected_with_sidecar(tmp_path: Path):
    _touch_binary(tmp_path, "legacy/old.exe")
    _touch_binary(tmp_path, "legacy/old.exe.mxtrace.json")
    _write_manifest(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe",
         "pre_sidecar": "legacy/old.exe.mxtrace.json", "tags": ["exe"]},
    ])
    corpus = Corpus.load(tmp_path)
    entry = corpus.by_name("legacy")
    assert entry.pre_sidecar is not None
    assert entry.pre_sidecar.name == "old.exe.mxtrace.json"


def test_mixed_buildable_plus_preprotected(tmp_path: Path):
    _touch_binary(tmp_path, "bin/fresh.exe")
    _touch_binary(tmp_path, "legacy/old.exe.packed")
    _write_manifest(tmp_path, [
        {"name": "fresh",  "binary": "bin/fresh.exe", "tags": ["vm"]},
        {"name": "legacy", "pre_protected": "legacy/old.exe.packed",
         "tags": ["packer"]},
    ])
    corpus = Corpus.load(tmp_path)
    assert corpus.by_name("fresh").is_pre_protected is False
    assert corpus.by_name("legacy").is_pre_protected is True


def test_entry_with_both_binary_and_pre_protected(tmp_path: Path):
    """Allowed: the unprotected path is kept for provenance, the
    benchmark prefers the pre-protected one."""
    _touch_binary(tmp_path, "bin/src.exe")
    _touch_binary(tmp_path, "legacy/built.exe.packed")
    _write_manifest(tmp_path, [
        {"name": "both", "binary": "bin/src.exe",
         "pre_protected": "legacy/built.exe.packed", "tags": []},
    ])
    corpus = Corpus.load(tmp_path)
    entry = corpus.by_name("both")
    assert entry.unprotected_binary is not None
    assert entry.pre_protected_binary is not None
    assert entry.is_pre_protected is True  # pre-protected wins routing.


def test_entry_without_any_source_rejected(tmp_path: Path):
    """CorpusEntrySpec.model_validator fires — neither binary nor
    pre_protected → manifest is structurally invalid."""
    (tmp_path / "corpus.json").write_text(
        json.dumps({
            "schema_version": CORPUS_SCHEMA_VERSION,
            "entries": [{"name": "nothing", "tags": ["vm"]}],
        }),
        encoding="utf-8",
    )
    with pytest.raises(CorpusLoadError):
        Corpus.load(tmp_path)


def test_missing_pre_protected_file_reported(tmp_path: Path):
    """A non-existent pre_protected path must surface in the 'missing'
    aggregate so fixing the manifest is actionable."""
    _write_manifest(tmp_path, [
        {"name": "gone", "pre_protected": "legacy/does_not_exist.exe",
         "tags": []},
    ])
    with pytest.raises(CorpusLoadError, match="pre_protected"):
        Corpus.load(tmp_path)


def test_missing_pre_sidecar_reported(tmp_path: Path):
    _touch_binary(tmp_path, "legacy/old.exe")
    _write_manifest(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe",
         "pre_sidecar": "legacy/missing.mxtrace.json", "tags": []},
    ])
    with pytest.raises(CorpusLoadError, match="pre_sidecar"):
        Corpus.load(tmp_path)
