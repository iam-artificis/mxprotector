"""Unit tests for common.git_info.

Two flavours: a live-repo smoke (this repo's own HEAD) plus a battery
of mocked-subprocess tests that exercise every failure mode without
shelling out.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from mx_mcp.common import git_info
from mx_mcp.common.git_info import GitHeadInfo, read_git_head


# ============================================================================
# Live-repo smoke — proves the happy path end-to-end.
# ============================================================================


def test_live_repo_returns_populated_info(repo_root: Path):
    info = read_git_head(repo_root)
    if info is None:
        pytest.skip("git unavailable in test environment")
    assert len(info.commit_sha) == 40
    assert info.commit_short == info.commit_sha[:7]
    # We cannot assert a particular branch name because CI may run on
    # detached HEAD. Just that the field is either None or non-empty.
    if info.branch is not None:
        assert info.branch != ""
    assert isinstance(info.dirty, bool)


def test_non_git_directory_returns_none(tmp_path: Path):
    # tmp_path is a scratch directory, never a git repo under pytest.
    assert read_git_head(tmp_path) is None


# ============================================================================
# Mocked-subprocess battery — each test controls the exact git output.
# ============================================================================


@pytest.fixture
def _mock_git(monkeypatch: pytest.MonkeyPatch):
    """Yield a context that replaces ``subprocess.run`` inside ``git_info``.

    The injected fake dispatches by git subcommand name and returns
    ``subprocess.CompletedProcess``-shaped objects. Tests supply a
    dictionary ``{subcmd: (returncode, stdout, stderr)}``.
    """
    responses: dict[str, tuple[int, str, str]] = {}
    raised: dict[str, BaseException] = {}
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        subcmd = argv[1]  # e.g. "rev-parse", "status"
        if subcmd in raised:
            raise raised[subcmd]
        rc, out, err = responses.get(subcmd, (0, "", ""))
        return SimpleNamespace(
            returncode=rc, stdout=out, stderr=err,
        )

    monkeypatch.setattr(git_info.subprocess, "run", fake_run)

    return SimpleNamespace(responses=responses, raised=raised, calls=calls)


def test_returns_none_when_git_missing(_mock_git, tmp_path: Path):
    _mock_git.raised["rev-parse"] = FileNotFoundError("git")
    assert read_git_head(tmp_path) is None


def test_returns_none_when_rev_parse_exits_nonzero(_mock_git, tmp_path: Path):
    _mock_git.responses["rev-parse"] = (128, "", "fatal: not a git repo")
    assert read_git_head(tmp_path) is None


def test_returns_none_on_timeout(_mock_git, tmp_path: Path):
    _mock_git.raised["rev-parse"] = subprocess.TimeoutExpired(
        cmd=["git", "rev-parse"], timeout=5.0,
    )
    assert read_git_head(tmp_path) is None


def test_happy_path_clean_tree(_mock_git, tmp_path: Path):
    sha = "abcdef0123456789abcdef0123456789abcdef01"
    # First call is rev-parse HEAD; second is rev-parse --abbrev-ref HEAD.
    # The fake dispatches by subcommand, so we have to differentiate.
    def fake_run(argv, **kwargs):
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=sha + "\n", stderr="")
        if argv[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout="master\n", stderr="")
        if argv[1] == "status":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected git argv: {argv}")

    # Override the fixture's dispatcher for finer control.
    import pytest as _p
    monkeypatch = _p.MonkeyPatch()
    monkeypatch.setattr(git_info.subprocess, "run", fake_run)
    try:
        info = read_git_head(tmp_path)
    finally:
        monkeypatch.undo()

    assert info is not None
    assert info.commit_sha == sha
    assert info.commit_short == sha[:7]
    assert info.branch == "master"
    assert info.dirty is False


def test_detached_head_sets_branch_none(tmp_path: Path):
    sha = "1234567abcdef1234567abcdef1234567abcdef0"

    def fake_run(argv, **kwargs):
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=sha + "\n", stderr="")
        if argv[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            # Detached HEAD → git emits the literal sentinel "HEAD".
            return SimpleNamespace(returncode=0, stdout="HEAD\n", stderr="")
        if argv[1] == "status":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected git argv: {argv}")

    import pytest as _p
    monkeypatch = _p.MonkeyPatch()
    monkeypatch.setattr(git_info.subprocess, "run", fake_run)
    try:
        info = read_git_head(tmp_path)
    finally:
        monkeypatch.undo()

    assert info is not None
    assert info.branch is None
    assert info.commit_sha == sha


def test_dirty_tree_sets_dirty_true(tmp_path: Path):
    sha = "0000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def fake_run(argv, **kwargs):
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=sha + "\n", stderr="")
        if argv[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout="feature/x\n", stderr="")
        if argv[1] == "status":
            return SimpleNamespace(
                returncode=0,
                stdout=" M mcp/src/mx_mcp/common/git_info.py\n?? mcp/tests/new.py\n",
                stderr="",
            )
        raise AssertionError(f"unexpected git argv: {argv}")

    import pytest as _p
    monkeypatch = _p.MonkeyPatch()
    monkeypatch.setattr(git_info.subprocess, "run", fake_run)
    try:
        info = read_git_head(tmp_path)
    finally:
        monkeypatch.undo()

    assert info is not None
    assert info.dirty is True
    assert info.branch == "feature/x"


def test_status_failure_returns_none_even_if_rev_parse_worked(tmp_path: Path):
    """A failing ``git status`` is treated as an opaque repo problem —
    we would rather have no info than half-populated info (silent
    incorrectness)."""
    def fake_run(argv, **kwargs):
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return SimpleNamespace(
                returncode=0,
                stdout="aa" * 20 + "\n", stderr="",
            )
        if argv[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout="main\n", stderr="")
        if argv[1] == "status":
            return SimpleNamespace(returncode=128, stdout="", stderr="broken")
        raise AssertionError(f"unexpected git argv: {argv}")

    import pytest as _p
    monkeypatch = _p.MonkeyPatch()
    monkeypatch.setattr(git_info.subprocess, "run", fake_run)
    try:
        info = read_git_head(tmp_path)
    finally:
        monkeypatch.undo()

    assert info is None


def test_githead_info_is_immutable():
    info = GitHeadInfo(
        commit_sha="a" * 40, commit_short="a" * 7, branch="main", dirty=False,
    )
    with pytest.raises(Exception):  # dataclass(frozen=True) raises FrozenInstanceError
        info.dirty = True  # type: ignore[misc]
