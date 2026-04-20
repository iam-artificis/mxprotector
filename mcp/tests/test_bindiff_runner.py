"""Unit tests for diffing.bindiff.bindiff_runner.

Every external dependency is mocked. Tests cover path-resolution
precedence, command-line shape, stdout-parsing integration (via the
real parser), and every failure mode.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from mx_mcp.diffing.bindiff import bindiff_runner as br
from mx_mcp.diffing.bindiff.bindiff_runner import (
    BINDIFF_PATH_ENV,
    BinDiffNotFoundError,
    BinDiffRunResult,
    resolve_bindiff_path,
    run_bindiff,
)


# ============================================================================
# Path resolution
# ============================================================================


def test_resolve_uses_override(tmp_path: Path):
    exe = tmp_path / "bindiff.exe"
    exe.write_bytes(b"\x4d\x5a")
    assert resolve_bindiff_path(exe) == exe


def test_resolve_env_var_points_at_exe(tmp_path: Path, monkeypatch):
    exe = tmp_path / "bindiff.exe"
    exe.write_bytes(b"\x4d\x5a")
    monkeypatch.setenv(BINDIFF_PATH_ENV, str(exe))
    assert resolve_bindiff_path() == exe


def test_resolve_env_var_points_at_directory(tmp_path: Path, monkeypatch):
    (tmp_path / "bindiff.exe").write_bytes(b"\x4d\x5a")
    monkeypatch.setenv(BINDIFF_PATH_ENV, str(tmp_path))
    assert resolve_bindiff_path() == tmp_path / "bindiff.exe"


def test_resolve_missing_raises(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(BINDIFF_PATH_ENV, raising=False)
    monkeypatch.setattr(br.shutil, "which", lambda _n: None)
    with pytest.raises(BinDiffNotFoundError):
        resolve_bindiff_path()


def test_resolve_env_var_to_nonexistent_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(BINDIFF_PATH_ENV, str(tmp_path / "ghost.exe"))
    with pytest.raises(BinDiffNotFoundError, match="not found at"):
        resolve_bindiff_path()


# ============================================================================
# Fixtures for the scan tests
# ============================================================================


# Minimal valid stdout — contains the one Similarity line parse_report
# strictly requires.
_STUB_STDOUT = (
    "BinDiff 8\n"
    "matched: 10 of 20/22 (primary/secondary, 8/9 non-library)\n"
    "Similarity: 42.3456% (Confidence: 85.0%)\n"
)


def _install_bindiff_exe(tmp_path: Path, monkeypatch) -> Path:
    exe = tmp_path / "bindiff.exe"
    exe.write_bytes(b"\x4d\x5a")
    monkeypatch.setenv(BINDIFF_PATH_ENV, str(exe))
    return exe


def _mock_subprocess(
    monkeypatch, *, returncode: int = 0,
    stdout: str = _STUB_STDOUT, stderr: str = "",
    raises: BaseException | None = None,
    write_artifacts: bool = False,
) -> list[list[str]]:
    """Replace ``_run_subprocess``. Optionally fabricate the output
    artefacts BinDiff would normally write."""
    captured: list[list[str]] = []

    def fake(cmd, timeout_s, cwd):
        captured.append(list(cmd))
        if raises is not None:
            raise raises
        if write_artifacts:
            # Derive paths the runner will subsequently look for.
            primary_arg = next(a for a in cmd if a.startswith("--primary="))
            secondary_arg = next(a for a in cmd if a.startswith("--secondary="))
            outdir_arg = next(a for a in cmd if a.startswith("--output_dir="))
            primary = Path(primary_arg.split("=", 1)[1])
            secondary = Path(secondary_arg.split("=", 1)[1])
            outdir = Path(outdir_arg.split("=", 1)[1])
            base = f"{primary.stem}_vs_{secondary.stem}"
            (outdir / f"{base}.BinDiff").write_bytes(b"sqlite stub")
            (outdir / f"{base}.results").write_text(
                "Function Matches (Non-Library).....: 8\n",
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(
            args=[], returncode=returncode,
            stdout=stdout, stderr=stderr,
        )

    monkeypatch.setattr(br, "_run_subprocess", fake)
    return captured


def _touch_binexport(tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    p.write_bytes(b"stub binexport")
    return p


# ============================================================================
# Happy path
# ============================================================================


def test_run_bindiff_happy_path(tmp_path: Path, monkeypatch):
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "pure_cff_a.BinExport")
    secondary = _touch_binexport(tmp_path, "pure_cff_b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()

    captured = _mock_subprocess(monkeypatch, write_artifacts=True)

    result = asyncio.run(run_bindiff(
        primary, secondary, output_dir=outdir,
    ))

    assert isinstance(result, BinDiffRunResult)
    assert result.ok is True
    assert result.report is not None
    assert result.report.similarity == pytest.approx(0.423456, abs=1e-6)
    # Produced artefacts discovered on disk.
    assert result.bindiff_db_path is not None
    assert result.results_path is not None
    assert result.bindiff_db_path.exists()
    assert result.results_path.exists()
    # Report was augmented with data from the .results file.
    assert result.report.results.function_matches_non_library == 8

    # Command shape.
    assert len(captured) == 1
    cmd = captured[0]
    assert any(c == f"--primary={primary}" for c in cmd)
    assert any(c == f"--secondary={secondary}" for c in cmd)
    assert any(c == f"--output_dir={outdir}" for c in cmd)
    assert "--output_format=log,bin" in cmd


# ============================================================================
# Error paths
# ============================================================================


def test_missing_primary_soft_fails(tmp_path: Path, monkeypatch):
    _install_bindiff_exe(tmp_path, monkeypatch)
    outdir = tmp_path / "out"
    outdir.mkdir()
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    result = asyncio.run(run_bindiff(
        tmp_path / "missing_primary.BinExport",
        secondary, output_dir=outdir,
    ))
    assert result.ok is False
    assert "primary BinExport missing" in (result.error or "")


def test_missing_secondary_soft_fails(tmp_path: Path, monkeypatch):
    _install_bindiff_exe(tmp_path, monkeypatch)
    outdir = tmp_path / "out"
    outdir.mkdir()
    primary = _touch_binexport(tmp_path, "a.BinExport")
    result = asyncio.run(run_bindiff(
        primary, tmp_path / "missing_secondary.BinExport",
        output_dir=outdir,
    ))
    assert result.ok is False
    assert "secondary BinExport missing" in (result.error or "")


def test_missing_output_dir_soft_fails(tmp_path: Path, monkeypatch):
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    result = asyncio.run(run_bindiff(
        primary, secondary, output_dir=tmp_path / "no_such_dir",
    ))
    assert result.ok is False
    assert "output_dir missing" in (result.error or "")


def test_missing_bindiff_exe_soft_fails(tmp_path: Path, monkeypatch):
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()
    monkeypatch.delenv(BINDIFF_PATH_ENV, raising=False)
    monkeypatch.setattr(br.shutil, "which", lambda _n: None)

    result = asyncio.run(run_bindiff(primary, secondary, output_dir=outdir))
    assert result.ok is False
    assert "bindiff.exe not found" in (result.error or "")


def test_nonzero_exit_soft_fails(tmp_path: Path, monkeypatch):
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()
    _mock_subprocess(monkeypatch, returncode=3, stderr="kaput")

    result = asyncio.run(run_bindiff(primary, secondary, output_dir=outdir))
    assert result.ok is False
    assert "exit=3" in (result.error or "")
    assert "kaput" in result.stderr_tail


def test_timeout_soft_fails(tmp_path: Path, monkeypatch):
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()
    _mock_subprocess(
        monkeypatch,
        raises=subprocess.TimeoutExpired(cmd=["bindiff"], timeout=1.0),
    )

    result = asyncio.run(run_bindiff(
        primary, secondary, output_dir=outdir, timeout_s=1.0,
    ))
    assert result.ok is False
    assert "timed out" in (result.error or "")


def test_no_similarity_line_soft_fails(tmp_path: Path, monkeypatch):
    """BinDiff produced output but stdout lacked a Similarity line.
    Treat as a soft fail so benchmarks do not record None silently."""
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()
    _mock_subprocess(
        monkeypatch,
        stdout="BinDiff 8 initialised but did nothing useful",
        write_artifacts=True,
    )

    result = asyncio.run(run_bindiff(primary, secondary, output_dir=outdir))
    assert result.ok is False
    assert "Similarity line" in (result.error or "")
    # Report still present — caller can inspect partial data.
    assert result.report is not None


def test_artifacts_missing_after_success(tmp_path: Path, monkeypatch):
    """BinDiff returned 0 and emitted a proper stdout line but left
    no .BinDiff / .results on disk. Report parses from stdout alone;
    artefact paths stay None so callers know they cannot archive."""
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()
    _mock_subprocess(monkeypatch, write_artifacts=False)

    result = asyncio.run(run_bindiff(primary, secondary, output_dir=outdir))
    assert result.ok is True
    assert result.bindiff_db_path is None
    assert result.results_path is None
    assert result.report is not None
    assert result.report.similarity == pytest.approx(0.423456, abs=1e-6)
    # But results stats are defaults (no file to read).
    assert result.report.results.function_matches_non_library == 0


def test_run_bindiff_never_raises(tmp_path: Path, monkeypatch):
    """Contract: every failure mode returns structured result, never
    propagates."""
    _install_bindiff_exe(tmp_path, monkeypatch)
    primary = _touch_binexport(tmp_path, "a.BinExport")
    secondary = _touch_binexport(tmp_path, "b.BinExport")
    outdir = tmp_path / "out"
    outdir.mkdir()
    _mock_subprocess(monkeypatch, raises=OSError("disk bombed"))

    # Must not raise.
    result = asyncio.run(run_bindiff(primary, secondary, output_dir=outdir))
    assert result.ok is False
    assert "failed to start" in (result.error or "")
