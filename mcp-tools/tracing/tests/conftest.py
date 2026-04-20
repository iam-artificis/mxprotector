"""Shared pytest fixtures.

Every test that needs a protected PE + sidecar consumes
``traced_fixture``. The fixture is session-scoped — we build once and
reuse across the whole test run.

Tests that need Frida consume the ``frida_available`` fixture; if the
host lacks a working Frida (rare — installed via pip) the test is
skipped rather than failed.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class TracedFixture:
    binary: Path
    sidecar: Path


def _repo_root() -> Path:
    # this file: mcp-tools/tracing/tests/conftest.py → 3 levels up
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return _repo_root()


@pytest.fixture(scope="session")
def builder_exe(repo_root: Path) -> Path:
    exe = (
        repo_root / "build" / "src" / "builder" / "Release"
        / "mxprotector_builder.exe"
    )
    if not exe.exists():
        pytest.skip(f"builder not built at {exe}")
    return exe


@pytest.fixture(scope="session")
def input_pe(repo_root: Path) -> Path:
    pe = repo_root / "build_testapp" / "test_vm_showcase.exe"
    if not pe.exists():
        pytest.skip(f"test binary not built at {pe}")
    return pe


@pytest.fixture(scope="session")
def traced_fixture(
    tmp_path_factory: pytest.TempPathFactory,
    repo_root: Path,
    builder_exe: Path,
    input_pe: Path,
) -> TracedFixture:
    tmp = tmp_path_factory.mktemp("traced")
    output = tmp / "protected.exe"
    proc = subprocess.run(
        [
            str(builder_exe),
            "-i", str(input_pe),
            "-o", str(output),
            "-l", "strong",
            "--trace-hints",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(repo_root),
    )
    assert proc.returncode == 0, (
        f"builder failed ({proc.returncode}):\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    sidecar = Path(f"{output}.mxtrace.json")
    assert sidecar.exists(), (
        f"sidecar not produced at {sidecar}; builder stdout:\n{proc.stdout}"
    )
    return TracedFixture(binary=output, sidecar=sidecar)


@pytest.fixture(scope="session")
def frida_available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except Exception:
        return False
