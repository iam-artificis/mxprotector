"""Unit tests for benchmarks.packer_benchmark.

Mocks both ``ensure_protected`` (to avoid invoking the real builder)
and ``run_pesieve`` (to avoid launching / scanning real processes) at
the benchmark module level. Each mocked ``run_pesieve`` is keyed by
corpus entry name so tests can inject different outcomes per entry.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import packer_benchmark as pb
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.unpacking.pe_sieve.report import (
    DumpedCounts,
    DumpReport,
    ModifiedCounts,
    PesieveReport,
    ScannedCounts,
    ScanReport,
)
from mx_mcp.unpacking.pe_sieve.runner import PesieveRunResult


# ============================================================================
# Corpus helper — supports both buildable and pre_protected entries.
# ============================================================================


def _make_corpus(
    tmp_path: Path,
    entries: list[dict],
) -> Corpus:
    """Write a corpus manifest with the given raw entry dicts.

    Each dict must have ``name`` + ``tags`` plus either ``binary`` or
    ``pre_protected`` (or both). Binary paths are realised on disk as
    stub files so the loader's existence check passes.
    """
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    for spec in entries:
        for key in ("binary", "pre_protected", "pre_sidecar"):
            if key in spec:
                p = corpus_root / spec[key]
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_bytes(b"\x4d\x5a")
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return Corpus.load(corpus_root)


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


# ============================================================================
# Mock factories
# ============================================================================


def _make_report(
    *, pid: int = 1, dumped: int = 0,
    implanted_pe: int = 0, modified_total: int = 0,
) -> PesieveReport:
    return PesieveReport(
        scan_report=ScanReport(
            pid=pid,
            main_image_path="C:\\t.exe",
            scanner_version="test",
            scanned=ScannedCounts(
                total=10, skipped=0,
                modified=ModifiedCounts(
                    total=modified_total, implanted_pe=implanted_pe,
                ),
            ),
        ),
        dump_report=DumpReport(
            pid=pid,
            output_dir=f"process_{pid}",
            dumped=DumpedCounts(total=dumped, dumped=dumped),
            dumps=[],
        ),
    )


def _ok_result(**counts) -> PesieveRunResult:
    return PesieveRunResult(
        ok=True, duration_ms=10,
        report=_make_report(**counts),
        dump_files=[], error=None,
    )


def _err_result(error: str) -> PesieveRunResult:
    return PesieveRunResult(
        ok=False, duration_ms=5, report=None, error=error,
    )


def _install_mocks(
    monkeypatch,
    *,
    build_map: dict[str, ProtectedBuild | Exception] | None = None,
    run_map: dict[str, PesieveRunResult | Exception] | None = None,
) -> dict:
    """Install fakes keyed by entry name.

    ``build_map`` overrides ``ensure_protected``'s return / raise per
    entry; ``run_map`` overrides ``run_pesieve`` per entry.
    """
    build_calls: list[tuple[str, Path]] = []
    run_calls: list[tuple[str, list[str] | None]] = []

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append((entry.name, output_dir))
        behaviour = (build_map or {}).get(entry.name)
        if isinstance(behaviour, Exception):
            raise behaviour
        if behaviour is not None:
            return behaviour
        # Default: stub output.
        output = output_dir / f"{entry.name}.mx.exe"
        output.write_bytes(b"\x4d\x5a")
        sidecar = output.parent / f"{output.name}.mxtrace.json"
        sidecar.write_text('{"schema_version":1}', encoding="utf-8")
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=(entry.pre_protected_binary or output),
            sidecar_path=sidecar if entry.unprotected_binary else None,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    async def fake_run(*, binary, workdir, child_args=None, **kw):
        # Recover the entry name from the workdir (``pesieve_<name>``).
        name = workdir.name.removeprefix("pesieve_")
        run_calls.append((name, list(child_args) if child_args else None))
        behaviour = (run_map or {}).get(name)
        if isinstance(behaviour, Exception):
            raise behaviour
        if behaviour is not None:
            return behaviour
        # Default: clean scan — no dumps, no implants, no modifications.
        return _ok_result()

    monkeypatch.setattr(pb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(pb, "run_pesieve", fake_run)
    monkeypatch.setattr(
        pb, "resolve_builder_path",
        lambda root: root / "fake_builder.exe",
    )
    return {"build_calls": build_calls, "run_calls": run_calls}


# ============================================================================
# Happy path
# ============================================================================


def test_happy_path_single_buildable_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["packer", "exe"]},
    ])
    _install_mocks(
        monkeypatch,
        run_map={"alpha": _ok_result(dumped=0, implanted_pe=0, modified_total=2)},
    )
    bench = pb.PackerPeSieveBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.benchmark == "packer_pesieve"
    assert result.category == "packer"
    assert result.errors == []
    assert len(result.metrics) == 3
    for m in result.metrics:
        assert m.direction is MetricDirection.LOWER_BETTER
        assert len(m.samples) == 1
    by_name = {m.name: m for m in result.metrics}
    assert by_name["pesieve_dumped_modules"].samples[0].value == 0
    assert by_name["pesieve_implanted_pe"].samples[0].value == 0
    assert by_name["pesieve_modified_total"].samples[0].value == 2


def test_happy_path_mixed_fresh_and_legacy(tmp_path: Path, monkeypatch):
    """Buildable + pre_protected entries both produce samples; the
    pe-sieve runner is called once per entry."""
    corpus = _make_corpus(tmp_path, [
        {"name": "fresh", "binary": "bin/fresh.exe",
         "tags": ["packer", "exe"]},
        {"name": "legacy",
         "pre_protected": "legacy/old.exe.packed",
         "tags": ["packer", "exe", "legacy"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        run_map={
            "fresh":  _ok_result(dumped=1, implanted_pe=0, modified_total=2),
            "legacy": _ok_result(dumped=3, implanted_pe=1, modified_total=4),
        },
    )
    bench = pb.PackerPeSieveBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert result.errors == []
    dumped = {s.sample_name: s.value for s in result.metrics[0].samples}
    assert dumped == {"fresh": 1, "legacy": 3}

    # One run per entry; names recoverable from workdirs.
    assert sorted(n for n, _ in mocks["run_calls"]) == ["fresh", "legacy"]


def test_values_sourced_from_report(tmp_path: Path, monkeypatch):
    """The three metrics pull their values directly from
    report.dumped.modules / implanted_pe / modified.total."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["packer", "exe"]},
    ])
    _install_mocks(
        monkeypatch,
        run_map={"alpha": _ok_result(dumped=7, implanted_pe=2, modified_total=9)},
    )
    result = asyncio.run(pb.PackerPeSieveBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    by_name = {m.name: m for m in result.metrics}
    assert by_name["pesieve_dumped_modules"].samples[0].value == 7
    assert by_name["pesieve_implanted_pe"].samples[0].value == 2
    assert by_name["pesieve_modified_total"].samples[0].value == 9


# ============================================================================
# Filtering — match_all on {packer, exe}
# ============================================================================


def test_only_packer_exe_tagged_entries_run(tmp_path: Path, monkeypatch):
    """A CFF-only entry (no 'packer' tag) must not invoke ensure_protected
    or run_pesieve."""
    corpus = _make_corpus(tmp_path, [
        {"name": "packed", "binary": "bin/packed.exe",
         "tags": ["packer", "exe"]},
        {"name": "cff_only", "binary": "bin/cff.exe", "tags": ["cff", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch)
    asyncio.run(pb.PackerPeSieveBenchmark().run(corpus, _fake_session(tmp_path)))

    names = {n for n, _ in mocks["build_calls"]}
    assert names == {"packed"}


def test_dll_tagged_entries_skipped(tmp_path: Path, monkeypatch):
    """Same 'packer' tag but only 'dll' surface (not 'exe') → skipped."""
    corpus = _make_corpus(tmp_path, [
        {"name": "dll_entry", "binary": "bin/x.dll",
         "tags": ["packer", "dll"]},
    ])
    mocks = _install_mocks(monkeypatch)
    result = asyncio.run(pb.PackerPeSieveBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("no corpus entries tagged" in e for e in result.errors)
    assert mocks["build_calls"] == []


# ============================================================================
# Error paths (fail-closed)
# ============================================================================


def test_build_failure_reports_error_for_that_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["packer", "exe"]},
        {"name": "beta",  "binary": "bin/beta.exe",
         "tags": ["packer", "exe"]},
    ])
    _install_mocks(
        monkeypatch,
        build_map={"alpha": BuilderError("bad PE")},
    )
    result = asyncio.run(pb.PackerPeSieveBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("alpha" in e and "build failed" in e for e in result.errors)
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"beta"}


def test_pesieve_failure_reports_error_for_that_entry(
    tmp_path: Path, monkeypatch,
):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["packer", "exe"]},
        {"name": "beta",  "binary": "bin/beta.exe",
         "tags": ["packer", "exe"]},
    ])
    _install_mocks(
        monkeypatch,
        run_map={
            "alpha": _err_result("pe-sieve exit=2: can't attach"),
            "beta":  _ok_result(dumped=1),
        },
    )
    result = asyncio.run(pb.PackerPeSieveBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert any("alpha" in e and "pe-sieve" in e for e in result.errors)
    names = {s.sample_name for s in result.metrics[0].samples}
    assert names == {"beta"}


def test_empty_corpus_returns_empty_metrics_and_note(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "other", "binary": "bin/o.exe", "tags": ["vm", "exe"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(pb.PackerPeSieveBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    assert len(result.metrics) == 3
    for m in result.metrics:
        assert m.samples == []
    assert any("no corpus entries tagged" in e for e in result.errors)


# ============================================================================
# launch_args forwarding
# ============================================================================


def test_launch_args_forwarded_to_runner(tmp_path: Path, monkeypatch):
    """An entry with launch_args passes them through to run_pesieve."""
    corpus = _make_corpus(tmp_path, [
        {"name": "long_runner", "binary": "bin/l.exe",
         "tags": ["packer", "exe"],
         "launch_args": ["--hold", "3"]},
    ])
    mocks = _install_mocks(monkeypatch)
    asyncio.run(pb.PackerPeSieveBenchmark().run(corpus, _fake_session(tmp_path)))
    assert mocks["run_calls"] == [("long_runner", ["--hold", "3"])]


def test_empty_launch_args_passes_none_to_runner(tmp_path: Path, monkeypatch):
    """No launch_args → runner receives None, not an empty list."""
    corpus = _make_corpus(tmp_path, [
        {"name": "simple", "binary": "bin/s.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch)
    asyncio.run(pb.PackerPeSieveBenchmark().run(corpus, _fake_session(tmp_path)))
    assert mocks["run_calls"] == [("simple", None)]


# ============================================================================
# Evidence
# ============================================================================


def test_sample_evidence_contains_pesieve_diagnostics(
    tmp_path: Path, monkeypatch,
):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe",
         "tags": ["packer", "exe"]},
    ])
    _install_mocks(
        monkeypatch,
        run_map={"alpha": PesieveRunResult(
            ok=True, duration_ms=250,
            report=_make_report(pid=4242, dumped=1),
            dump_files=[Path("some/dump.exe")],
            error=None,
        )},
    )
    result = asyncio.run(pb.PackerPeSieveBenchmark().run(
        corpus, _fake_session(tmp_path),
    ))
    ev = result.metrics[0].samples[0].evidence
    assert ev["pid"] == 4242
    assert ev["pesieve_duration_ms"] == 250
    # Path rendering differs across platforms (Windows backslashes,
    # POSIX forward slashes) — assert the filename component only.
    assert [Path(p).name for p in ev["dump_files"]] == ["dump.exe"]
