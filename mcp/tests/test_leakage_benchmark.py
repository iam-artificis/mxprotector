"""Unit tests for benchmarks.leakage_benchmark.

Follows the packer-benchmark mocking pattern: patch
``ensure_protected`` at the module level so the builder is never
invoked, and materialise synthetic ``.mx.exe`` bytes per entry to
feed the real scan helpers. Scan internals have dedicated coverage
in ``test_leakage_scan``; the benchmark tests here assert
distribution + metric selection + fail-closed handling.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import leakage_benchmark as lb
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus


# ============================================================================
# Corpus + mock plumbing
# ============================================================================


def _make_corpus(tmp_path: Path, entries: list[dict]) -> Corpus:
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


def _install_mocks(
    monkeypatch,
    *,
    build_map: dict[str, ProtectedBuild | Exception] | None = None,
    output_bytes: dict[str, bytes] | None = None,
):
    """Override ``ensure_protected`` per entry. The mocked protected
    binary's contents come from ``output_bytes[entry.name]`` (default:
    a short clean PE-like prefix with no forbidden literals and no
    Rich header)."""
    build_calls: list[str] = []

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append(entry.name)
        behaviour = (build_map or {}).get(entry.name)
        if isinstance(behaviour, Exception):
            raise behaviour
        if behaviour is not None:
            return behaviour
        output = output_dir / f"{entry.name}.mx.exe"
        payload = (output_bytes or {}).get(
            entry.name, b"MZ" + b"\x00" * 64 + b"KERNEL32.DLL\x00"
        )
        output.write_bytes(payload)
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=output,
            sidecar_path=None,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    monkeypatch.setattr(lb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        lb, "resolve_builder_path", lambda root: root / "fake_builder.exe",
    )
    return {"build_calls": build_calls}


# ============================================================================
# Happy paths
# ============================================================================


def test_clean_binary_scores_all_zeros(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "clean", "binary": "bin/clean.exe", "tags": ["exe"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    assert isinstance(result, BenchmarkResult)
    assert result.errors == []
    by_name = {m.name: m for m in result.metrics}
    assert by_name["leaked_forbidden_literal_count"].samples[0].value == 0
    assert by_name["leaked_pdb_path_count"].samples[0].value == 0
    assert by_name["leaked_rich_header_present"].samples[0].value == 0.0
    for m in result.metrics:
        assert m.direction is MetricDirection.LOWER_BETTER


def test_forbidden_literal_surfaces_in_metric_and_evidence(
    tmp_path: Path, monkeypatch,
):
    payload = b"MZ" + b"\x00" * 32 + b"MxProtector" + b"\x00" * 32
    corpus = _make_corpus(tmp_path, [
        {"name": "leaks", "binary": "bin/leaks.exe", "tags": ["exe"]},
    ])
    _install_mocks(monkeypatch, output_bytes={"leaks": payload})
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    by_name = {m.name: m for m in result.metrics}
    forbidden = by_name["leaked_forbidden_literal_count"]
    assert forbidden.samples[0].value == 1
    breakdown = forbidden.samples[0].evidence["forbidden_hit_breakdown"]
    assert breakdown[0]["literal"] == "MxProtector"
    assert breakdown[0]["hit_count"] == 1


def test_pdb_path_surfaces_in_metric(tmp_path: Path, monkeypatch):
    payload = b"MZ" + b"\x00" * 32 + b"D:\\build\\foo.pdb\x00" + b"\x00" * 32
    corpus = _make_corpus(tmp_path, [
        {"name": "pdb", "binary": "bin/p.exe", "tags": ["exe"]},
    ])
    _install_mocks(monkeypatch, output_bytes={"pdb": payload})
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    by_name = {m.name: m for m in result.metrics}
    assert by_name["leaked_pdb_path_count"].samples[0].value == 1
    ev = by_name["leaked_pdb_path_count"].samples[0].evidence
    assert any(".pdb" in p["literal"] for p in ev["pdb_paths"])


def test_rich_header_surfaces_in_metric(tmp_path: Path, monkeypatch):
    payload = b"MZ" + b"\x00" * 128 + b"Rich" + b"\x00" * 64
    corpus = _make_corpus(tmp_path, [
        {"name": "rich", "binary": "bin/r.exe", "tags": ["exe"]},
    ])
    _install_mocks(monkeypatch, output_bytes={"rich": payload})
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    by_name = {m.name: m for m in result.metrics}
    assert by_name["leaked_rich_header_present"].samples[0].value == 1.0


# ============================================================================
# Corpus filtering
# ============================================================================


def test_non_exe_entries_skipped(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "dll_only", "binary": "bin/x.dll", "tags": ["dll"]},
    ])
    mocks = _install_mocks(monkeypatch)
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    assert mocks["build_calls"] == []
    assert any("no corpus entries tagged 'exe'" in e for e in result.errors)


def test_handles_mixed_fresh_and_legacy(tmp_path: Path, monkeypatch):
    """Both buildable + pre_protected entries produce a sample each.
    ``ensure_protected`` for legacy entries returns the preserved
    binary; the scan runs against whatever bytes ``.mx.exe`` has."""
    corpus = _make_corpus(tmp_path, [
        {"name": "fresh", "binary": "bin/f.exe", "tags": ["exe"]},
        {"name": "legacy", "pre_protected": "legacy/old.exe",
         "tags": ["exe", "legacy"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    sample_names = {
        s.sample_name for s in result.metrics[0].samples
    }
    assert sample_names == {"fresh", "legacy"}


# ============================================================================
# Fail-closed
# ============================================================================


def test_build_failure_reports_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "ok", "binary": "bin/a.exe", "tags": ["exe"]},
        {"name": "fails", "binary": "bin/b.exe", "tags": ["exe"]},
    ])
    _install_mocks(
        monkeypatch, build_map={"fails": BuilderError("bad input")},
    )
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    assert any("fails" in e and "build failed" in e for e in result.errors)
    # Healthy entry still contributes a sample.
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"ok"}


def test_registered_on_leakage_category(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "ok", "binary": "bin/a.exe", "tags": ["exe"]},
    ])
    _install_mocks(monkeypatch)
    result = asyncio.run(
        lb.LeakageSurfaceBenchmark().run(corpus, _fake_session(tmp_path))
    )
    assert result.category == "leakage"
    assert result.tier == "fast"
