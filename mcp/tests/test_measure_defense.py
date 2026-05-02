"""Unit tests for tools.measure_defense.

The production tool reads the global benchmark registry; tests inject
a custom ``benchmarks_source`` to keep themselves hermetic (no
dependency on whichever benchmarks are currently wired).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Iterable

import pytest

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
)
from mx_mcp.common.corpus import Corpus
from mx_mcp.tools.measure_defense import (
    MeasureDefenseInput,
    MeasureDefenseOutput,
    MeasureDefenseTool,
)


# ============================================================================
# Synthetic corpus + helpers
# ============================================================================


def _make_corpus(tmp_path: Path, names: Iterable[str] = ("alpha",)) -> Path:
    corpus_root = tmp_path / "corpus"
    (corpus_root / "bin").mkdir(parents=True)
    entries = []
    for n in names:
        bin_path = corpus_root / "bin" / f"{n}.exe"
        bin_path.write_bytes(b"\x4d\x5a")
        entries.append({"name": n, "binary": f"bin/{n}.exe", "tags": ["vm"]})
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return corpus_root


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


# ============================================================================
# Mock benchmark classes
# ============================================================================


class _OkBench(IBenchmark):
    name = "ok_bench"
    description = "stub"
    category = "cff"
    tier = "fast"

    async def run(self, corpus: Corpus, session) -> BenchmarkResult:
        return BenchmarkResult(
            benchmark=self.name,
            category=self.category,
            tier=self.tier,
            duration_ms=7,
            metrics=[MetricResult(
                name="score",
                direction=MetricDirection.HIGHER_BETTER,
                samples=[
                    MetricSample(sample_name=e.name, value=0.5)
                    for e in corpus.entries()
                ],
                aggregate=AggregateStats(
                    p10=0.5, p50=0.5, p90=0.5, mean=0.5, stddev=None,
                    n_samples=len(corpus), n_errors=0,
                ),
            )],
        )


class _RaisingBench(IBenchmark):
    name = "raises"
    description = "intentional failure"
    category = "vm"
    tier = "slow"

    async def run(self, corpus, session):
        raise RuntimeError("backend blew up")


# ============================================================================
# Empty-registry paths (the P1 steady state)
# ============================================================================


def test_empty_registry_returns_empty_result(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert isinstance(out, MeasureDefenseOutput)
    assert out.benchmark_count == 0
    assert out.benchmarks == []
    assert any("no benchmarks registered" in n for n in out.notes)


def test_filter_that_matches_nothing_returns_empty(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        categories=["no_such_category"],
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 0
    assert any("no benchmarks match filter" in n for n in out.notes)


# ============================================================================
# Corpus load failures
# ============================================================================


def test_missing_corpus_surfaces_note_when_benchmarks_present(tmp_path: Path):
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(corpus_path=str(tmp_path / "no_such_dir"))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 0
    assert any("corpus load failed" in n for n in out.notes)


def test_missing_corpus_ignored_when_no_benchmarks(tmp_path: Path):
    # Empty registry path short-circuits before corpus load.
    tool = MeasureDefenseTool(benchmarks_source=lambda: [])
    args = MeasureDefenseInput(corpus_path=str(tmp_path / "no_such_dir"))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmarks == []


# ============================================================================
# Execution paths
# ============================================================================


def test_runs_registered_benchmark_on_corpus(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path, names=("alpha", "beta"))
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 1
    assert out.corpus_size == 2
    bench_result = out.benchmarks[0]
    assert bench_result.benchmark == "ok_bench"
    assert len(bench_result.metrics[0].samples) == 2


def test_category_filter_respected(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench, _RaisingBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root), categories=["cff"],
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.benchmark_count == 1
    assert out.benchmarks[0].benchmark == "ok_bench"


def test_tier_filter_respected(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench, _RaisingBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root), tier="slow")
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    # Only the slow one runs; and it raises, so it's captured as an error
    # result rather than propagated (fail-closed).
    assert out.benchmark_count == 1
    assert out.benchmarks[0].benchmark == "raises"
    assert out.benchmarks[0].errors


def test_invalid_tier_raises(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root), tier="ultra")
    with pytest.raises(ValueError, match="unknown tier"):
        asyncio.run(tool.run(args, _fake_session(tmp_path)))


def test_benchmark_raising_is_fail_closed(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_RaisingBench])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    # A backend exception is captured, not re-raised (MCP.md principle).
    assert out.benchmark_count == 1
    result = out.benchmarks[0]
    assert result.metrics == []
    assert any("RuntimeError" in e for e in result.errors)


# ============================================================================
# output_png — chart rendering at the tool boundary
# ============================================================================


def test_output_png_unset_leaves_chart_fields_none(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [])
    args = MeasureDefenseInput(corpus_path=str(corpus_root))
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.png_path is None
    assert out.png_note is None


def test_output_png_writes_chart_when_matplotlib_present(tmp_path: Path):
    pytest.importorskip("matplotlib")
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    target = tmp_path / "chart.png"
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        output_png=str(target),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert out.png_note is None
    assert out.png_path is not None
    assert Path(out.png_path).exists()
    # PNG magic — proves the file is a real image, not a stub written
    # by the helper before delegating to matplotlib.
    assert Path(out.png_path).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_output_png_graceful_when_renderer_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    # Simulate missing matplotlib by patching the guard at the call
    # site. ``measurement_chart`` imported the name into its own
    # module namespace via ``from ... import matplotlib_available``;
    # patching ``_mpl.matplotlib_available`` would leave the bound
    # local alone.
    from mx_mcp.reporting.charts import measurement_chart

    monkeypatch.setattr(measurement_chart, "matplotlib_available", lambda: False)

    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    target = tmp_path / "chart.png"
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        output_png=str(target),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert out.png_path is None
    assert out.png_note is not None
    assert "matplotlib" in out.png_note
    assert not target.exists()


# ============================================================================
# Snapshot persistence — auto-save wiring. All tests stub
# ``ensure_protected`` at the module level to avoid pulling the real
# builder; snapshot save then exercises the real ``SnapshotStore``.
# ============================================================================


def _stub_ensure_protected(monkeypatch: pytest.MonkeyPatch):
    """Install a fake ``ensure_protected`` that fabricates a valid
    ProtectedBuild + sidecar on disk so the snapshot save actually
    copies bytes. Returns a list that records every (name, output_dir)
    the fake saw."""
    from mx_mcp.common.builder import ProtectedBuild
    from mx_mcp.tools import measure_defense as md

    calls: list[tuple[str, Path]] = []

    async def fake_ensure(entry, *, output_dir: Path, **kw):
        calls.append((entry.name, output_dir))
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{entry.name}.mx.exe"
        output.write_bytes(b"\x4d\x5a")
        sidecar = output.parent / f"{output.name}.mxtrace.json"
        sidecar.write_text('{"schema_version":1}', encoding="utf-8")
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=output, sidecar_path=sidecar,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    monkeypatch.setattr(md, "ensure_protected", fake_ensure)
    # Builder path existence check inside _build_canonicals is
    # also via md's bound name — patch that too so the short-circuit
    # does not fire.
    fake_builder = Path(str(monkeypatch)) if False else None
    monkeypatch.setattr(
        md, "resolve_builder_path",
        lambda root: root / "fake_builder.exe",
    )
    # Create the fake builder file so the "exists" probe passes.
    return calls


def test_snapshot_disabled_skips_persistence(tmp_path: Path):
    """``snapshot=False`` means no filesystem touching, no ids."""
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root), snapshot=False,
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert out.snapshot_id is None
    assert out.snapshot_path is None
    assert not (tmp_path / "mcp" / "reports" / "snapshots").exists()


def test_snapshot_saved_when_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """Happy path: benchmarks ran, builder stubbed, snapshot lands
    on disk with measurement + artifacts."""
    corpus_root = _make_corpus(tmp_path, names=("alpha", "beta"))
    _stub_ensure_protected(monkeypatch)
    # Realise the fake builder file so the "exists" probe in
    # _build_canonicals sees it.
    (tmp_path / "fake_builder.exe").write_bytes(b"\x4d\x5a")
    monkeypatch.setattr(
        "mx_mcp.tools.measure_defense.resolve_builder_path",
        lambda root: tmp_path / "fake_builder.exe",
    )

    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert out.snapshot_id is not None
    assert out.snapshot_path is not None
    snap_dir = Path(out.snapshot_path)
    assert snap_dir.exists()
    assert (snap_dir / "manifest.json").exists()
    assert (snap_dir / "measurement.json").exists()
    # Two entries × (exe + sidecar) = 4 artifacts.
    artifacts = sorted(p.name for p in (snap_dir / "artifacts").iterdir())
    assert artifacts == [
        "alpha.mx.exe", "alpha.mx.exe.mxtrace.json",
        "beta.mx.exe",  "beta.mx.exe.mxtrace.json",
    ]


def test_snapshot_still_saved_when_builder_absent(tmp_path: Path):
    """No builder on disk → canonicals cannot be built. The snapshot
    is still persisted (measurement.json + manifest have standalone
    value for cross-version comparison); artifacts are empty and a
    note explains the reason."""
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    # Benchmark ran and produced metrics.
    assert out.benchmark_count == 1
    # Snapshot persisted — measurement still queryable later.
    assert out.snapshot_id is not None
    assert out.snapshot_path is not None
    assert any("builder missing" in n for n in out.notes)
    # But artifacts/ is empty because canonical build was skipped.
    artifacts_dir = Path(out.snapshot_path) / "artifacts"
    assert list(artifacts_dir.iterdir()) == []


def test_snapshot_skipped_when_no_benchmarks_ran(tmp_path: Path):
    """Empty registry means no measurement to archive — skip cleanly,
    no note-spam about builder/store issues."""
    corpus_root = _make_corpus(tmp_path)
    tool = MeasureDefenseTool(benchmarks_source=lambda: [])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert out.snapshot_id is None
    # The snapshots dir was never touched.
    assert not (tmp_path / "snapshots").exists()


def test_snapshot_manifest_records_git_and_corpus_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """Manifest on disk carries the metadata the comparison tool
    will later read: git commit + corpus path + builder level."""
    corpus_root = _make_corpus(tmp_path)
    _stub_ensure_protected(monkeypatch)
    (tmp_path / "fake_builder.exe").write_bytes(b"\x4d\x5a")
    monkeypatch.setattr(
        "mx_mcp.tools.measure_defense.resolve_builder_path",
        lambda root: tmp_path / "fake_builder.exe",
    )

    tool = MeasureDefenseTool(benchmarks_source=lambda: [_OkBench])
    args = MeasureDefenseInput(
        corpus_path=str(corpus_root),
        snapshots_root=str(tmp_path / "snapshots"),
        level="strong",
        builder_args=["--trace-hints"],
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    manifest = json.loads(
        (Path(out.snapshot_path) / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["builder_level"] == "strong"
    assert manifest["builder_args"] == ["--trace-hints"]
    assert manifest["corpus_path"] == str(corpus_root)
    # git_* fields may be None when the test env lacks git, but the
    # key must exist.
    assert "git_commit" in manifest
    assert "git_dirty" in manifest
