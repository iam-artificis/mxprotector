"""Unit tests for tools.compare_snapshots.

The tool is exercised end-to-end against a real :class:`SnapshotStore`
built in a tmp dir. Only the chart-rendering path is mocked when
matplotlib is missing (caught by the ``output_png`` test).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    MetricDirection,
    MetricResult,
    MetricSample,
    MetricScale,
)
from mx_mcp.common.snapshots import (
    SnapshotManifest,
    SnapshotStore,
)
from mx_mcp.tools.compare_snapshots import (
    CompareSnapshotsInput,
    CompareSnapshotsOutput,
    CompareSnapshotsTool,
    SnapshotResolveError,
)


# ============================================================================
# Helpers
# ============================================================================


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


def _bench_result(
    benchmark: str, metric_name: str, p90_value: float,
    *, scale_strong: float = 10.0,
) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark=benchmark, category="cff", tier="fast",
        duration_ms=1,
        metrics=[MetricResult(
            name=metric_name,
            direction=MetricDirection.HIGHER_BETTER,
            samples=[MetricSample(sample_name="x", value=p90_value)],
            aggregate=AggregateStats(
                p10=p90_value, p50=p90_value, p90=p90_value,
                mean=p90_value, stddev=None, n_samples=1, n_errors=0,
            ),
            scale=MetricScale(weak_value=0.0, strong_value=scale_strong),
        )],
    )


def _save_snapshot(
    store: SnapshotStore,
    *,
    snapshot_id: str,
    benchmarks: list[BenchmarkResult],
    git_commit: str = "a" * 40,
    timestamp: str = "2026-04-20T18:05:11Z",
) -> None:
    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        timestamp=timestamp,
        git_commit=git_commit,
        git_branch="master",
        git_dirty=False,
        builder_level="strong",
        builder_args=[],
        corpus_path="/tmp/corpus",
        artifact_count=0,
    )
    measurement = {
        "corpus_path": "/tmp/corpus",
        "corpus_size": 1, "benchmark_count": len(benchmarks),
        "duration_ms": 1, "notes": [],
        "benchmarks": [b.model_dump(mode="json") for b in benchmarks],
    }
    store.save(
        manifest=manifest, measurement_payload=measurement, artifacts=[],
    )


# ============================================================================
# Explicit id resolution
# ============================================================================


def test_compare_two_explicit_ids_produces_diff(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T09-00-00Z_aaaaaaa",
        benchmarks=[_bench_result("cff", "mc_blocks", 5.0)],
    )
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T18-00-00Z_bbbbbbb",
        benchmarks=[_bench_result("cff", "mc_blocks", 8.0)],
    )

    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="2026-04-20T09-00-00Z_aaaaaaa",
        right="2026-04-20T18-00-00Z_bbbbbbb",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert isinstance(out, CompareSnapshotsOutput)
    # Higher-better metric going 5 → 8 = improvement (60%).
    assert len(out.diff.improvements) == 1
    assert out.diff.improvements[0].metric == "mc_blocks"
    assert out.diff.gate_passed is True


def test_compare_detects_regression(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T09-00-00Z_aaaaaaa",
        benchmarks=[_bench_result("cff", "mc_blocks", 8.0)],
    )
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T18-00-00Z_bbbbbbb",
        benchmarks=[_bench_result("cff", "mc_blocks", 4.0)],
    )
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="2026-04-20T09-00-00Z_aaaaaaa",
        right="2026-04-20T18-00-00Z_bbbbbbb",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert len(out.diff.regressions) == 1
    assert out.diff.gate_passed is False


# ============================================================================
# Alias resolution — latest / previous
# ============================================================================


def test_latest_alias_resolves(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T09-00-00Z_aaaaaaa",
        benchmarks=[_bench_result("cff", "m", 1.0)],
    )
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T18-00-00Z_bbbbbbb",
        benchmarks=[_bench_result("cff", "m", 9.0)],
    )
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="previous", right="latest",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.left_id == "2026-04-20T09-00-00Z_aaaaaaa"
    assert out.right_id == "2026-04-20T18-00-00Z_bbbbbbb"


def test_latest_on_empty_store_raises(tmp_path: Path):
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="latest", right="latest",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    with pytest.raises(SnapshotResolveError, match="no snapshots"):
        asyncio.run(tool.run(args, _fake_session(tmp_path)))


def test_previous_requires_at_least_two(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T09-00-00Z_aaaaaaa",
        benchmarks=[_bench_result("cff", "m", 1.0)],
    )
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="previous", right="latest",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    with pytest.raises(SnapshotResolveError, match="need at least 2"):
        asyncio.run(tool.run(args, _fake_session(tmp_path)))


# ============================================================================
# Missing snapshots + corpus-path warning
# ============================================================================


def test_missing_explicit_id_raises(tmp_path: Path):
    SnapshotStore(tmp_path / "snapshots")  # realise directory
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="2026-04-20T09-00-00Z_aaaaaaa",
        right="2026-04-20T18-00-00Z_bbbbbbb",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    with pytest.raises(SnapshotResolveError):
        asyncio.run(tool.run(args, _fake_session(tmp_path)))


def test_mismatched_corpus_path_surfaces_note(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    # Craft two snapshots with different corpus paths manually.
    for sid, corpus in [
        ("2026-04-20T09-00-00Z_aaaaaaa", "/corpus/A"),
        ("2026-04-20T18-00-00Z_bbbbbbb", "/corpus/B"),
    ]:
        manifest = SnapshotManifest(
            snapshot_id=sid,
            timestamp="x", git_commit=None, git_branch=None, git_dirty=False,
            builder_level="strong", builder_args=[],
            corpus_path=corpus, artifact_count=0,
        )
        measurement = {
            "corpus_path": corpus, "corpus_size": 0,
            "benchmark_count": 0, "duration_ms": 0, "notes": [],
            "benchmarks": [_bench_result("cff", "m", 1.0).model_dump(mode="json")],
        }
        store.save(manifest=manifest, measurement_payload=measurement, artifacts=[])

    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="2026-04-20T09-00-00Z_aaaaaaa",
        right="2026-04-20T18-00-00Z_bbbbbbb",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert any("corpus path differs" in n for n in out.notes)


# ============================================================================
# Chart path — optional render
# ============================================================================


def test_output_png_writes_chart_when_matplotlib_present(tmp_path: Path):
    pytest.importorskip("matplotlib")
    store = SnapshotStore(tmp_path / "snapshots")
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T09-00-00Z_aaaaaaa",
        benchmarks=[_bench_result("cff", "mc_blocks", 3.0)],
    )
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T18-00-00Z_bbbbbbb",
        benchmarks=[_bench_result("cff", "mc_blocks", 6.0)],
    )
    target = tmp_path / "compare.png"
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="previous", right="latest",
        snapshots_root=str(tmp_path / "snapshots"),
        output_png=str(target),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert out.png_note is None
    assert out.png_path is not None
    assert Path(out.png_path).exists()
    assert Path(out.png_path).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_output_png_unset_leaves_chart_fields_none(tmp_path: Path):
    store = SnapshotStore(tmp_path / "snapshots")
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T09-00-00Z_aaaaaaa",
        benchmarks=[_bench_result("cff", "m", 1.0)],
    )
    _save_snapshot(
        store,
        snapshot_id="2026-04-20T18-00-00Z_bbbbbbb",
        benchmarks=[_bench_result("cff", "m", 2.0)],
    )
    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="previous", right="latest",
        snapshots_root=str(tmp_path / "snapshots"),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.png_path is None
    assert out.png_note is None
