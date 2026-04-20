"""Unit tests for tools.record_baseline."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mx_mcp.common.baselines import (
    BASELINE_SCHEMA_VERSION,
    BaselineDoc,
    BaselineExistsError,
    JsonFileStore,
)
from mx_mcp.common.benchmark_base import (
    AggregateStats,
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
)
from mx_mcp.tools.measure_defense import MeasureDefenseTool
from mx_mcp.tools.record_baseline import (
    RecordBaselineInput,
    RecordBaselineOutput,
    RecordBaselineTool,
)


def _make_corpus(tmp_path: Path) -> Path:
    corpus_root = tmp_path / "corpus"
    (corpus_root / "bin").mkdir(parents=True)
    (corpus_root / "bin" / "a.exe").write_bytes(b"\x4d\x5a")
    (corpus_root / "corpus.json").write_text(
        json.dumps({
            "schema_version": 1,
            "entries": [{"name": "a", "binary": "bin/a.exe", "tags": ["vm"]}],
        }),
        encoding="utf-8",
    )
    return corpus_root


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


class _OkBench(IBenchmark):
    name = "ok"
    description = "stub"
    category = "cff"
    tier = "fast"

    async def run(self, corpus, session):
        return BenchmarkResult(
            benchmark=self.name,
            category=self.category,
            tier=self.tier,
            duration_ms=1,
            metrics=[MetricResult(
                name="m",
                direction=MetricDirection.HIGHER_BETTER,
                samples=[MetricSample(sample_name="a", value=1.0)],
                aggregate=AggregateStats(
                    p10=1.0, p50=1.0, p90=1.0, mean=1.0, stddev=None,
                    n_samples=1, n_errors=0,
                ),
            )],
        )


def _tool_with_bench(bench_cls) -> RecordBaselineTool:
    measure = MeasureDefenseTool(benchmarks_source=lambda: [bench_cls])
    return RecordBaselineTool(measure_tool=measure)


# ============================================================================
# Happy path
# ============================================================================


def test_save_creates_file_parseable_as_baseline(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"
    tool = _tool_with_bench(_OkBench)

    args = RecordBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))

    assert isinstance(out, RecordBaselineOutput)
    assert out.benchmark_count == 1
    assert out.metric_count == 1
    path = baselines_root / "v1.json"
    assert Path(out.baseline_path) == path
    assert path.exists()

    doc = JsonFileStore(baselines_root).load("v1")
    assert isinstance(doc, BaselineDoc)
    assert doc.schema_version == BASELINE_SCHEMA_VERSION
    assert doc.name == "v1"
    assert doc.builder_level == "strong"
    assert doc.benchmarks[0].benchmark == "ok"


def test_git_commit_is_hex_or_none(tmp_path: Path):
    # The workspace_root is tmp_path (no git repo), so git_commit
    # should be None — best-effort lookup swallows failure silently.
    corpus_root = _make_corpus(tmp_path)
    tool = _tool_with_bench(_OkBench)
    args = RecordBaselineInput(
        baseline_name="v1",
        baselines_root=str(tmp_path / "baselines"),
        corpus_path=str(corpus_root),
    )
    out = asyncio.run(tool.run(args, _fake_session(tmp_path)))
    assert out.git_commit is None


# ============================================================================
# Overwrite semantics
# ============================================================================


def test_overwrite_false_blocks_replacement(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"
    tool = _tool_with_bench(_OkBench)
    args = RecordBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    asyncio.run(tool.run(args, _fake_session(tmp_path)))
    # Second call without overwrite → explicit error.
    with pytest.raises(BaselineExistsError, match="already exists"):
        asyncio.run(tool.run(args, _fake_session(tmp_path)))


def test_overwrite_true_replaces(tmp_path: Path):
    corpus_root = _make_corpus(tmp_path)
    baselines_root = tmp_path / "baselines"
    tool = _tool_with_bench(_OkBench)
    first = RecordBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
    )
    asyncio.run(tool.run(first, _fake_session(tmp_path)))

    second = RecordBaselineInput(
        baseline_name="v1",
        baselines_root=str(baselines_root),
        corpus_path=str(corpus_root),
        overwrite=True,
    )
    # Second call succeeds; just verify it didn't raise and file exists.
    out = asyncio.run(tool.run(second, _fake_session(tmp_path)))
    assert Path(out.baseline_path).exists()
