"""MCP tool: run the registered defense benchmarks.

Agent-facing entry point. Loads the corpus, filters the benchmark
registry by ``categories`` / ``tier``, runs each benchmark on the
corpus, and returns a typed aggregate.

Empty-registry handling (the state at the end of P1): returns an
empty benchmarks list with a readable note. This keeps the contract
stable so that later phases merely populate the registry — callers
don't change.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from pydantic import BaseModel, Field

from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    IBenchmark,
    all_benchmarks,
)
from mx_mcp.common.corpus import Corpus, CorpusLoadError
from mx_mcp.common.tiers import Tier, parse_tier
from mx_mcp.common.tool_base import ITool, register_tool


_LOG = logging.getLogger(__name__)


DEFAULT_CORPUS_REL = Path("mcp") / "fixtures" / "corpus"
DEFAULT_TIMEOUT_S = 600.0


# ============================================================================
# Filter helpers
# ============================================================================


def _filter_benchmarks(
    benchmarks: list[type[IBenchmark]],
    categories: list[str] | None,
    tier: Tier | None,
) -> list[type[IBenchmark]]:
    """Apply category + tier filters. Empty filters pass everything through."""
    result = list(benchmarks)
    if categories:
        cat_set = frozenset(categories)
        result = [b for b in result if b.category in cat_set]
    if tier is not None:
        result = [b for b in result if b.tier == tier.value]
    return result


def _resolve_corpus_path(
    corpus_path: str | None, workspace_root: Path
) -> Path:
    if corpus_path is None:
        return workspace_root / DEFAULT_CORPUS_REL
    p = Path(corpus_path)
    return p if p.is_absolute() else (workspace_root / p).resolve()


# ============================================================================
# I/O schema
# ============================================================================


class MeasureDefenseInput(BaseModel):
    corpus_path: str | None = Field(
        default=None,
        description=(
            "Override the corpus root (absolute or workspace-relative). "
            "Default: mcp/fixtures/corpus relative to the workspace root."
        ),
    )
    categories: list[str] | None = Field(
        default=None,
        description=(
            "Filter benchmarks by category (cff / vm / packer / mutation "
            "/ anti_analysis / diffing / budget_to_crack). Default: all."
        ),
    )
    tier: str | None = Field(
        default=None,
        description=(
            "Filter benchmarks by tier (fast / slow / nightly). "
            "Default: run every tier the registry exposes."
        ),
    )
    level: str = Field(
        default="strong",
        description="Protection level forwarded to the builder for corpus protection.",
    )
    builder_args: list[str] = Field(
        default_factory=list,
        description="Extra CLI args forwarded to mxprotector_builder.",
    )
    timeout_s: float = Field(
        default=DEFAULT_TIMEOUT_S,
        description="Total benchmark timeout (seconds). Acts as an outer cap on the aggregate.",
    )


class MeasureDefenseOutput(BaseModel):
    corpus_path: str
    corpus_size: int
    benchmark_count: int
    duration_ms: int
    benchmarks: list[BenchmarkResult]
    notes: list[str] = Field(default_factory=list)


# ============================================================================
# Tool
# ============================================================================


@register_tool
class MeasureDefenseTool(ITool[MeasureDefenseInput, MeasureDefenseOutput]):
    """Run registered benchmarks and return aggregate metrics."""

    name = "measure_defense"
    description = (
        "Run the registered defense benchmarks over the curated corpus "
        "and return per-benchmark metrics with aggregate distributions "
        "(p10 / p50 / p90 / mean / stddev). Filter by categories (cff, "
        "vm, packer, mutation, anti_analysis, diffing, budget_to_crack) "
        "and/or tier (fast, slow, nightly)."
    )
    input_schema = MeasureDefenseInput
    output_schema = MeasureDefenseOutput

    # Test-injection seam: tests construct with a custom source; server
    # uses the zero-arg default which reads the global registry.
    def __init__(
        self,
        benchmarks_source: "BenchmarksSource | None" = None,
    ) -> None:
        self._benchmarks_source = benchmarks_source or all_benchmarks

    async def run(
        self, args: MeasureDefenseInput, session
    ) -> MeasureDefenseOutput:
        t0 = time.monotonic()
        notes: list[str] = []

        tier = parse_tier(args.tier) if args.tier else None

        all_bench = list(self._benchmarks_source())
        filtered = _filter_benchmarks(all_bench, args.categories, tier)

        corpus_path = _resolve_corpus_path(args.corpus_path, session.workspace_root)

        # Empty-registry short-circuit: return before touching the
        # filesystem so corpus absence does not mask the "nothing to
        # do" state.
        if not filtered:
            if not all_bench:
                notes.append("no benchmarks registered")
            else:
                notes.append(
                    f"no benchmarks match filter "
                    f"(categories={args.categories}, tier={args.tier})"
                )
            return MeasureDefenseOutput(
                corpus_path=str(corpus_path),
                corpus_size=0,
                benchmark_count=0,
                duration_ms=int((time.monotonic() - t0) * 1000),
                benchmarks=[],
                notes=notes,
            )

        try:
            corpus = Corpus.load(corpus_path)
        except CorpusLoadError as e:
            _LOG.error("corpus load failed: %s", e)
            return MeasureDefenseOutput(
                corpus_path=str(corpus_path),
                corpus_size=0,
                benchmark_count=0,
                duration_ms=int((time.monotonic() - t0) * 1000),
                benchmarks=[],
                notes=[f"corpus load failed: {e}"],
            )

        results: list[BenchmarkResult] = []
        # ``asyncio.wait_for`` wraps the full benchmark sequence so a
        # runaway backend cannot exceed the outer timeout. Per-benchmark
        # budgets live on the benchmark side in later phases.
        try:
            results = await asyncio.wait_for(
                self._run_benchmarks(filtered, corpus, session),
                timeout=args.timeout_s,
            )
        except asyncio.TimeoutError:
            notes.append(
                f"outer timeout of {args.timeout_s}s exceeded; "
                f"{len(results)} benchmark(s) completed before the cut"
            )

        return MeasureDefenseOutput(
            corpus_path=str(corpus_path),
            corpus_size=len(corpus),
            benchmark_count=len(results),
            duration_ms=int((time.monotonic() - t0) * 1000),
            benchmarks=results,
            notes=notes,
        )

    @staticmethod
    async def _run_benchmarks(
        benchmarks: list[type[IBenchmark]],
        corpus: Corpus,
        session,
    ) -> list[BenchmarkResult]:
        """Run every benchmark sequentially; single failure logs + skips."""
        out: list[BenchmarkResult] = []
        for bench_cls in benchmarks:
            bench = bench_cls()
            _LOG.info("run benchmark %s (%s/%s)",
                      bench_cls.name, bench_cls.category, bench_cls.tier)
            try:
                result = await bench.run(corpus, session)
                out.append(result)
            except Exception as e:  # noqa: BLE001 — fail-closed, surface as error result
                _LOG.exception("benchmark '%s' raised", bench_cls.name)
                out.append(BenchmarkResult(
                    benchmark=bench_cls.name,
                    category=bench_cls.category,
                    tier=bench_cls.tier,
                    duration_ms=0,
                    metrics=[],
                    errors=[f"{type(e).__name__}: {e}"],
                ))
        return out


# Type alias kept at module level so tests can reference it without
# reaching into private tool state.
from typing import Callable

BenchmarksSource = Callable[[], list[type[IBenchmark]]]
