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
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    IBenchmark,
    all_benchmarks,
)
from mx_mcp.common.builder import (
    BuilderError,
    ensure_protected,
    resolve_builder_path,
)
from mx_mcp.common.corpus import Corpus, CorpusEntry, CorpusLoadError
from mx_mcp.common.git_info import read_git_head
from mx_mcp.common.snapshots import (
    SNAPSHOT_SCHEMA_VERSION,
    InvalidSnapshotIdError,
    Snapshot,
    SnapshotExistsError,
    SnapshotManifest,
    SnapshotStore,
    make_snapshot_id,
)
from mx_mcp.common.tiers import Tier, parse_tier
from mx_mcp.common.tool_base import ITool, register_tool


_LOG = logging.getLogger(__name__)


DEFAULT_CORPUS_REL = Path("mcp") / "fixtures" / "corpus"
# All per-run measurement artifacts (charts, snapshots, driver logs)
# converge under ``mcp/reports/``. Snapshots specifically land in
# ``mcp/reports/snapshots/`` — the legacy ``mcp/snapshots/`` location
# is no longer written; older clones can be migrated by moving the
# directory into the new path before re-running the tool.
DEFAULT_SNAPSHOTS_REL = Path("mcp") / "reports" / "snapshots"
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
    output_png: str | None = Field(
        default=None,
        description=(
            "If set, render the measurement as a PNG chart at this "
            "path. Requires matplotlib — install with "
            "``pip install -e \".[viz]\"`` in ``mcp/``. When matplotlib "
            "is missing, the tool still returns the full numeric "
            "result and surfaces an install hint in ``png_note``."
        ),
    )
    snapshot: bool = Field(
        default=True,
        description=(
            "When True (default), persist the measurement — plus a "
            "canonical rebuild of every buildable corpus entry — as a "
            "snapshot under ``snapshots_root``. Snapshots enable later "
            "``compare_snapshots`` runs and forward replay of new "
            "benchmarks against past binaries. Unit tests set this to "
            "False to avoid pulling the real builder."
        ),
    )
    snapshots_root: str | None = Field(
        default=None,
        description=(
            "Override for the snapshot store root; default "
            "``mcp/reports/snapshots`` relative to the workspace. "
            "Git-ignored under the consolidated reports/ tree."
        ),
    )


class MeasureDefenseOutput(BaseModel):
    corpus_path: str
    corpus_size: int
    benchmark_count: int
    duration_ms: int
    benchmarks: list[BenchmarkResult]
    notes: list[str] = Field(default_factory=list)
    png_path: str | None = None
    png_note: str | None = None
    # Snapshot persistence — optional; ``None`` when disabled, skipped
    # (empty run), or when auto-save soft-failed (note explains why).
    snapshot_id: str | None = None
    snapshot_path: str | None = None


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

        results: list[BenchmarkResult] = []
        corpus_size = 0

        if not filtered:
            # Empty-registry short-circuit: do not touch the filesystem
            # so corpus absence does not mask the "nothing to do" state.
            if not all_bench:
                notes.append("no benchmarks registered")
            else:
                notes.append(
                    f"no benchmarks match filter "
                    f"(categories={args.categories}, tier={args.tier})"
                )
        else:
            try:
                corpus = Corpus.load(corpus_path)
                corpus_size = len(corpus)
            except CorpusLoadError as e:
                _LOG.error("corpus load failed: %s", e)
                notes.append(f"corpus load failed: {e}")
            else:
                # ``asyncio.wait_for`` wraps the full benchmark sequence
                # so a runaway backend cannot exceed the outer timeout.
                # Per-benchmark budgets live on the benchmark side.
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

        output = MeasureDefenseOutput(
            corpus_path=str(corpus_path),
            corpus_size=corpus_size,
            benchmark_count=len(results),
            duration_ms=int((time.monotonic() - t0) * 1000),
            benchmarks=results,
            notes=notes,
        )

        # Auto-snapshot — runs only when benchmarks actually produced
        # results AND the caller has not opted out. All failures are
        # soft: they add a note but leave the measurement intact,
        # because the numbers have value even when the archive step
        # fails (full disk, permission denied, builder absent, …).
        if args.snapshot and results:
            snapshots_root = _resolve_snapshots_root(
                args.snapshots_root, session.workspace_root,
            )
            snapshot_id, snapshot_path, snap_notes = await _capture_snapshot(
                workspace_root=session.workspace_root,
                snapshots_root=snapshots_root,
                corpus=corpus,  # type: ignore[has-type]
                measurement_payload=output.model_dump(mode="json"),
                builder_level=args.level,
                builder_args=list(args.builder_args),
                corpus_path=corpus_path,
            )
            output.snapshot_id = snapshot_id
            output.snapshot_path = snapshot_path
            output.notes.extend(snap_notes)

        # Optional PNG rendering — delayed imports keep the tool module
        # free of the matplotlib dependency and avoid a top-level cycle
        # with the reporting package.
        if args.output_png is not None:
            from mx_mcp.reporting.charts.measurement_chart import (
                MeasurementChartRenderer,
            )
            from mx_mcp.reporting.render_or_skip import try_render_png

            output.png_path, output.png_note = try_render_png(
                MeasurementChartRenderer(), output, args.output_png,
            )

        return output

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


# ============================================================================
# Snapshot helpers
#
# Keeping snapshot logic as module-level functions (rather than
# private methods) lets tests exercise them in isolation — the tool
# method stays a thin orchestrator.
# ============================================================================


def _resolve_snapshots_root(
    override: str | None, workspace_root: Path,
) -> Path:
    if override is None:
        return workspace_root / DEFAULT_SNAPSHOTS_REL
    p = Path(override)
    return p if p.is_absolute() else (workspace_root / p).resolve()


def _iso_utc_now() -> str:
    """ISO-8601 UTC stamp with second precision.

    Returns ``YYYY-MM-DDTHH:MM:SSZ`` — unchanged from the format
    ``record_baseline`` uses, so a future deduplication into a shared
    ``common/timestamps.py`` module is a trivial rename.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _capture_snapshot(
    *,
    workspace_root: Path,
    snapshots_root: Path,
    corpus: Corpus,
    measurement_payload: dict[str, Any],
    builder_level: str,
    builder_args: list[str],
    corpus_path: Path,
) -> tuple[str | None, str | None, list[str]]:
    """Capture the current run as a snapshot — never raises.

    Returns ``(snapshot_id, snapshot_path, extra_notes)``. On success
    the first two are populated and ``extra_notes`` is empty. On
    soft-failure (no builder, disk full, id collision, …) the first
    two are ``None`` and ``extra_notes`` carries the exact reason.
    """
    git = read_git_head(workspace_root)
    timestamp = _iso_utc_now()
    try:
        snapshot_id = make_snapshot_id(timestamp_iso=timestamp, git=git)
    except InvalidSnapshotIdError as e:
        return None, None, [f"snapshot skipped: invalid id ({e})"]

    builder_path = resolve_builder_path(workspace_root)

    # Build canonicals in a scratch dir; the snapshot store will copy
    # them into its own managed artifacts/ directory on save.
    with tempfile.TemporaryDirectory(prefix="mx_mcp_snap_") as scratch:
        scratch_path = Path(scratch)
        artifacts, build_notes = await _build_canonicals(
            corpus=corpus,
            output_dir=scratch_path,
            builder_path=builder_path,
            workspace_root=workspace_root,
        )

        manifest = SnapshotManifest(
            schema_version=SNAPSHOT_SCHEMA_VERSION,
            snapshot_id=snapshot_id,
            timestamp=timestamp,
            git_commit=git.commit_sha if git else None,
            git_branch=git.branch if git else None,
            git_dirty=git.dirty if git else False,
            builder_level=builder_level,
            builder_args=builder_args,
            corpus_path=str(corpus_path),
            artifact_count=len(artifacts),
        )

        try:
            snap = SnapshotStore(snapshots_root).save(
                manifest=manifest,
                measurement_payload=measurement_payload,
                artifacts=artifacts,
            )
        except SnapshotExistsError as e:
            return None, None, build_notes + [
                f"snapshot skipped: id already exists ({e}); "
                f"retry in a later second"
            ]
        except OSError as e:
            return None, None, build_notes + [f"snapshot save failed: {e}"]

    _LOG.info(
        "captured snapshot %s (%d artifact(s), %d build note(s))",
        snap.manifest.snapshot_id, len(artifacts), len(build_notes),
    )
    return snap.manifest.snapshot_id, str(snap.root), build_notes


async def _build_canonicals(
    *,
    corpus: Corpus,
    output_dir: Path,
    builder_path: Path,
    workspace_root: Path,
) -> tuple[list[tuple[str, Path]], list[str]]:
    """Build a canonical artifact for every corpus entry.

    "Canonical" means ``trace_hints`` on, no benchmark-specific extra
    args — the production-like build that most future benchmarks
    (pe-sieve, unicorn, symbolic) want to analyse. Per-benchmark
    builds with specialised flags (e.g. CFF's ``--no-packer``) are
    NOT preserved; their metrics are already in ``measurement.json``.

    Returns ``(artifacts, notes)``. Per-entry failures land in
    ``notes`` but do not stop the loop — partial artifact sets are
    still useful, and each missing one is traceable to an explicit
    note.
    """
    artifacts: list[tuple[str, Path]] = []
    notes: list[str] = []

    if not builder_path.exists() and any(
        not e.is_pre_protected for e in corpus.entries()
    ):
        # Buildable entries cannot be produced without the builder.
        # Pre-protected entries would still copy cleanly, but losing
        # the majority of artifacts makes the snapshot less useful;
        # surface the root cause once rather than per entry.
        notes.append(
            f"snapshot canonical build skipped: builder missing at {builder_path}"
        )
        return artifacts, notes

    for entry in corpus.entries():
        try:
            pb = await ensure_protected(
                entry,
                output_dir=output_dir,
                builder_path=builder_path,
                workspace_root=workspace_root,
            )
        except (BuilderError, FileNotFoundError) as e:
            notes.append(
                f"snapshot canonical build failed for '{entry.name}': {e}"
            )
            continue

        canonical_exe = f"{entry.name}.mx.exe"
        artifacts.append((canonical_exe, pb.protected_binary))
        if pb.sidecar_path is not None and pb.sidecar_path.exists():
            artifacts.append(
                (f"{entry.name}.mx.exe.mxtrace.json", pb.sidecar_path)
            )

    return artifacts, notes
