"""CFF microcode benchmark — first real benchmark using the IDA backend.

## Method

For every CFF-tagged corpus entry:

1. Build a protected version using the current ``mxprotector_builder``.
2. Run IDA (headless) with the ``cff_metrics`` IDAPython script.
3. Parse the per-function metrics the script emits.
4. Emit one ``MetricSample`` per *function* (not per entry), keyed by
   ``{entry}::{fn_name}``.

Per-function aggregation is deliberate: per-MCP.md the gate is p90
across *functions* so that a single broken hot function cannot hide
behind the per-binary mean.

## Metrics

All four are ``higher_better`` — a stronger CFF pass inflates every
count:

* ``mc_blocks``          — microcode basic-block count.
* ``mc_gotos``           — m_goto / m_ijmp tail count (CFF dispatcher
                           signature).
* ``mc_cyclomatic``      — ``E - N + 2`` on the microcode CFG.
* ``mc_backedge_ratio``  — heuristic back-edge fraction.

See ``static/ida/scripts/cff_metrics.py`` for the exact extraction.

## Failure modes

Fail-closed: build failures, IDA launch failures, and Hex-Rays
unavailable all appear in ``BenchmarkResult.errors`` with one line
per affected entry. Samples from successful entries still aggregate
so the benchmark reports something useful even in a partial run.
"""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path

import mx_mcp.static.ida as _ida_pkg
from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
    aggregate_numeric,
    register_benchmark,
)
from mx_mcp.common.builder import (
    BuilderError,
    build_protected,
    resolve_builder_path,
)
from mx_mcp.static.ida.runner import (
    IdaNotFoundError,
    run_ida_script,
)


_LOG = logging.getLogger(__name__)


# Path to the IDAPython companion script. Resolved relative to the
# ``static.ida`` package so the benchmark can move between
# ``benchmarks/`` subfolders without touching this constant.
SCRIPT_PATH = (
    Path(_ida_pkg.__file__).parent / "scripts" / "cff_metrics.py"
)


# Metric names + directions — declared once so test code can reference
# the tuple without re-typing strings.
_METRIC_DEFS: tuple[tuple[str, MetricDirection], ...] = (
    ("mc_blocks",          MetricDirection.HIGHER_BETTER),
    ("mc_gotos",           MetricDirection.HIGHER_BETTER),
    ("mc_cyclomatic",      MetricDirection.HIGHER_BETTER),
    ("mc_backedge_ratio",  MetricDirection.HIGHER_BETTER),
)


@register_benchmark
class CffMicrocodeBenchmark(IBenchmark):
    """HexRays microcode CFF metrics — per-function distribution."""

    name = "cff_microcode"
    description = (
        "HexRays microcode complexity on CFF-tagged corpus entries. "
        "Emits mc_blocks / mc_gotos / mc_cyclomatic / mc_backedge_ratio "
        "as per-function samples aggregated into p10 / p50 / p90."
    )
    category = "cff"
    tier = "fast"
    corpus_tags = frozenset({"cff"})

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name,
                category=self.category,
                tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[_empty_metric(name, direction) for name, direction in _METRIC_DEFS],
                errors=["no corpus entries tagged 'cff'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        # Protected binaries land in a temp dir that disappears at the
        # end of the benchmark — we don't persist them between runs.
        with tempfile.TemporaryDirectory(prefix="mx_mcp_cff_bench_") as td:
            td_path = Path(td)
            for entry in entries:
                entry_errors = await _process_entry(
                    entry=entry,
                    output_dir=td_path,
                    builder_path=builder_path,
                    workspace_root=session.workspace_root,
                    samples_by_metric=samples_by_metric,
                )
                errors.extend(entry_errors)

        metrics = [
            _build_metric(name, direction, samples_by_metric[name])
            for name, direction in _METRIC_DEFS
        ]
        return BenchmarkResult(
            benchmark=self.name,
            category=self.category,
            tier=self.tier,
            duration_ms=int((time.monotonic() - t0) * 1000),
            metrics=metrics,
            errors=errors,
        )


# ============================================================================
# Private helpers
# ============================================================================


def _empty_metric(name: str, direction: MetricDirection) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=[],
        aggregate=aggregate_numeric([]),
    )


def _build_metric(
    name: str,
    direction: MetricDirection,
    samples: list[MetricSample],
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
    )


async def _process_entry(
    *,
    entry,
    output_dir: Path,
    builder_path: Path,
    workspace_root: Path,
    samples_by_metric: dict[str, list[MetricSample]],
) -> list[str]:
    """Build + IDA + extract for one corpus entry.

    Returns the list of error strings accumulated for this entry
    (empty on full success). Successful per-function samples are
    appended in place to ``samples_by_metric``.
    """
    errors: list[str] = []
    protected_path = output_dir / f"{entry.name}.mx.exe"

    try:
        pb = await build_protected(
            unprotected=entry.unprotected_binary,
            output=protected_path,
            builder_path=builder_path,
            workspace_root=workspace_root,
        )
    except (BuilderError, FileNotFoundError) as e:
        return [f"{entry.name}: build failed: {e}"]

    try:
        ida_result = await run_ida_script(
            binary=pb.protected_binary,
            script=SCRIPT_PATH,
        )
    except IdaNotFoundError as e:
        return [f"{entry.name}: IDA missing: {e}"]
    except FileNotFoundError as e:
        return [f"{entry.name}: IDA launch: {e}"]

    if not ida_result.ok or ida_result.output is None:
        return [f"{entry.name}: IDA: {ida_result.error or 'no output'}"]

    ida_out = ida_result.output
    if not ida_out.get("hexrays_available", False):
        return [f"{entry.name}: Hex-Rays not available in IDA"]

    functions = ida_out.get("functions", [])
    if not functions:
        errors.append(f"{entry.name}: no functions decompiled")

    for fn in functions:
        fn_name = fn.get("name") or f"sub_{fn.get('ea', 0):X}"
        sample_name = f"{entry.name}::{fn_name}"
        # ``mba_maturity`` surfaces whether MMAT_GLBOPT3 (what d810
        # attacks) or the decompile-driven fallback produced the
        # numbers. Absent on older script output → None.
        evidence_base = {
            "ea": fn.get("ea"),
            "fn_size": fn.get("size"),
            "mba_maturity": fn.get("mba_maturity"),
        }
        for metric_name, _ in _METRIC_DEFS:
            samples_by_metric[metric_name].append(MetricSample(
                sample_name=sample_name,
                value=fn.get(metric_name),
                evidence=evidence_base,
            ))

    for err in ida_out.get("errors", []):
        errors.append(f"{entry.name}: ida-fn: {err}")

    return errors
