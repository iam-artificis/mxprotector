"""CFF microcode benchmark — filtered amplification + coverage.

## Method

For every CFF-tagged buildable corpus entry:

1. Build a protected version.
2. Extract the list of CFF-protected functions from the sidecar's
   ``protected_functions`` array (filtered by ``kind == "cff"``).
   These RVAs are the **input PE** RVAs of functions the CFF pass
   defended — the right denominator for amplification.
3. Measure two baselines against the unprotected binary:

   * ``baseline_filtered`` — per-function totals restricted to the
     functions matching the filter.
   * ``baseline_total`` — unrestricted totals across every function.

   Both go through the shared :class:`CfgBaselineCache`; distinct
   filter keys mean the two live in separate cache slots and both run
   exactly once per session.

4. Measure the protected side via one IDA invocation running in
   **dual mode**: region mode on the ``.cff`` section captures the
   dispatcher's microcode, and per-function mode (also filtered) picks
   up whatever IDA finds at the original function RVAs — which in
   protected builds is either the in-place flattened body or a
   small trampoline jump to the dispatcher. Sum of both is the total
   microcode budget the CFF pass produced for those functions.

## Metrics

All five are ``HIGHER_BETTER`` — stronger CFF inflates every quantity.

* ``mc_blocks_amplification``      — ↑ ``protected_total /
                                       baseline_filtered``. Expected
                                       > 1 because flattening emits
                                       more blocks than the source
                                       contained.
* ``mc_cyclomatic_amplification``  — ↑ same shape, cyclomatic
                                       complexity.
* ``mc_gotos_amplification``       — ↑ same shape, goto / ijmp
                                       counts. Amplifies harder than
                                       blocks because every flattened
                                       state's tail is a goto.
* ``mc_backedge_ratio``            — ↑ edge-weighted back-edge
                                       fraction across the region
                                       records. Already a ratio in
                                       ``[0, 1]``; no normalisation.
* ``cff_coverage``                 — ↑ ``baseline_filtered.total_blocks
                                       / baseline_total.total_blocks``.
                                       Fraction of the unprotected
                                       binary's microcode that got
                                       CFF'd. Orthogonal to
                                       amplification — a high
                                       amplification on a tiny slice
                                       of the binary scores high on
                                       the former, low on this.

## Pre-protected entries

Excluded. A pre-protected artefact has no unprotected source to
measure a baseline against, so the ratios are undefined.

## Failure modes

Fail-closed: every per-entry failure surfaces in
``BenchmarkResult.errors`` and the benchmark still aggregates the
healthy entries.
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from pathlib import Path

import mx_mcp.static.ida as _ida_pkg
from mx_mcp.common.baseline import (
    BaselineError,
    CfgBaseline,
    CfgBaselineCache,
)
from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
    MetricScale,
    aggregate_numeric,
    register_benchmark,
)
from mx_mcp.common.builder import (
    BuilderError,
    ensure_protected,
    resolve_builder_path,
)
from mx_mcp.common.ida_cfg_baseline import IdaCfgBaselineProvider
from mx_mcp.common.ratio import ratio_safe
from mx_mcp.common.sidecar import Sidecar, load_sidecar
from mx_mcp.static.ida.runner import (
    IdaNotFoundError,
    run_ida_script,
)


_LOG = logging.getLogger(__name__)


SCRIPT_PATH = (
    Path(_ida_pkg.__file__).parent / "scripts" / "cff_metrics.py"
)


# Metric declarations — empirical calibration against the seed corpus
# at strong-level protection (p50 observations from
# ``scripts/_smoke_vm_and_chart.py``):
#
#   mc_blocks_amplification      5.66x  → strong=10.0   → score ≈ 0.52
#   mc_cyclomatic_amplification  5.67x  → strong=10.0   → score ≈ 0.52
#   mc_gotos_amplification       33.5x  → strong=60.0   → score ≈ 0.55
#   mc_backedge_ratio            0.259  → strong=0.6    → score ≈ 0.43
#   cff_coverage                 0.44%  → strong=0.01   → score ≈ 0.44
#
# Coverage anchors are tight against the seed corpus because these
# test binaries are dominated by CRT / runtime bloat — only a small
# fraction of total microcode is under ``MX_CFF_BEGIN/END`` markers.
# On realistic production binaries where user code forms a larger
# fraction of ``.text``, coverage will run higher and ``strong_value``
# should be relaxed.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("mc_blocks_amplification",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=1.0, strong_value=10.0)),
    ("mc_cyclomatic_amplification",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=1.0, strong_value=10.0)),
    ("mc_gotos_amplification",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=1.0, strong_value=60.0)),
    ("mc_backedge_ratio",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.6)),
    ("cff_coverage",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.01)),
)


@register_benchmark
class CffMicrocodeBenchmark(IBenchmark):
    """CFF filtered-amplification + coverage benchmark."""

    name = "cff_microcode"
    description = (
        "Filtered amplification ratios (protected microcode / "
        "unprotected-baseline microcode, restricted to functions the "
        "CFF pass defended) plus cff_coverage (fraction of the "
        "unprotected binary's CFG complexity that got CFF'd) and an "
        "absolute backedge ratio on the dispatcher."
    )
    category = "cff"
    tier = "fast"
    corpus_tags = frozenset({"cff"})

    def __init__(
        self,
        *,
        baseline_cache: CfgBaselineCache | None = None,
    ) -> None:
        self._baseline_cache = baseline_cache

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=["no corpus entries tagged 'cff'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)
        baseline_cache = self._resolve_baseline_cache()

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_cff_bench_") as td:
            td_path = Path(td)
            for entry in entries:
                entry_errors = await _process_entry(
                    entry=entry,
                    output_dir=td_path,
                    builder_path=builder_path,
                    workspace_root=session.workspace_root,
                    baseline_cache=baseline_cache,
                    samples_by_metric=samples_by_metric,
                )
                errors.extend(entry_errors)

        metrics = [
            _build_metric(name, direction, scale, samples_by_metric[name])
            for name, direction, scale in _METRIC_DEFS
        ]
        return BenchmarkResult(
            benchmark=self.name, category=self.category, tier=self.tier,
            duration_ms=int((time.monotonic() - t0) * 1000),
            metrics=metrics, errors=errors,
        )

    def _resolve_baseline_cache(self) -> CfgBaselineCache:
        if self._baseline_cache is None:
            self._baseline_cache = CfgBaselineCache(IdaCfgBaselineProvider())
        return self._baseline_cache


# ============================================================================
# Private helpers
# ============================================================================


def _empty_metric(
    name: str, direction: MetricDirection, scale: MetricScale,
) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=[],
        aggregate=aggregate_numeric([]), scale=scale,
    )


def _build_metric(
    name: str,
    direction: MetricDirection,
    scale: MetricScale,
    samples: list[MetricSample],
) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
        scale=scale,
    )


async def _process_entry(
    *,
    entry,
    output_dir: Path,
    builder_path: Path,
    workspace_root: Path,
    baseline_cache: CfgBaselineCache,
    samples_by_metric: dict[str, list[MetricSample]],
) -> list[str]:
    """Build → sidecar → baselines → protected IDA → samples."""
    if entry.is_pre_protected:
        return [
            f"{entry.name}: pre-protected — no unprotected source to "
            f"measure amplification against"
        ]
    if entry.unprotected_binary is None:
        return [f"{entry.name}: corpus entry has no unprotected source"]

    # 1. Build protected + sidecar.
    try:
        pb = await ensure_protected(
            entry,
            output_dir=output_dir,
            builder_path=builder_path,
            extra_args=["--no-packer"],
            workspace_root=workspace_root,
        )
    except (BuilderError, FileNotFoundError) as e:
        return [f"{entry.name}: build failed: {e}"]

    sidecar_or_err = _load_sidecar_or_error(pb.sidecar_path, entry.name)
    if isinstance(sidecar_or_err, str):
        return [sidecar_or_err]
    sidecar = sidecar_or_err

    cff_section = sidecar.sections.get("cff")
    if cff_section is None or cff_section.size == 0:
        return [
            f"{entry.name}: sidecar has no (non-empty) 'cff' section — "
            f"CFF disabled or --no-cfg-flattening in effect"
        ]

    # 2. Protected-function filter from sidecar.
    filter_rvas = _filter_rvas_from_sidecar(sidecar, kind="cff")
    if not filter_rvas:
        return [
            f"{entry.name}: sidecar has no cff-kind entries in "
            f"protected_functions — cannot filter baseline"
        ]

    # 3. Two baseline measurements — filtered (amplification
    #    denominator) + total (coverage denominator). Shared cache
    #    runs each unique (binary, filter) pair once per session.
    try:
        baseline_filtered = await baseline_cache.get(
            entry.unprotected_binary, filter_rvas=filter_rvas,
        )
        baseline_total = await baseline_cache.get(
            entry.unprotected_binary, filter_rvas=None,
        )
    except BaselineError as e:
        return [f"{entry.name}: baseline measurement failed: {e}"]
    except FileNotFoundError as e:
        return [f"{entry.name}: baseline input missing: {e}"]

    # 4. Protected-side IDA — dual mode.
    regions = [{
        "name": "cff_section",
        "rva": cff_section.rva,
        "size": cff_section.size,
    }]
    try:
        ida_result = await run_ida_script(
            binary=pb.protected_binary,
            script=SCRIPT_PATH,
            extra_env={
                "MX_MCP_IDA_REGIONS": json.dumps(regions),
                "MX_MCP_IDA_FUNCTION_FILTER": json.dumps(
                    sorted(filter_rvas)),
            },
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

    records = ida_out.get("functions", [])
    errors: list[str] = [
        f"{entry.name}: ida-region: {e}"
        for e in ida_out.get("errors", [])
    ]

    function_records = [r for r in records
                        if r.get("record_type") == "function"]
    region_records = [r for r in records
                      if r.get("record_type") == "region"]

    if not region_records:
        errors.append(
            f"{entry.name}: gen_microcode produced no blocks for the "
            f"cff section [0x{cff_section.rva:X}"
            f"..{cff_section.rva + cff_section.size:X}) — bytes may be "
            f"encrypted (packer on?) or invalid"
        )
        return errors

    _record_amplification_samples(
        entry_name=entry.name,
        baseline_filtered=baseline_filtered,
        baseline_total=baseline_total,
        function_records=function_records,
        region_records=region_records,
        samples_by_metric=samples_by_metric,
    )
    return errors


# ============================================================================
# Aggregation + sample emission
# ============================================================================


def _filter_rvas_from_sidecar(sidecar: Sidecar, *, kind: str) -> frozenset[int]:
    return frozenset(
        pf.rva for pf in sidecar.protected_functions if pf.kind == kind
    )


def _sum_records(records: list[dict], field: str) -> int:
    return sum(int(r.get(field, 0)) for r in records)


def _record_amplification_samples(
    *,
    entry_name: str,
    baseline_filtered: CfgBaseline,
    baseline_total: CfgBaseline,
    function_records: list[dict],
    region_records: list[dict],
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    """Convert protected + baseline records into per-entry samples.

    Totals summed across *both* record types:

    * Function records on protected side — in-place flattened bodies +
      trampoline stubs that IDA picks up at the filter RVAs.
    * Region records on protected side — the ``.cff`` dispatcher
      microcode, independent of IDA function recognition.

    These are disjoint (.text vs .cff sections) and together cover the
    full microcode footprint of the CFF pass for the filtered
    functions.
    """
    protected_blocks = (_sum_records(function_records, "mc_blocks")
                        + _sum_records(region_records, "mc_blocks"))
    protected_cyc = (_sum_records(function_records, "mc_cyclomatic")
                     + _sum_records(region_records, "mc_cyclomatic"))
    protected_gotos = (_sum_records(function_records, "mc_gotos")
                       + _sum_records(region_records, "mc_gotos"))

    blocks_amp = ratio_safe(float(protected_blocks),
                            float(baseline_filtered.total_blocks))
    cyc_amp = ratio_safe(float(protected_cyc),
                         float(baseline_filtered.total_cyclomatic))
    gotos_amp = ratio_safe(float(protected_gotos),
                           float(baseline_filtered.total_gotos))

    # Backedge ratio — absolute, weighted across region records only.
    # The dispatcher is the CFG that matters for CFF's irreducibility
    # signal; function-level stubs are trivial and would dilute.
    total_edges = _sum_records(region_records, "mc_edges")
    total_backedges = _sum_records(region_records, "mc_backedges")
    backedge_ratio: float | None = (
        total_backedges / total_edges if total_edges > 0 else None
    )

    # Coverage — fraction of the unprotected binary's CFG budget that
    # ended up in the filter. Denominator = whole-source total blocks.
    coverage = ratio_safe(
        float(baseline_filtered.total_blocks),
        float(baseline_total.total_blocks),
    )

    evidence = {
        "protected_blocks_total":       protected_blocks,
        "protected_blocks_in_cff":      _sum_records(region_records, "mc_blocks"),
        "protected_blocks_in_text":     _sum_records(function_records, "mc_blocks"),
        "protected_cyclomatic_total":   protected_cyc,
        "protected_gotos_total":        protected_gotos,
        "baseline_filtered_blocks":     baseline_filtered.total_blocks,
        "baseline_filtered_cyclomatic": baseline_filtered.total_cyclomatic,
        "baseline_filtered_gotos":      baseline_filtered.total_gotos,
        "baseline_filtered_functions":  baseline_filtered.function_count,
        "baseline_total_blocks":        baseline_total.total_blocks,
        "baseline_total_functions":     baseline_total.function_count,
        "protected_function_records":   len(function_records),
        "protected_region_records":     len(region_records),
        "filter_rva_count":             (
            len(baseline_filtered.filter_rvas)
            if baseline_filtered.filter_rvas is not None else 0
        ),
    }

    _LOG.info(
        "%s: cff — blocks %d/%d=%s cyc %d/%d=%s gotos %d/%d=%s "
        "ber=%s cov=%s",
        entry_name,
        protected_blocks, baseline_filtered.total_blocks, _fmt(blocks_amp),
        protected_cyc, baseline_filtered.total_cyclomatic, _fmt(cyc_amp),
        protected_gotos, baseline_filtered.total_gotos, _fmt(gotos_amp),
        _fmt(backedge_ratio), _fmt(coverage),
    )

    samples_by_metric["mc_blocks_amplification"].append(MetricSample(
        sample_name=entry_name, value=blocks_amp, evidence=evidence,
    ))
    samples_by_metric["mc_cyclomatic_amplification"].append(MetricSample(
        sample_name=entry_name, value=cyc_amp, evidence=evidence,
    ))
    samples_by_metric["mc_gotos_amplification"].append(MetricSample(
        sample_name=entry_name, value=gotos_amp, evidence=evidence,
    ))
    samples_by_metric["mc_backedge_ratio"].append(MetricSample(
        sample_name=entry_name, value=backedge_ratio, evidence=evidence,
    ))
    samples_by_metric["cff_coverage"].append(MetricSample(
        sample_name=entry_name, value=coverage, evidence=evidence,
    ))


def _fmt(r: float | None) -> str:
    return f"{r:.3f}" if r is not None else "n/a"


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    if sidecar_path is None:
        return (
            f"{entry_name}: build produced no sidecar (trace-hints off?) "
            f"— benchmark cannot identify the cff section"
        )
    try:
        return load_sidecar(sidecar_path)
    except Exception as e:  # noqa: BLE001 — fail-closed: one entry
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"
