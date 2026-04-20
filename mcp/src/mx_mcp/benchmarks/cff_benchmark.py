"""CFF microcode benchmark — amplification ratios vs unprotected baseline.

## Method

For every CFF-tagged *buildable* corpus entry:

1. Measure the unprotected source via the shared baseline cache
   (:class:`CfgBaselineCache`). The cache runs IDA in per-function
   mode once per unique baseline binary within the benchmark run,
   aggregating block / cyclomatic / goto totals across every
   function it can lift.
2. Build a protected version of the same source.
3. Run IDA in **region** mode on the sidecar-reported ``.cff``
   section. Region mode is required because IDA does not recognise
   CFF dispatcher entries as functions — they're reachable only
   through indirect jumps from small ``.text`` trampolines, so
   "iterate all functions" misses them entirely.
4. Aggregate the per-region records (``.cff`` is normally one region
   = one record; multi-region support is preserved for future
   pipelines that split dispatchers) and divide by the baseline
   totals to produce amplification ratios.

## Pre-protected entries

Excluded up front. A pre-protected binary has no unprotected source
against which to measure a baseline, so the amplification ratios are
undefined. Mixing normalised and non-normalised samples across a
metric's distribution would corrupt the aggregate — better to surface
"this entry has no baseline" as an error than to quietly degrade into
incomparable numbers.

## Metrics

* ``mc_blocks_amplification``     — ↑ ``sum(protected .cff blocks) /
                                      sum(baseline all-function blocks)``.
                                      Values above 1.0 mean CFF emitted
                                      more microcode blocks in the
                                      dispatcher than existed in the
                                      entire source.
* ``mc_cyclomatic_amplification`` — ↑ same shape, cyclomatic complexity.
* ``mc_gotos_amplification``      — ↑ same shape, goto / ijmp counts.
                                      Tends higher than the block
                                      amplification because the
                                      dispatcher tail of every flattened
                                      state is a goto.
* ``mc_backedge_ratio``           — ↑ edge-weighted average across the
                                      region records. Absolute ratio in
                                      ``[0, 1]`` — already a ratio, so
                                      no per-binary normalisation.

All four are HIGHER_BETTER — a stronger CFF pass inflates every
quantity. ``mc_blocks`` / ``mc_gotos`` / ``mc_cyclomatic`` were raw
counts before this refactor; the amplification variants replace them
and the scale anchors land around mid-scale against the current
strong-level corpus (measured values drive commit 4 calibration).

## Failure modes

Fail-closed: every per-entry failure surfaces in
``BenchmarkResult.errors`` and the benchmark still aggregates
whichever entries succeeded. The recognised terminal states:

* ``baseline measurement failed`` — IDA / PE inspection of the
  unprotected binary failed (reports underlying reason).
* ``pre-protected — no baseline`` — entry is an archived artefact.
* ``build failed`` — builder returned non-zero or didn't produce the
  expected output.
* ``sidecar missing`` / ``no 'cff' section`` — trace hints disabled
  or build ran without CFG flattening.
* ``IDA missing`` / ``IDA exit=N`` — region-mode IDA launch failed.
* ``Hex-Rays not available`` — IDA ran but the decompiler plugin is
  absent / disabled.
* ``gen_microcode produced no blocks`` — the ``.cff`` bytes were
  unreadable (packer on?) or the range was invalid.
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


# IDAPython companion script — shared with the baseline provider. The
# CFF benchmark uses region mode (MX_MCP_IDA_REGIONS env var) to
# point IDA at the .cff byte range; the baseline provider omits that
# env var so the script walks every function.
SCRIPT_PATH = (
    Path(_ida_pkg.__file__).parent / "scripts" / "cff_metrics.py"
)


# Metric declarations — all HIGHER_BETTER.
#
# Scale calibration (empirical, post-smoke run against the seed
# corpus at strong-level protection):
#
#   Observed p50 values — ``mc_blocks_amplification`` 0.0224,
#   ``mc_cyclomatic_amplification`` 0.0196,
#   ``mc_gotos_amplification`` 0.0703, ``mc_backedge_ratio`` 0.26.
#
# The amplification ratios are small because the CFF pass only
# touches ``MX_CFF_BEGIN/END``-delimited regions — most of the
# unprotected source's microcode is outside that scope, pulling the
# denominator up. Anchors are set so the current strong-level output
# lands around score 0.45–0.5 (mid-scale). This gives both an
# upward runway for future CFF improvements and a visible drop
# window if a regression reduces flattening strength.
#
# * ``mc_blocks_amplification`` — weak 0.0, strong 0.05. p50 0.0224
#   → score ≈ 0.448.
# * ``mc_cyclomatic_amplification`` — weak 0.0, strong 0.04. p50
#   0.0196 → score ≈ 0.490.
# * ``mc_gotos_amplification`` — weak 0.0, strong 0.15. Gotos amplify
#   harder than blocks (each flattened state's tail is a goto) so the
#   scale span is wider. p50 0.0703 → score ≈ 0.469.
# * ``mc_backedge_ratio`` — weak 0.0, strong 0.6. Absolute ratio in
#   ``[0, 1]``. p50 0.26 → score ≈ 0.433.
#
# When the CFF pass gets a material upgrade, re-run
# ``scripts/_smoke_vm_and_chart.py`` and nudge the ``strong_value``
# upward so the new p50 sits near 0.5 again.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("mc_blocks_amplification",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.05)),
    ("mc_cyclomatic_amplification",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.04)),
    ("mc_gotos_amplification",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.15)),
    ("mc_backedge_ratio",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.6)),
)


@register_benchmark
class CffMicrocodeBenchmark(IBenchmark):
    """HexRays microcode CFF metrics — amplification vs unprotected."""

    name = "cff_microcode"
    description = (
        "HexRays microcode complexity on CFF-tagged corpus entries. "
        "Emits mc_{blocks,cyclomatic,gotos}_amplification as ratios "
        "of protected .cff section totals over unprotected-baseline "
        "totals (higher = more aggressive flattening), plus "
        "mc_backedge_ratio as an absolute measure of CFG "
        "irreducibility."
    )
    category = "cff"
    tier = "fast"
    corpus_tags = frozenset({"cff"})

    def __init__(
        self,
        *,
        baseline_cache: CfgBaselineCache | None = None,
    ) -> None:
        """Construct the benchmark.

        ``baseline_cache`` is optional for testability — the registry
        instantiates via ``cls()`` and the first ``run()`` lazily
        creates a default cache wrapping :class:`IdaCfgBaselineProvider`.
        Tests inject a stub-backed cache directly.
        """
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
        """Lazy-create the baseline cache on first ``run`` call.

        Kept as a one-liner method rather than inline in ``run`` so
        tests that subclass the benchmark can override the default
        without copy-pasting the rest of ``run``.
        """
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
    """Baseline + build + region-IDA + amplification for one entry.

    Returns the accumulated error strings for this entry (empty on
    full success). Samples append in place to ``samples_by_metric``.
    """
    if entry.is_pre_protected:
        return [
            f"{entry.name}: pre-protected — no unprotected source to "
            f"measure amplification against"
        ]

    if entry.unprotected_binary is None:
        # Belt-and-braces — Corpus.load should have rejected this.
        return [f"{entry.name}: corpus entry has no unprotected source"]

    # 1. Baseline measurement (cached across entries + benchmarks that
    #    share this cache instance).
    try:
        baseline = await baseline_cache.get(entry.unprotected_binary)
    except BaselineError as e:
        return [f"{entry.name}: baseline measurement failed: {e}"]
    except FileNotFoundError as e:
        return [f"{entry.name}: baseline input missing: {e}"]

    # 2. Build protected + sidecar.
    try:
        pb = await ensure_protected(
            entry,
            output_dir=output_dir,
            builder_path=builder_path,
            # ``--no-packer`` keeps .cff plaintext on disk so IDA can
            # analyse the dispatcher bytes directly. A packed build
            # would have the section RC4-encrypted on disk (decrypted
            # only at runtime by the stub) and the benchmark would
            # see ciphertext. Packer quality has its own benchmark.
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

    regions = [{
        "name": "cff_section",
        "rva": cff_section.rva,
        "size": cff_section.size,
    }]

    # 3. Region-mode IDA on the protected .cff section.
    try:
        ida_result = await run_ida_script(
            binary=pb.protected_binary,
            script=SCRIPT_PATH,
            extra_env={"MX_MCP_IDA_REGIONS": json.dumps(regions)},
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

    if not records:
        errors.append(
            f"{entry.name}: gen_microcode produced no blocks for the "
            f"cff section [0x{cff_section.rva:X}..{cff_section.rva + cff_section.size:X}) "
            f"— bytes may be encrypted (packer on?) or invalid"
        )
        return errors

    # 4. Aggregate protected-side totals + amplification ratios.
    _record_amplification_samples(
        entry_name=entry.name,
        baseline=baseline,
        records=records,
        samples_by_metric=samples_by_metric,
    )
    return errors


# ============================================================================
# Aggregation + sample emission
# ============================================================================


def _record_amplification_samples(
    *,
    entry_name: str,
    baseline: CfgBaseline,
    records: list[dict],
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    """Convert per-region records into four per-entry samples.

    Multi-region aggregation semantics:

    * ``mc_blocks`` / ``mc_cyclomatic`` / ``mc_gotos`` are summed
      across regions (per-region independence — each region contributes
      its own microcode blocks to the CFF section).
    * ``mc_backedge_ratio`` is computed from the summed edge and
      back-edge counts, giving an edge-weighted average across regions
      instead of an unweighted mean (a region with 100 edges should
      pull the ratio harder than one with 5).
    """
    total_blocks = sum(int(r.get("mc_blocks", 0)) for r in records)
    total_cyc = sum(int(r.get("mc_cyclomatic", 0)) for r in records)
    total_gotos = sum(int(r.get("mc_gotos", 0)) for r in records)
    total_edges = sum(int(r.get("mc_edges", 0)) for r in records)
    total_backedges = sum(int(r.get("mc_backedges", 0)) for r in records)

    blocks_amp = ratio_safe(float(total_blocks), float(baseline.total_blocks))
    cyc_amp = ratio_safe(float(total_cyc), float(baseline.total_cyclomatic))
    gotos_amp = ratio_safe(float(total_gotos), float(baseline.total_gotos))

    if total_edges > 0:
        backedge_ratio: float | None = total_backedges / total_edges
    else:
        # No edges across any region — CFG is a single node or
        # gen_microcode returned degenerate blocks. Report as error
        # sample (None) rather than silent 0.0 so aggregation flags it.
        backedge_ratio = None

    evidence = {
        "protected_blocks": total_blocks,
        "protected_cyclomatic": total_cyc,
        "protected_gotos": total_gotos,
        "protected_edges": total_edges,
        "protected_backedges": total_backedges,
        "baseline_blocks": baseline.total_blocks,
        "baseline_cyclomatic": baseline.total_cyclomatic,
        "baseline_gotos": baseline.total_gotos,
        "baseline_function_count": baseline.function_count,
        "region_count": len(records),
        # Per-region peek — ea / rva / mba_maturity of the first
        # region so post-mortem on a single-region entry (the typical
        # case) does not require cross-referencing another tool.
        "first_region_ea": records[0].get("ea"),
        "first_region_rva": records[0].get("rva"),
        "first_region_mba_maturity": records[0].get("mba_maturity"),
    }

    _LOG.info(
        "%s: cff — blocks %d/%d=%s cyc %d/%d=%s gotos %d/%d=%s ber=%s",
        entry_name,
        total_blocks, baseline.total_blocks,
        _fmt_ratio(blocks_amp),
        total_cyc, baseline.total_cyclomatic,
        _fmt_ratio(cyc_amp),
        total_gotos, baseline.total_gotos,
        _fmt_ratio(gotos_amp),
        _fmt_ratio(backedge_ratio),
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


def _fmt_ratio(r: float | None) -> str:
    return f"{r:.3f}" if r is not None else "n/a"


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    """Return the parsed sidecar or an entry-level error string."""
    if sidecar_path is None:
        return (
            f"{entry_name}: build produced no sidecar (trace-hints off?) "
            f"— benchmark cannot identify the cff section"
        )
    try:
        return load_sidecar(sidecar_path)
    except Exception as e:  # noqa: BLE001 — fail-closed: one entry, not the whole run
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"
