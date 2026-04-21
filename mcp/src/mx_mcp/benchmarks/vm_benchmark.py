"""VM static benchmark — filtered footprint + coverage + entropy.

Mirrors the CFF benchmark's normalisation pattern but over VM-protected
regions.

## Method

For every VM-tagged buildable corpus entry:

1. Build a protected version.
2. Extract the list of VM-protected function RVAs from the sidecar's
   ``protected_functions`` array (``kind == "vm"``). These locate, in
   the input PE's address space, the regions the VM pass replaced
   with stubs.
3. Measure two baselines against the unprotected binary:

   * ``baseline_filtered`` — per-function aggregates restricted to
     the VM'd functions. ``functions_total_bytes`` on this baseline
     is the natural denominator for the footprint ratio.
   * ``baseline_total`` — unrestricted. Its ``text_section_size``
     is the denominator for coverage.

4. Read the ``.vm`` section bytes from disk, compute entropy metrics,
   and divide by ``baseline_filtered.functions_total_bytes`` for the
   footprint ratio.

## Numerator caveat — why this is *footprint*, not pure bytecode

The ``.vm`` section contains everything the VM pass emits: the actual
opcode-stream **bytecode** plus the **VM machine** that executes it
(dispatcher, per-opcode handlers, handler table, key material). The
VM machine is a fixed-ish cost *per region* (one blob per source
region, each blob self-contained). On a corpus with tiny source
functions the machine overhead dominates — e.g. a 70 B source
function produces a ~16 KB ``.vm`` blob where only a fraction is the
actual bytecode stream.

Without backend support for emitting per-segment offsets
(:issue:`x64_vm_backend phase 6`), we cannot cleanly separate
bytecode from machine bytes in the sidecar. The metric therefore
measures the *total VM footprint per byte of source code*, not the
pure bytecode expansion factor. The name ``vm_footprint_density``
reflects that honestly; a future ``vm_bytecode_density`` will land
once the backend publishes sub-blob labels.

Interpretation:

* High ``vm_footprint_density`` — the VM pass emits a lot of binary
  per byte of source. This includes legitimate bytecode growth **and**
  per-region machine overhead. Useful signal for "how much .vm
  footprint does the defender pay", **not** a direct measure of
  bytecode verbosity.
* Values in the hundreds are realistic for small source regions
  because the per-region VM machine is a fixed ~10-20 KB.

## Metrics

| Name | Direction | Kind |
|---|---|---|
| ``vm_footprint_density``       | ↑ | ratio    | ``vm_section_bytes / baseline_filtered.functions_total_bytes``. VM footprint (bytecode + dispatcher + handlers) per byte of source. |
| ``vm_bytecode_entropy``        | ↑ | absolute | Byte-level Shannon entropy of the ``.vm`` section. |
| ``vm_bytecode_bigram_entropy`` | ↑ | absolute | 16-bit bigram Shannon entropy. |
| ``vm_coverage``                | ↑ | ratio    | ``baseline_filtered.functions_total_bytes / baseline_total.text_section_size``. Fraction of the unprotected ``.text`` footprint that got VM'd. |

Footprint and coverage are orthogonal: high footprint on a tiny
coverage means "heavy VM on a few hot paths", high footprint + high
coverage means "heavy VM across the whole binary".

Pre-protected entries are rejected — no unprotected baseline exists.
"""

from __future__ import annotations

import logging
import math
import tempfile
import time
from collections import Counter
from pathlib import Path

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
from mx_mcp.common.pe_reader import (
    NotAPeError,
    SectionNotFoundError,
    read_section_bytes,
)
from mx_mcp.common.ratio import ratio_safe
from mx_mcp.common.sidecar import Sidecar, load_sidecar


_LOG = logging.getLogger(__name__)


# Empirical calibration against the seed corpus at strong-level
# protection (p50 observations from ``scripts/_smoke_vm_and_chart.py``):
#
#   vm_footprint_density         186x    → strong=350.0  → score ≈ 0.53
#   vm_bytecode_entropy          5.90    → strong=7.5    → score ≈ 0.56
#   vm_bytecode_bigram_entropy   8.08    → strong=10.5   → score ≈ 0.48
#   vm_coverage                  0.089%  → strong=0.002  → score ≈ 0.45
#
# Footprint values in the hundreds are dominated by per-region VM
# machine overhead (dispatcher + handlers + tables ≈ 10-20 KB per
# region, fixed-ish), not pure bytecode expansion. A 70 B source
# function yields a ~16 KB VM blob because the machine ships with
# every blob. On a corpus with larger source regions the per-region
# overhead dilutes and the ratio approaches the true bytecode
# expansion factor — retune ``strong_value`` downward as the corpus
# grows, or split the metric once the x64_vm_backend exposes per-
# segment offsets (see module docstring).
#
# Coverage anchors are tight because the seed corpus binaries are
# CRT-dominated; user code under ``MX_VM_BEGIN/END`` is a small
# fraction of the total ``.text``.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("vm_footprint_density",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=1.0, strong_value=350.0)),
    ("vm_bytecode_entropy",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=4.0, strong_value=7.5)),
    ("vm_bytecode_bigram_entropy",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=6.0, strong_value=10.5)),
    ("vm_coverage",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.002)),
)


@register_benchmark
class VmStaticBenchmark(IBenchmark):
    """VM filtered density + coverage + entropy."""

    name = "vm_static"
    description = (
        "Static VM metrics on VM-tagged corpus entries. "
        "vm_footprint_density = .vm section bytes (bytecode + "
        "dispatcher + handlers, not separable today) / sum of "
        "unprotected source-function sizes the pass virtualised. "
        "vm_coverage = function bytes over the whole unprotected "
        ".text. Plus byte + bigram Shannon entropies on the .vm "
        "bytes as a randomness signal independent of source size."
    )
    category = "vm"
    tier = "fast"
    corpus_tags = frozenset({"vm"})

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
                errors=["no corpus entries tagged 'vm'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)
        baseline_cache = self._resolve_baseline_cache()

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_vm_bench_") as td:
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
    """Build → sidecar → baselines → protected bytes → samples."""
    if entry.is_pre_protected:
        return [
            f"{entry.name}: pre-protected — no unprotected source to "
            f"measure bytecode density against"
        ]
    if entry.unprotected_binary is None:
        return [f"{entry.name}: corpus entry has no unprotected source"]

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
    sidecar: Sidecar = sidecar_or_err

    vm_section = sidecar.sections.get("vm")
    if vm_section is None or vm_section.size == 0:
        return [
            f"{entry.name}: sidecar has no (non-empty) 'vm' section — "
            f"virtualization pass disabled or no MX_VM_BEGIN/END markers"
        ]

    filter_rvas = _filter_rvas_from_sidecar(sidecar, kind="vm")
    if not filter_rvas:
        return [
            f"{entry.name}: sidecar has no vm-kind entries in "
            f"protected_functions — cannot filter baseline"
        ]

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

    try:
        bytecode = read_section_bytes(
            pb.protected_binary, vm_section.rva, vm_section.size,
        )
    except (NotAPeError, SectionNotFoundError) as e:
        return [f"{entry.name}: VM bytes read failed: {type(e).__name__}: {e}"]
    except OSError as e:
        return [f"{entry.name}: VM bytes IO error: {e}"]

    byte_entropy = _shannon_byte_entropy(bytecode)
    bigram_entropy = _shannon_bigram_entropy(bytecode)
    section_bytes = len(bytecode)

    # Footprint = whole .vm section / source function bytes. This is
    # biased upward by the per-region VM machine (dispatcher + handler
    # table + handlers) that ships inside every blob — see module
    # docstring. A pure-bytecode variant will land once x64_vm_backend
    # publishes per-segment offsets.
    footprint = ratio_safe(
        float(section_bytes),
        float(baseline_filtered.functions_total_bytes),
    )
    coverage = ratio_safe(
        float(baseline_filtered.functions_total_bytes),
        float(baseline_total.text_section_size),
    )

    _LOG.info(
        "%s: vm section [0x%X..0x%X) %dB / baseline_filtered "
        "functions_total_bytes %dB → footprint=%s entropy=%.3f "
        "bigram=%.3f coverage=%s",
        entry.name, vm_section.rva, vm_section.rva + vm_section.size,
        section_bytes, baseline_filtered.functions_total_bytes,
        _fmt(footprint), byte_entropy, bigram_entropy, _fmt(coverage),
    )

    evidence = {
        "rva": vm_section.rva,
        "sidecar_size": vm_section.size,
        # ``vm_section_bytes`` is the raw numerator of footprint —
        # ALL bytes in .vm, including VM machine overhead. Renamed
        # from ``bytecode_bytes`` which was semantically misleading
        # (the section is not pure bytecode, as noted in the module
        # docstring).
        "vm_section_bytes":               section_bytes,
        "baseline_filtered_functions":    baseline_filtered.function_count,
        "baseline_filtered_bytes":        baseline_filtered.functions_total_bytes,
        "baseline_total_text_size":       baseline_total.text_section_size,
        "baseline_total_functions":       baseline_total.function_count,
        "baseline_total_bytes":           baseline_total.functions_total_bytes,
        "dispatcher_rva":                 sidecar.vm.dispatcher_rva,
        "virtualized_regions":            len(sidecar.vm.handlers),
        "filter_rva_count":               len(filter_rvas),
    }
    sample_name = entry.name

    values: dict[str, float | int | None] = {
        "vm_footprint_density":       footprint,
        "vm_bytecode_entropy":        byte_entropy,
        "vm_bytecode_bigram_entropy": bigram_entropy,
        "vm_coverage":                coverage,
    }
    for metric_name, value in values.items():
        samples_by_metric[metric_name].append(MetricSample(
            sample_name=sample_name, value=value, evidence=evidence,
        ))

    return []


def _filter_rvas_from_sidecar(sidecar: Sidecar, *, kind: str) -> frozenset[int]:
    return frozenset(
        pf.rva for pf in sidecar.protected_functions if pf.kind == kind
    )


def _fmt(r: float | None) -> str:
    return f"{r:.4f}" if r is not None else "n/a"


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    if sidecar_path is None:
        return (
            f"{entry_name}: build produced no sidecar (trace-hints off?) "
            f"— benchmark cannot identify the vm section"
        )
    try:
        return load_sidecar(sidecar_path)
    except Exception as e:  # noqa: BLE001 — fail-closed: one entry
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"


# ============================================================================
# Entropy helpers (unchanged from the pre-normalisation revision).
# ============================================================================


def _shannon_byte_entropy(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    counts = Counter(data)
    total = len(data)
    acc = 0.0
    for c in counts.values():
        p = c / total
        acc -= p * math.log2(p)
    return acc


def _shannon_bigram_entropy(data: bytes) -> float:
    if len(data) < 3:
        return 0.0
    pairs = Counter(
        (data[i] << 8) | data[i + 1]
        for i in range(len(data) - 1)
    )
    total = sum(pairs.values())
    acc = 0.0
    for c in pairs.values():
        p = c / total
        acc -= p * math.log2(p)
    return acc
