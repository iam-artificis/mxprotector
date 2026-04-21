"""VM static benchmark — filtered density + coverage + entropy.

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
     is the natural denominator for bytecode density.
   * ``baseline_total`` — unrestricted. Its ``text_section_size``
     is the denominator for coverage.

4. Read the ``.vm`` section bytes from disk, compute entropy metrics,
   and divide by ``baseline_filtered.functions_total_bytes`` for the
   density ratio.

## Metrics

| Name | Direction | Kind |
|---|---|---|
| ``vm_bytecode_density``        | ↑ | ratio  | ``vm_bytes / baseline_filtered.functions_total_bytes``. Expected > 1 — VM bytecode per byte of source code the pass replaced. |
| ``vm_bytecode_entropy``        | ↑ | absolute | Byte-level Shannon entropy of the ``.vm`` section. |
| ``vm_bytecode_bigram_entropy`` | ↑ | absolute | 16-bit bigram Shannon entropy. |
| ``vm_coverage``                | ↑ | ratio  | ``baseline_filtered.functions_total_bytes / baseline_total.text_section_size``. Fraction of the unprotected ``.text`` footprint that got VM'd. |

Density and coverage are orthogonal: high density on a tiny coverage
means "heavy VM on a few hot paths", high density + high coverage
means "heavy VM across the whole binary".

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
#   vm_bytecode_density          186x    → strong=350.0  → score ≈ 0.53
#   vm_bytecode_entropy          5.90    → strong=7.5    → score ≈ 0.56
#   vm_bytecode_bigram_entropy   8.08    → strong=10.5   → score ≈ 0.48
#   vm_coverage                  0.089%  → strong=0.002  → score ≈ 0.45
#
# Density and coverage anchors are tight against the seed corpus
# because user-written code being virtualised is a small fraction of
# the binary's total .text (most of which is CRT / runtime bloat);
# within that slice the VM pass emits ~186 bytes of bytecode per byte
# of source. On real binaries with more user code, coverage scales
# up and density may drift down — retune ``strong_value`` upward for
# coverage, possibly downward for density if the bytecode encoder
# gets tighter.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("vm_bytecode_density",
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
        "vm_bytecode_density = bytecode bytes / sum of unprotected "
        "source-function sizes the pass virtualised. vm_coverage = "
        "same numerator against the whole unprotected .text. Plus "
        "byte + bigram Shannon entropies on the bytecode."
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

    density = ratio_safe(
        float(section_bytes),
        float(baseline_filtered.functions_total_bytes),
    )
    coverage = ratio_safe(
        float(baseline_filtered.functions_total_bytes),
        float(baseline_total.text_section_size),
    )

    _LOG.info(
        "%s: vm section [0x%X..0x%X) %dB / baseline_filtered "
        "functions_total_bytes %dB → density=%s entropy=%.3f "
        "bigram=%.3f coverage=%s",
        entry.name, vm_section.rva, vm_section.rva + vm_section.size,
        section_bytes, baseline_filtered.functions_total_bytes,
        _fmt(density), byte_entropy, bigram_entropy, _fmt(coverage),
    )

    evidence = {
        "rva": vm_section.rva,
        "sidecar_size": vm_section.size,
        "bytecode_bytes": section_bytes,
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
        "vm_bytecode_density":        density,
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
