"""VM static benchmark — bytecode density + entropy.

Complements the CFF microcode benchmark. Where CFF measurement needs a
full IDA + Hex-Rays round-trip on the *protected* artefact, the VM
benchmark is static-only on the numerator side:

1. Measure the unprotected source's ``.text`` virtual size via the
   shared baseline cache (trivial PE header read inside the baseline
   provider; the companion IDA run is reused if another benchmark
   primed the cache).
2. Build the corpus entry with ``--no-packer`` so the VM section
   lands plaintext on disk (packed builds RC4-encrypt the section at
   build time; the decryption stub unwraps it only at runtime).
3. Parse the ``.mxtrace.json`` sidecar to learn the VM section's
   ``(rva, size)`` window and the count of ``VirtualizationPass``-
   emitted region labels.
4. Read the VM bytecode bytes from disk and compute the quality
   metrics over them.

## Metrics

| Name | Direction | Kind | Meaning |
|---|---|---|---|
| ``vm_bytecode_density``         | ↑ | ratio   | ``bytecode_bytes / unprotected_.text_virtual_size``. 1.0 = VM pass emitted bytecode equal in size to the whole original code; >1.0 = bytecode bigger than source. Corpus-independent — a 10 KB entry with 2 KB bytecode and a 100 KB entry with 20 KB both land at 0.2. |
| ``vm_bytecode_entropy``         | ↑ | absolute | Byte-level Shannon entropy (bits / byte). Low values mean repeating opcodes / fixed operand patterns — trivial to cluster. Already unit-normalised by construction ([0, 8]); no per-binary baseline needed. |
| ``vm_bytecode_bigram_entropy``  | ↑ | absolute | 16-bit bigram Shannon entropy. Catches short-range repetition that single-byte entropy masks (e.g. a common two-byte opcode prefix). Same unit-normalised rationale as the single-byte entropy. |

``vm_bytecode_bytes`` (a previous metric) is no longer scored on its
own. The density ratio captures "how much bytecode per byte of source"
which is the useful signal; the raw count remains in per-sample
evidence for post-mortem but aggregating it produced a corpus-size
dependent number that the density metric supersedes.

## Pre-protected entries

Excluded. A legacy pre-protected binary has no unprotected source
against which to measure ``.text`` — the density ratio is undefined.
Mixing density samples with "no-signal" filler corrupts the aggregate.

## Failure modes

Fail-closed: every failure lands in ``BenchmarkResult.errors`` and the
benchmark still returns aggregated metrics from healthy entries.
Terminal states the benchmark handles explicitly:

* Baseline measurement failure (IDA / PE inspection) → entry errored.
* Pre-protected entry → entry errored (no baseline source).
* Build failure → entry errored.
* Missing / empty VM section in sidecar → entry errored.
* Missing sidecar → entry errored (rebuild with ``--trace-hints``).
* PE section lookup failure → entry errored.
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


# Metric declarations.
#
# Scale rationale (initial pass — retune in commit 4 calibration):
#
# * ``vm_bytecode_density`` — weak 0.0 (pass ran but emitted nothing)
#   / strong 2.0 (bytecode is 2× the original code footprint — heavy
#   virtualisation). Typical measurements on the seed corpus land in
#   the 0.05–0.5 band; the anchor leaves generous headroom for
#   corpora with heavier VM coverage.
#
# * ``vm_bytecode_entropy`` — unchanged scale from the pre-refactor
#   revision. Shannon byte entropy with a hard upper bound of 8.0.
#   Scale ``[4.0, 7.5]`` flags anything below 4 bits as trivially
#   patterned (weak) and rewards near-uniform encodings (strong).
#
# * ``vm_bytecode_bigram_entropy`` — unchanged scale. Max 16.0, but
#   real encoded streams hit 8–11 because adjacent bytes are
#   correlated (opcode then operand). Scale ``[6.0, 10.5]`` tracks
#   the realistic band; strong=10.5 means the encoder has broken
#   most short-range correlations.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("vm_bytecode_density",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=2.0)),
    ("vm_bytecode_entropy",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=4.0, strong_value=7.5)),
    ("vm_bytecode_bigram_entropy",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=6.0, strong_value=10.5)),
)


@register_benchmark
class VmStaticBenchmark(IBenchmark):
    """VM static-analysis benchmark — bytecode density + entropy."""

    name = "vm_static"
    description = (
        "Static VM bytecode metrics on VM-tagged corpus entries. "
        "Emits vm_bytecode_density as a corpus-independent amplification "
        "ratio (bytecode bytes / unprotected .text virtual size) plus "
        "byte + bigram Shannon entropies as absolute quality signals."
    )
    category = "vm"
    tier = "fast"
    corpus_tags = frozenset({"vm"})

    def __init__(
        self,
        *,
        baseline_cache: CfgBaselineCache | None = None,
    ) -> None:
        """Construct the benchmark.

        ``baseline_cache`` is optional for testability. The registry
        instantiates via ``cls()`` — the first ``run`` call lazy-creates
        a default cache wrapping :class:`IdaCfgBaselineProvider`.
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
    """Baseline + build + sidecar + byte-scan for one entry.

    Returns accumulated error strings. On success, appends one sample
    per metric to ``samples_by_metric`` in place.
    """
    if entry.is_pre_protected:
        return [
            f"{entry.name}: pre-protected — no unprotected source to "
            f"measure bytecode density against"
        ]

    if entry.unprotected_binary is None:
        return [f"{entry.name}: corpus entry has no unprotected source"]

    # 1. Baseline — only ``text_section_size`` is needed here, but the
    #    cache stores the full CfgBaseline so another benchmark (cff)
    #    can reuse the IDA pass. Requesting the baseline reuses any
    #    pre-existing cache entry transparently.
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
            # ``--no-packer`` so the VM section lands plaintext on
            # disk. Packed builds would hand us RC4 ciphertext —
            # still high-entropy, but dishonestly so.
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
            f"virtualization pass disabled or no MX_VM_BEGIN/END "
            f"markers in source"
        ]

    try:
        bytecode = read_section_bytes(
            pb.protected_binary, vm_section.rva, vm_section.size,
        )
    except (NotAPeError, SectionNotFoundError) as e:
        return [f"{entry.name}: VM bytes read failed: {type(e).__name__}: {e}"]
    except OSError as e:
        return [f"{entry.name}: VM bytes IO error: {e}"]

    # 3. Compute scored quantities.
    byte_entropy = _shannon_byte_entropy(bytecode)
    bigram_entropy = _shannon_bigram_entropy(bytecode)
    section_bytes = len(bytecode)
    density = ratio_safe(
        float(section_bytes), float(baseline.text_section_size),
    )

    _LOG.info(
        "%s: vm section [0x%X..0x%X) %d B / baseline.text %d B → "
        "density=%s entropy=%.3f bigram=%.3f",
        entry.name, vm_section.rva, vm_section.rva + vm_section.size,
        section_bytes, baseline.text_section_size,
        f"{density:.4f}" if density is not None else "n/a",
        byte_entropy, bigram_entropy,
    )

    evidence = {
        "rva": vm_section.rva,
        "sidecar_size": vm_section.size,
        "bytecode_bytes": section_bytes,
        "baseline_text_size": baseline.text_section_size,
        "dispatcher_rva": sidecar.vm.dispatcher_rva,
        "virtualized_regions": len(sidecar.vm.handlers),
    }
    sample_name = entry.name

    values: dict[str, float | int | None] = {
        "vm_bytecode_density": density,
        "vm_bytecode_entropy": byte_entropy,
        "vm_bytecode_bigram_entropy": bigram_entropy,
    }
    for metric_name, value in values.items():
        samples_by_metric[metric_name].append(MetricSample(
            sample_name=sample_name, value=value, evidence=evidence,
        ))

    return []


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    """Return the parsed sidecar or an entry-level error string."""
    if sidecar_path is None:
        return (
            f"{entry_name}: build produced no sidecar (trace-hints off?) "
            f"— benchmark cannot identify the vm section"
        )
    try:
        return load_sidecar(sidecar_path)
    except Exception as e:  # noqa: BLE001 — fail-closed: one entry, not the whole run
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"


# ============================================================================
# Entropy helpers
#
# Kept private because they encode specific definitions tied to this
# benchmark's interpretation (log₂-base Shannon over the full byte
# population; bigrams as contiguous 16-bit windows). Anyone wanting a
# more general facility should port these to ``common/`` deliberately.
# ============================================================================


def _shannon_byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits over the byte population of ``data``.

    Returns ``0.0`` for empty / single-byte input (no distribution to
    measure — callers treat it as the weakest end of the scale).
    """
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
    """Shannon entropy in bits over contiguous byte pairs.

    Bigram view catches short-range structure (e.g. a common two-byte
    opcode prefix) that single-byte entropy averages out. Returns
    ``0.0`` for inputs shorter than 3 bytes — two bigrams is the
    minimum where "distribution" is a meaningful word.
    """
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
