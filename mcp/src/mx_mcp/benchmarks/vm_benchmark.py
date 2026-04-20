"""VM static benchmark — sidecar + on-disk bytecode entropy.

Complements the CFF microcode benchmark. Where CFF measurement needs a
full IDA + Hex-Rays round-trip, the VM benchmark is *static-only*:

1. Build the corpus entry with ``--no-packer`` so the VM section lands
   plaintext on disk (packed builds RC4-encrypt the section at build
   time; the decryption stub unwraps it only at runtime).
2. Parse the ``.mxtrace.json`` sidecar to learn the VM section's
   ``(rva, size)`` window and the count of ``VirtualizationPass``-
   emitted region labels.
3. Read the VM bytecode bytes from disk and compute two quality
   metrics over them (byte + bigram Shannon entropy), plus a pair of
   surface metrics (section size, region count).

## Metrics emitted

| Name | Direction | Kind | Meaning |
|---|---|---|---|
| ``vm_bytecode_entropy``         | ↑ | quality | Byte-level Shannon entropy of the VM section. Low values mean repeating opcodes / fixed operand patterns — an attacker can cluster them trivially. |
| ``vm_bytecode_bigram_entropy``  | ↑ | quality | 16-bit bigram Shannon entropy. Catches short-range repetition that single-byte entropy masks (e.g. a common two-byte opcode prefix). |
| ``vm_bytecode_bytes``           | ↑ | surface | Raw VM section size. Zero means virtualization pass did not run or the corpus entry had no ``MX_VM_BEGIN/END`` markers. |

## Failure modes

Fail-closed: every failure lands in ``BenchmarkResult.errors`` and the
benchmark still returns aggregated metrics from the healthy entries.
The current error surface:

* Build failure (``BuilderError``) — no samples for that entry.
* Missing / empty VM section in the sidecar — entry skipped.
* Sidecar missing — entry skipped (rebuild with ``--trace-hints``).
* PE section lookup failure — bytes unreadable, entry skipped.

No single-entry failure fails the whole benchmark; the caller gets
partial data with an explicit ``errors`` list they can escalate.
"""

from __future__ import annotations

import logging
import math
import tempfile
import time
from collections import Counter
from pathlib import Path

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
    build_protected,
    resolve_builder_path,
)
from mx_mcp.common.pe_reader import (
    NotAPeError,
    SectionNotFoundError,
    read_section_bytes,
)
from mx_mcp.common.sidecar import Sidecar, load_sidecar


_LOG = logging.getLogger(__name__)


# Metric declarations.
#
# Scales centre ≈0.5 on the current ``strong`` defence level against
# the seed corpus (measured: byte entropy 5.93, bigram entropy 8.18,
# 16.2 KB bytecode, 1 region). Rationale for each endpoint:
#
# * ``vm_bytecode_entropy``        — Shannon byte entropy has a hard
#   upper bound of 8.0 (uniform bytes). Structured opcode streams land
#   in the 5–6 bit range on our encoder; a well-shuffled VM with
#   varied operand sizes could approach ~7+. Scale ``[4.0, 7.5]`` flags
#   anything below 4 bits as trivially patterned (weak) and rewards
#   near-uniform encodings (strong). p90=5.93 → score≈0.55.
# * ``vm_bytecode_bigram_entropy`` — Contiguous byte-pair entropy.
#   Max 16.0 but real encoded streams hit ~8–11 because adjacent
#   bytes are correlated (opcode then operand). Scale ``[6.0, 10.5]``
#   tracks the realistic band; strong=10.5 means the encoder has
#   broken most short-range correlations. p90=8.18 → score≈0.48.
# * ``vm_bytecode_bytes``          — Surface metric: 0 means the VM
#   pass ran but emitted nothing (or wasn't run at all). 32 KiB of
#   virtualized code is a reasonable "strong deployment" target for
#   the seed corpus; expand ``strong_value`` as the corpus grows into
#   larger inputs. p90=16.2 KiB → score≈0.49.
#
# A previous revision exposed ``vm_region_count`` (count of
# ``MX_VM_BEGIN/_END`` pairs). Removed: that count is source-code
# dependent, not protector-controlled — an entry with ten markers
# scores 10× higher than one with a single marker for reasons
# unrelated to defence quality. Its only honest signal (pass ran at
# all) is already covered by ``vm_bytecode_bytes=0`` as a regression
# alarm.
#
# Retune after the corpus changes materially — these are declarative
# contracts with the reporting layer and no runtime code branches on
# them.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("vm_bytecode_entropy",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=4.0, strong_value=7.5)),
    ("vm_bytecode_bigram_entropy",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=6.0, strong_value=10.5)),
    ("vm_bytecode_bytes",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=32768.0)),
)


@register_benchmark
class VmStaticBenchmark(IBenchmark):
    """VM static-analysis benchmark — entropy + surface metrics."""

    name = "vm_static"
    description = (
        "Static VM bytecode metrics on VM-tagged corpus entries. "
        "Emits vm_bytecode_entropy / vm_bytecode_bigram_entropy as "
        "quality signals and vm_bytecode_bytes as a surface indicator. "
        "No emulation or decompilation required."
    )
    category = "vm"
    tier = "fast"
    corpus_tags = frozenset({"vm"})

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name,
                category=self.category,
                tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=["no corpus entries tagged 'vm'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        # Protected binaries land in a temp dir that disappears at the
        # end of the benchmark — we don't persist them between runs.
        with tempfile.TemporaryDirectory(prefix="mx_mcp_vm_bench_") as td:
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
            _build_metric(name, direction, scale, samples_by_metric[name])
            for name, direction, scale in _METRIC_DEFS
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


def _empty_metric(
    name: str, direction: MetricDirection, scale: MetricScale,
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=[],
        aggregate=aggregate_numeric([]),
        scale=scale,
    )


def _build_metric(
    name: str,
    direction: MetricDirection,
    scale: MetricScale,
    samples: list[MetricSample],
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
        scale=scale,
    )


async def _process_entry(
    *,
    entry,
    output_dir: Path,
    builder_path: Path,
    workspace_root: Path,
    samples_by_metric: dict[str, list[MetricSample]],
) -> list[str]:
    """Build + sidecar + byte-scan for one corpus entry.

    Returns accumulated error strings. On success, appends one sample
    per metric to ``samples_by_metric`` in place.
    """
    protected_path = output_dir / f"{entry.name}.mx.exe"

    try:
        pb = await build_protected(
            unprotected=entry.unprotected_binary,
            output=protected_path,
            builder_path=builder_path,
            # Same reasoning as cff_benchmark: ``--no-packer`` keeps
            # the VM bytecode plaintext on disk. Packed builds would
            # hand us RC4 ciphertext — still high-entropy, but a
            # dishonest inflation of the quality metrics.
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
            f"virtualization pass disabled or no MX_VM_BEGIN/END markers in source"
        ]

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

    _LOG.info(
        "%s: vm section [0x%X..0x%X) %d B — entropy=%.3f bigram=%.3f",
        entry.name, vm_section.rva, vm_section.rva + vm_section.size,
        section_bytes, byte_entropy, bigram_entropy,
    )

    # ``sidecar.vm.handlers`` is still read for evidence (helps post-
    # mortem when a build misbehaves) but is no longer exposed as a
    # metric — see the _METRIC_DEFS comment for the rationale.
    evidence = {
        "rva": vm_section.rva,
        "sidecar_size": vm_section.size,
        "bytes_read": section_bytes,
        "dispatcher_rva": sidecar.vm.dispatcher_rva,
        "virtualized_regions": len(sidecar.vm.handlers),
    }
    sample_name = entry.name

    values: dict[str, float | int] = {
        "vm_bytecode_entropy": byte_entropy,
        "vm_bytecode_bigram_entropy": bigram_entropy,
        "vm_bytecode_bytes": section_bytes,
    }
    for metric_name, value in values.items():
        samples_by_metric[metric_name].append(MetricSample(
            sample_name=sample_name, value=value, evidence=evidence,
        ))

    return []


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    """Return the parsed sidecar or an error-string for the entry's
    ``errors`` list.

    Extracted so ``_process_entry`` reads top-to-bottom with one
    success path and a labelled early-return per failure mode.
    """
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
