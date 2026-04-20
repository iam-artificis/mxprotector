"""Packer benchmark — pe-sieve against fresh + legacy protected binaries.

The first benchmark that uses a real third-party attacker tool
(hasherezade/pe-sieve). Every metric here mirrors what an attacker
actually cares about:

* Did pe-sieve produce a usable PE dump? — ``pesieve_dumped_modules``.
* Did pe-sieve classify anything as an implanted PE image? —
  ``pesieve_implanted_pe``.
* How many modules did it flag in total? — ``pesieve_modified_total``.

All three are **lower-is-better**: more hits = weaker packer.
Scales land the current ``strong`` defence near 0.5 on the seed
corpus — retune when the corpus grows (see ``_METRIC_DEFS`` comment).

## Corpus coverage

The benchmark consumes entries tagged ``packer`` + ``exe``. Three
kinds appear in the fixture corpus:

1. **Fresh builds** — buildable entries (``pure_vm``, ``pure_cff``,
   ``mixed``). Tagged ``packer`` because the current builder always
   runs the packer pass unless ``--no-packer`` is passed.
2. **Legacy builds** — pre-protected entries (``legacy_*``) pointing
   at ``build_testapp/*.exe.packed``. These were produced by older
   builder versions; running the same pe-sieve against old vs new
   is the user-requested "then vs now" comparison on one chart.

Sidecar-dependent benchmarks (CFF / VM) skip the legacy entries
automatically because ``pre_sidecar`` is unset — the sidecar-less
path reports "no sidecar" and the entry drops.

## Child-process lifecycle

``pe-sieve`` scans a *running* process. The benchmark therefore:

1. Launches the protected binary (via the pe-sieve runner's
   controller) into a per-entry scratch directory.
2. Waits ``DEFAULT_DECRYPT_WAIT_MS`` so the packer has time to
   unwrap its encrypted sections in memory.
3. Invokes pe-sieve against the child PID with a hard timeout.
4. Collects report + dump files.
5. Terminates the child (the runner guarantees this in a ``finally``).

If the binary exits before step 2 (very short-lived test app or
anti-debug trip), the entry is reported with a clear error and the
next entry continues.

## Why ``child_args`` from the entry is forwarded

Some corpus entries are designed to do meaningful work before
exiting (e.g. pure_vm loops); others finish in milliseconds. The
``launch_args`` field on ``CorpusEntry`` lets an entry request
``--hold`` / ``--sleep`` style arguments so pe-sieve has a running
process to attach to. Legacy entries leave this empty — they run to
completion on their own cadence.
"""

from __future__ import annotations

import logging
import tempfile
import time
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
    ensure_protected,
    resolve_builder_path,
)
from mx_mcp.common.corpus import CorpusEntry
from mx_mcp.unpacking.pe_sieve.runner import (
    DEFAULT_DECRYPT_WAIT_MS,
    DEFAULT_SCAN_TIMEOUT_S,
    PesieveRunResult,
    run_pesieve,
)


_LOG = logging.getLogger(__name__)


# Metric declarations.
#
# All three are LOWER_BETTER, so ``weak_value > strong_value`` on the
# scale (strong = 0 hits, weak = "the packer is wide open"). Initial
# ranges are best guesses without calibration; #7 will retune them
# against real pe-sieve output on the seed corpus.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("pesieve_dumped_modules",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=5.0, strong_value=0.0)),
    ("pesieve_implanted_pe",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=3.0, strong_value=0.0)),
    ("pesieve_modified_total",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=10.0, strong_value=0.0)),
)


@register_benchmark
class PackerPeSieveBenchmark(IBenchmark):
    """pe-sieve unpack / implant detection against packer-tagged entries."""

    name = "packer_pesieve"
    description = (
        "Runs hasherezade/pe-sieve against every packer-tagged corpus "
        "entry — fresh builder output plus any legacy .exe.packed "
        "preserved under build_testapp/. Emits dumped_modules / "
        "implanted_pe / modified_total (all lower-is-better) as the "
        "core attacker-visibility signals."
    )
    category = "packer"
    tier = "fast"
    corpus_tags = frozenset({"packer", "exe"})

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags, match_all=True)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=["no corpus entries tagged 'packer' + 'exe'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_packer_") as td:
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
            benchmark=self.name, category=self.category, tier=self.tier,
            duration_ms=int((time.monotonic() - t0) * 1000),
            metrics=metrics, errors=errors,
        )


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
    entry: CorpusEntry,
    output_dir: Path,
    builder_path: Path,
    workspace_root: Path,
    samples_by_metric: dict[str, list[MetricSample]],
) -> list[str]:
    """Build (or resolve) + pe-sieve for one corpus entry.

    Returns the list of error strings accumulated for this entry.
    Per-metric samples are appended in-place to ``samples_by_metric``
    on success.
    """
    # 1. Obtain the protected binary (fresh build or pre-protected).
    try:
        pb = await ensure_protected(
            entry,
            output_dir=output_dir,
            builder_path=builder_path,
            # Packer is ON by default — this is the production-like
            # build and the surface pe-sieve is meant to attack.
            workspace_root=workspace_root,
        )
    except (BuilderError, FileNotFoundError) as e:
        return [f"{entry.name}: build failed: {e}"]

    # 2. Per-entry scratch directory for pe-sieve dumps / reports.
    entry_workdir = output_dir / f"pesieve_{entry.name}"
    entry_workdir.mkdir(parents=True, exist_ok=True)

    # 3. Run pe-sieve end-to-end. The runner handles child lifecycle
    #    (launch / wait for decryption / scan / terminate) and never
    #    raises — fail-closed at the per-entry boundary.
    result = await run_pesieve(
        binary=pb.protected_binary,
        workdir=entry_workdir,
        decrypt_wait_ms=DEFAULT_DECRYPT_WAIT_MS,
        scan_timeout_s=DEFAULT_SCAN_TIMEOUT_S,
        child_args=list(entry.launch_args) or None,
    )

    if not result.ok or result.report is None:
        return [f"{entry.name}: pe-sieve: {result.error or 'no report'}"]

    _record_samples(entry.name, result, samples_by_metric)
    return []


def _record_samples(
    entry_name: str,
    result: PesieveRunResult,
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    """Translate a :class:`PesieveRunResult` into per-metric samples."""
    assert result.report is not None  # caller-validated
    report = result.report

    dumped = report.dumped.modules
    implanted_pe = report.scanned.modified.implanted_pe
    modified_total = report.scanned.modified.total

    evidence = {
        "pid": report.pid,
        "pesieve_duration_ms": result.duration_ms,
        "pesieve_main_image": report.main_image_path,
        "pesieve_output_dir": report.output_dir,
        "dump_files": [str(p) for p in result.dump_files],
        "pesieve_errors": list(report.errors),
    }

    _LOG.info(
        "%s: pe-sieve %dms — dumped=%d implanted_pe=%d modified_total=%d",
        entry_name, result.duration_ms, dumped, implanted_pe, modified_total,
    )

    values: dict[str, int] = {
        "pesieve_dumped_modules": dumped,
        "pesieve_implanted_pe": implanted_pe,
        "pesieve_modified_total": modified_total,
    }
    for metric_name, value in values.items():
        samples_by_metric[metric_name].append(MetricSample(
            sample_name=entry_name, value=value, evidence=evidence,
        ))
