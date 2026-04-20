"""Packer benchmark — pe-sieve against fresh + legacy protected binaries.

The first benchmark that uses a real third-party attacker tool
(hasherezade/pe-sieve). The design choices below are deliberately
conservative about what the metrics *mean* so the resulting chart
does not overstate protection strength.

## Scored metrics (two of them)

* ``pesieve_dumped_modules`` — did pe-sieve walk away with usable PE
  dumps? Baseline on the current packer is 1 (the main image always
  gets REALIGNED and dumped) because we do not yet run any anti-dump
  pass. Scale ``[weak=1, strong=0]`` makes the baseline read as
  0.00 — an honest "zero anti-dump defence" signal. Future anti-dump
  work lifts the score towards 1.0.
* ``pesieve_fingerprint_count`` — how many distinct modules pe-sieve
  flagged as ``modified`` (patched / hooked / replaced / …).
  A *surface* metric, not a quality one: fewer distinct fingerprints
  = less for an attacker to lean on. Baseline is 1 (our own main
  image, patched by the packer by design). ``[weak=5, strong=0]``
  gives 0.80 at baseline — regressions that add visible fingerprints
  pull the score down.

## Canary (not scored, surfaced as benchmark errors)

* ``implanted_pe`` — pe-sieve classifies a module as an "implanted
  PE image" (process-hollowing / doppelgänging signature). A
  self-patching packer like ours never legitimately triggers this;
  baseline is 0 on every entry. Non-zero values are a *regression
  alarm*, not a score — they mean the protector accidentally made
  itself look like a hollowing attack. Surfaced per-entry in the
  benchmark's ``errors`` list with a ``CANARY`` prefix so a
  reviewer sees the alert even without reading evidence.

``modified_total``-as-score (previous revision) was removed because
its "always 1" baseline scored 0.67 regardless of real protection,
producing a misleadingly rosy chart.

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


# Metric declarations — two scored metrics, both LOWER_BETTER
# (``weak_value > strong_value`` so the same linear normaliser handles
# either direction). Calibrated against live pe-sieve 0.4.1.1 output
# on the seed corpus at the current ``strong`` defence level.
#
# Baseline observations (3 fresh entries, 4 legacy skipped):
#
#   dumped_modules      = 1 per entry — pe-sieve always REALIGNs and
#                         dumps the main image. Zero anti-dump defence
#                         in the current packer.
#   modified_total      = 1 per entry — main image is self-patched by
#                         design; one module is our minimum surface.
#
# Scale rationale:
#
# * ``pesieve_dumped_modules`` — ``weak=1 / strong=0``.
#   Deliberately NO headroom below the baseline. The honest reading
#   is "we have no anti-dump defence" (score = 0.0). Adding real
#   anti-dump work lifts the score towards 1.0 as dump_count drops
#   to 0. A regression that made pe-sieve dump *more* modules would
#   clamp at 0.0 too — a rarely-hit edge since our packer does not
#   spawn extra modules, and we prefer "floor at 0" over inventing
#   a larger ``weak_value`` that paints a rosier baseline.
#
# * ``pesieve_fingerprint_count`` — ``weak=5 / strong=0``.
#   Baseline=1 reads as 0.80. A *surface* metric: every additional
#   distinct module pe-sieve flags pulls the score down. Direction
#   is still LOWER_BETTER because, holding deployment fixed, fewer
#   flagged modules means less fingerprint for the attacker to
#   cluster on. Scale width of 5 leaves room for regressions that
#   expand surface (new instrumented loader modules, hooks, etc.).
#
# Retune when the corpus materially changes shape or the packer adds
# anti-dump / anti-fingerprint work that shifts the baselines.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("pesieve_dumped_modules",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=1.0, strong_value=0.0)),
    ("pesieve_fingerprint_count",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=5.0, strong_value=0.0)),
)


@register_benchmark
class PackerPeSieveBenchmark(IBenchmark):
    """pe-sieve unpack / implant detection against packer-tagged entries."""

    name = "packer_pesieve"
    description = (
        "Runs hasherezade/pe-sieve against every packer-tagged corpus "
        "entry — fresh builder output plus any legacy .exe.packed "
        "preserved under build_testapp/. Scored metrics (both "
        "lower-is-better): dumped_modules (anti-dump defence quality) "
        "and fingerprint_count (pe-sieve surface area). Non-scored "
        "canary: implanted_pe — any non-zero value appears as a "
        "CANARY entry in benchmark.errors."
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

    return _record_samples(entry.name, result, samples_by_metric)


def _record_samples(
    entry_name: str,
    result: PesieveRunResult,
    samples_by_metric: dict[str, list[MetricSample]],
) -> list[str]:
    """Translate a :class:`PesieveRunResult` into per-metric samples.

    Returns a list of canary warnings (one per tripped canary).
    Empty list in the normal case — the caller appends whatever
    is returned to the benchmark-level ``errors`` aggregate so a
    reviewer sees the warning in standard output.
    """
    assert result.report is not None  # caller-validated
    report = result.report

    dumped = report.dumped_count
    fingerprint = report.modified_total
    implanted_pe = report.implanted_pe_count

    # Evidence carries the full pe-sieve breakdown plus the canary
    # reading. Scored metrics are the ones the chart renders; the
    # canary is surfaced separately (see below) to avoid inflating
    # the score with a tautology ("we are not a process-hollowing
    # attack" is not a defence win).
    evidence = {
        "pid": report.pid,
        "pesieve_duration_ms": result.duration_ms,
        "pesieve_main_image": report.main_image_path,
        "pesieve_output_dir": report.output_dir,
        "dump_files": [str(p) for p in result.dump_files],
        "scanner_version": report.scan_report.scanner_version,
        "modified_breakdown": report.scan_report.scanned.modified.model_dump(),
        "dump_entries": [d.model_dump() for d in report.dump_report.dumps],
        "canary_implanted_pe": implanted_pe,
    }

    _LOG.info(
        "%s: pe-sieve %dms — dumped=%d fingerprint=%d (canary implanted_pe=%d)",
        entry_name, result.duration_ms, dumped, fingerprint, implanted_pe,
    )

    values: dict[str, int] = {
        "pesieve_dumped_modules": dumped,
        "pesieve_fingerprint_count": fingerprint,
    }
    for metric_name, value in values.items():
        samples_by_metric[metric_name].append(MetricSample(
            sample_name=entry_name, value=value, evidence=evidence,
        ))

    canary_warnings: list[str] = []
    if implanted_pe > 0:
        # A self-patching packer never legitimately triggers pe-sieve's
        # implant-PE classifier. A non-zero count means we accidentally
        # produced something pe-sieve recognises as a hollowing-style
        # attack — flag loudly for investigation.
        canary_warnings.append(
            f"{entry_name}: CANARY implanted_pe={implanted_pe} — "
            f"pe-sieve classified output as implanted PE; regression alarm"
        )
    return canary_warnings
