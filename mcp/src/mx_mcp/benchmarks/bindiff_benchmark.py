"""Diffing-resistance benchmark — two seeded builds compared via BinDiff.

Tests how well the protector *randomises* output. For each corpus
entry we build the same source binary twice back-to-back and let
BinDiff compute how structurally similar the two artefacts ended up.

Low similarity = strong randomisation (an attacker cannot
cross-reference between builds to lift protector internals).

## Why two builds of the *same* source

Diffing-resistance is a property of the **builder**, not of any
one binary. Given identical source input, an idealised strong
randomisation produces two outputs that look like they came from
different inputs entirely. A deterministic builder produces two
bit-identical binaries (BinDiff similarity = 1.0). The MxProtector
builder sits somewhere in between; the benchmark pins down exactly
where.

## Pipeline per entry

1. ``ensure_protected`` the entry twice into distinct output files.
   Pre-protected entries are rejected up front — there is no source
   to rebuild with a different seed, so the signal does not exist
   for them.
2. IDA headless + BinExport plugin exports each protected binary
   to ``.BinExport`` (:mod:`diffing.bindiff.binexport_runner`).
3. ``bindiff.exe`` diffs the pair (:mod:`diffing.bindiff.bindiff_runner`).
4. Record scored metrics + evidence.

## Metrics (both LOWER_BETTER)

* ``bindiff_similarity`` — BinDiff's overall similarity score in
  ``[0, 1]``. 0 = independent-looking binaries, 1 = bit-identical.
  Primary signal; scale calibrated so the current baseline lands
  around the middle.
* ``bindiff_function_match_ratio`` — matched functions divided by
  the mean function count across the two sides. Measures whether
  BinDiff can still line functions up with each other even when
  overall structural similarity is low — a secondary lens that
  catches "randomised at the basic-block level but not at the
  function-boundary level" regressions.

## Tier

``slow``: each entry costs one extra build plus two full IDA
analyses (~60-90s each) plus a BinDiff run. Three corpus entries
therefore land around 8-10 minutes on typical hardware. That
rules the benchmark out of ``fast``.
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
from mx_mcp.diffing.bindiff.binexport_runner import run_binexport
from mx_mcp.diffing.bindiff.bindiff_runner import (
    BinDiffRunResult,
    run_bindiff,
)


_LOG = logging.getLogger(__name__)


# Metric declarations — both LOWER_BETTER (weak > strong).
#
# Scale anchors (subject to retune in the P4 smoke / calibration
# commit — initial values are best-guess ranges derived from one
# manual BinDiff 8 run against pure_cff.mx.exe where similarity
# landed at ~0.615):
#
# * ``bindiff_similarity`` — weak=0.95 (near-deterministic) /
#   strong=0.30 (aggressively randomised). The baseline lands near
#   the midpoint, giving symmetric headroom either direction.
# * ``bindiff_function_match_ratio`` — weak=0.95 (function-boundary
#   identity preserved almost entirely) / strong=0.20 (function
#   boundaries shuffle enough that BinDiff cannot align most
#   pairs). A regression that preserves function identity while
#   breaking block-level randomisation would pull this metric up
#   while leaving ``similarity`` roughly unchanged — worth
#   scoring separately.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("bindiff_similarity",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=0.95, strong_value=0.30)),
    ("bindiff_function_match_ratio",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=0.95, strong_value=0.20)),
)


@register_benchmark
class BinDiffBenchmark(IBenchmark):
    """Diffing-resistance — BinDiff similarity across two seeded builds."""

    name = "bindiff_resistance"
    description = (
        "Builds each corpus entry twice back-to-back, exports both to "
        "BinExport via IDA headless, runs BinDiff on the pair, and "
        "records the resulting similarity / function-match ratio as "
        "randomisation-strength metrics (lower = more diverged = "
        "stronger randomisation)."
    )
    category = "diffing"
    tier = "slow"
    corpus_tags = frozenset({"diffing", "exe"})

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags, match_all=True)
        # Pre-protected entries cannot be rebuilt with a fresh seed,
        # so the signal does not exist for them. Filter defensively
        # even though the ``diffing`` tag convention already excludes
        # legacy entries — a manifest typo should not crash the run.
        entries = [e for e in entries if not e.is_pre_protected]

        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=[
                    "no buildable corpus entries tagged 'diffing' + 'exe'"
                ],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_bindiff_") as td:
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
    """Build twice, export each, diff, record.

    Returns accumulated error strings for this entry. Per-metric
    samples append in-place on success. Any sub-step failure aborts
    the entry with an error describing where it stopped — downstream
    steps are not run since they depend on the aborted output.
    """
    # 1. Build the same entry twice. The builder uses std::random_device
    #    for section naming and pass-internal shuffling, so two
    #    back-to-back calls produce structurally distinct binaries.
    protected_paths: list[Path] = []
    for label in ("a", "b"):
        try:
            pb = await ensure_protected(
                entry,
                output_dir=output_dir / f"build_{label}",
                builder_path=builder_path,
                workspace_root=workspace_root,
            )
        except (BuilderError, FileNotFoundError) as e:
            return [f"{entry.name}: seeded build '{label}' failed: {e}"]
        protected_paths.append(pb.protected_binary)

    # 2. Export each protected binary to .BinExport via IDA. Run them
    #    sequentially — IDA locks its database files and two IDAs on
    #    the same machine fight each other for licence / temp files.
    binexport_paths: list[Path] = []
    for label, protected in zip(("a", "b"), protected_paths):
        be_path = output_dir / f"{entry.name}_{label}.BinExport"
        result = await run_binexport(protected, be_path)
        if not result.ok:
            return [
                f"{entry.name}: BinExport '{label}' failed: "
                f"{result.error or 'unknown'}"
            ]
        binexport_paths.append(result.output_path or be_path)

    # 3. Diff the pair.
    bindiff_workdir = output_dir / f"{entry.name}_bindiff"
    bindiff_workdir.mkdir(parents=True, exist_ok=True)
    bindiff_result = await run_bindiff(
        primary=binexport_paths[0],
        secondary=binexport_paths[1],
        output_dir=bindiff_workdir,
    )
    if not bindiff_result.ok or bindiff_result.report is None:
        return [
            f"{entry.name}: bindiff failed: "
            f"{bindiff_result.error or 'no report'}"
        ]

    _record_samples(entry.name, bindiff_result, samples_by_metric)
    return []


def _record_samples(
    entry_name: str,
    result: BinDiffRunResult,
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    """Translate a successful :class:`BinDiffRunResult` into samples."""
    assert result.report is not None  # caller-validated
    report = result.report

    similarity = report.similarity
    fn_ratio = report.function_match_ratio

    # ``similarity`` cannot be ``None`` here — the bindiff runner
    # downgrades that case to ok=False, which short-circuited earlier.
    # ``fn_ratio`` can still be ``None`` when the matched / total
    # counts line was missing; the ``None`` propagates into the
    # MetricSample and surfaces as an ``n_errors`` contribution.
    assert similarity is not None

    evidence = {
        "bindiff_duration_ms": result.duration_ms,
        "confidence": report.confidence,
        "matched_functions": report.stdout.matched_functions,
        "primary_functions": report.stdout.primary_functions,
        "secondary_functions": report.stdout.secondary_functions,
        "bindiff_db_path": (
            str(result.bindiff_db_path) if result.bindiff_db_path else None
        ),
        "results_path": (
            str(result.results_path) if result.results_path else None
        ),
        "results_stats": result.report.results.model_dump(),
    }

    _LOG.info(
        "%s: bindiff %dms — similarity=%.4f fn_ratio=%s",
        entry_name, result.duration_ms, similarity,
        f"{fn_ratio:.4f}" if fn_ratio is not None else "n/a",
    )

    samples_by_metric["bindiff_similarity"].append(MetricSample(
        sample_name=entry_name, value=similarity, evidence=evidence,
    ))
    samples_by_metric["bindiff_function_match_ratio"].append(MetricSample(
        sample_name=entry_name, value=fn_ratio, evidence=evidence,
    ))
