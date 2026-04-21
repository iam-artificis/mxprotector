"""Metadata-leakage benchmark — soft regression surface.

Complementary to the hard-block :class:`NoProtectorMetadataLeakedInvariant`.
Measures three signals per corpus entry:

* ``leaked_forbidden_literal_count`` — anchor metric: count of
  protector-identifying literal hits (pass names, SDK markers,
  ``MxProtector``). Should always be zero; non-zero means the
  invariant above would also fail. Kept on the benchmark surface so
  the chart has a baseline that reads ``0`` and a regression that
  pulls it above zero shows up as score-loss, not just an invariant
  flip-flop.
* ``leaked_pdb_path_count`` — count of ``.pdb``-ending printable runs
  in the file. A release-mode packed PE should carry no PDB paths;
  any hit indicates debug-info residue (usually a MSVC ``IMAGE_DEBUG_
  TYPE_CODEVIEW`` directory that wasn't stripped, or a linker-leaked
  object-file path).
* ``leaked_rich_header_present`` — boolean-as-float: 1 if the MSVC
  Rich-header signature is in the file, 0 otherwise. Current packer
  preserves the Rich header by default — baseline reads 1, and the
  score bottoms at 0.00, serving as "we have not yet implemented
  Rich-header stripping" signpost. Surfaces the gap honestly; future
  work lifts the score to 1.00.

All three metrics are ``LOWER_BETTER`` (weak > strong). Scale anchors
are set so the *current* baseline on the seed corpus reads around
mid-range for the non-zero metrics (so real movement is visible) and
exactly 0.00 for the always-zero ``forbidden_literal_count`` — that
metric has no headroom because the invariant has already gated it.

## Corpus coverage

Consumes every corpus entry tagged ``exe`` (fresh builds + legacy).
Legacy pre-protected artefacts are included on purpose: they are the
"then vs now" comparison point for leakage surface — an old build
that happens to leak a PDB path would show up as a per-entry
regression in the chart without any new builder invocation.

## Fail-closed

Per-entry OS errors (unreadable file, vanished during measurement)
become ``None`` metric values; the aggregator treats those as
errors in the standard way. Benchmark-level failure is only when we
cannot resolve the builder at all.
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
from mx_mcp.common.leakage_scan import (
    has_rich_header,
    scan_forbidden_literals,
    scan_pdb_paths,
)


_LOG = logging.getLogger(__name__)


# Metric declarations. All three are LOWER_BETTER (``weak > strong``).
#
# Scale rationale:
#
# * ``leaked_forbidden_literal_count`` — ``weak=5 / strong=0``.
#   Baseline reads 0.00 (no headroom) because the hard-block invariant
#   already ensures zero. The scale exists so a regression past the
#   invariant (shouldn't happen) shows as 0.00 → still floor-clamped,
#   matching the invariant verdict direction.
# * ``leaked_pdb_path_count`` — ``weak=3 / strong=0``. A single
#   leaked PDB path cuts the score to ~0.67. Modest headroom on the
#   low side keeps the chart readable.
# * ``leaked_rich_header_present`` — ``weak=1 / strong=0``. Boolean.
#   Current packer preserves the Rich header → baseline 0.00. The
#   benchmark surfaces the gap; future anti-fingerprint work lifts
#   the score toward 1.00 as the header gets stripped.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("leaked_forbidden_literal_count",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=5.0, strong_value=0.0)),
    ("leaked_pdb_path_count",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=3.0, strong_value=0.0)),
    ("leaked_rich_header_present",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=1.0, strong_value=0.0)),
)


@register_benchmark
class LeakageSurfaceBenchmark(IBenchmark):
    """Metadata leakage — forbidden-literal + PDB + Rich-header scan."""

    name = "leakage_surface"
    description = (
        "Static scan of shipped PEs for protector-identifying literals "
        "(hard-gated via invariant), PDB path residue, and MSVC Rich-header "
        "presence. Soft benchmark surfaces regressions + exposes "
        "not-yet-implemented anti-fingerprint work as score gaps."
    )
    category = "leakage"
    tier = "fast"
    corpus_tags = frozenset({"exe"})

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
                errors=["no corpus entries tagged 'exe'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_leakage_") as td:
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
    """Build (or resolve) → three scans → per-metric samples."""
    try:
        pb = await ensure_protected(
            entry,
            output_dir=output_dir,
            builder_path=builder_path,
            workspace_root=workspace_root,
        )
    except (BuilderError, FileNotFoundError) as e:
        return [f"{entry.name}: build failed: {e}"]

    binary = pb.protected_binary
    try:
        forbidden_hits = scan_forbidden_literals(binary)
        pdb_hits = scan_pdb_paths(binary)
        rich_present = has_rich_header(binary)
    except OSError as e:
        return [f"{entry.name}: scan failed: {e}"]

    evidence = {
        "binary": str(binary),
        "forbidden_hit_breakdown": _group_hit_breakdown(forbidden_hits),
        "pdb_paths": [
            {"offset": off, "literal": lit} for off, lit in pdb_hits[:8]
        ],
        "pdb_paths_truncated": len(pdb_hits) > 8,
        "rich_header_present": rich_present,
    }

    _LOG.info(
        "%s: leakage — forbidden=%d pdb=%d rich=%s",
        entry.name, len(forbidden_hits), len(pdb_hits),
        "y" if rich_present else "n",
    )

    values: dict[str, int | float] = {
        "leaked_forbidden_literal_count": len(forbidden_hits),
        "leaked_pdb_path_count": len(pdb_hits),
        "leaked_rich_header_present": 1.0 if rich_present else 0.0,
    }
    for metric_name, value in values.items():
        samples_by_metric[metric_name].append(MetricSample(
            sample_name=entry.name, value=value, evidence=evidence,
        ))
    return []


def _group_hit_breakdown(hits) -> list[dict]:
    """Compact per-literal summary for metric evidence.

    Same shape as the invariant's ``breakdown`` so a reviewer who
    flipped between the two outputs gets consistent per-literal
    structure. Lives here rather than importing from the invariant
    module to keep the benchmark → invariant import direction one-way
    (benchmarks never pull invariant code).
    """
    by_literal: dict[str, list] = {}
    for h in hits:
        by_literal.setdefault(h.literal, []).append(h)
    out = []
    for literal in sorted(by_literal):
        lit_hits = sorted(by_literal[literal], key=lambda h: h.offset)
        out.append({
            "literal": literal,
            "hit_count": len(lit_hits),
            "first_offsets": [
                {"offset": h.offset, "encoding": h.encoding}
                for h in lit_hits[:4]
            ],
        })
    return out
