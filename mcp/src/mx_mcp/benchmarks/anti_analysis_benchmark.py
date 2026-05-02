"""Anti-analysis coverage benchmark — P10.

Per ``MCP.md`` cross-cutting table:

    | Detection coverage {x64dbg, Frida, Unicorn, pafish, al-khaser} |
    | ↑ | anti_analysis/coverage | FAIL < threshold |

For every corpus entry, walks the registered :mod:`mx_mcp.anti_analysis`
detectors, collapses the per-detector outcomes into a single
:class:`~mx_mcp.anti_analysis.coverage.DetectionCoverage`, and emits
the rate as the benchmark's metric.

## Metric

``anti_analysis_coverage_rate`` — ``HIGHER_BETTER`` in ``[0.0, 1.0]``.
Computed as ``detected / informative`` per binary. SKIPPED detectors
(external tool unavailable) are excluded from the denominator. When
*every* detector skipped, the per-entry sample is ``None`` (counts
as an error in the aggregator) so the score is not deflated by
missing tooling.

Scale anchors: weak=0.0 (zero anti-analysis surface visible) →
strong=1.0 (every detector fired). Mid-range readings (0.4–0.7) are
the realistic seed-corpus baseline today; the gate FAILs at < 0.4
to prevent silent erosion of the surface.

## Corpus + tier

Tier ``slow`` per the MCP.md "2–3× budget" hint — the detector list
is small but extending the catalogue with dynamic backends (driving
external tools) will need that headroom. Corpus-wide: every entry
tagged ``exe`` (legacy + fresh builds), same as the leakage benchmark.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
import time
from pathlib import Path

from mx_mcp.anti_analysis import (
    DetectionCoverage,
    DetectionResult,
    all_detectors,
    compute_coverage,
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
from mx_mcp.common.corpus import CorpusEntry


_LOG = logging.getLogger(__name__)


# Single metric — coverage rate. HIGHER_BETTER. weak=0.0 → 0% surface,
# strong=1.0 → every detector fired. The 0.4 FAIL threshold the gate
# uses sits inside this range so the score is reviewable on the chart
# even when the gate has not tripped.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("anti_analysis_coverage_rate",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=1.0)),
)


@register_benchmark
class AntiAnalysisCoverageBenchmark(IBenchmark):
    """Detection-coverage rate across the registered anti-analysis detectors."""

    name = "anti_analysis_coverage"
    description = (
        "For every corpus entry, walk the registered anti-analysis "
        "detectors (x64dbg / Frida / Unicorn / pafish / al-khaser), "
        "collapse outcomes into a coverage rate (detected / "
        "informative), and emit it as a HIGHER_BETTER metric. SKIPPED "
        "detectors (external tool unavailable) are excluded from the "
        "denominator so missing tooling does not deflate the score. "
        "Slow tier — extending detectors to drive real external tools "
        "needs the headroom MCP.md's '2-3× budget' hint allocates."
    )
    category = "anti_analysis"
    tier = "slow"
    corpus_tags = frozenset({"exe"})

    def __init__(
        self,
        *,
        # Test-injection seam — tests pass a curated detector list.
        detectors_factory=all_detectors,
    ) -> None:
        self._detectors_factory = detectors_factory

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[_empty_metric()],
                errors=["no corpus entries tagged 'exe'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples: list[MetricSample] = []
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_aa_") as td:
            td_path = Path(td)
            for entry in entries:
                entry_errors = await self._process_entry(
                    entry=entry,
                    output_dir=td_path,
                    builder_path=builder_path,
                    workspace_root=session.workspace_root,
                    samples=samples,
                )
                errors.extend(entry_errors)

        return BenchmarkResult(
            benchmark=self.name, category=self.category, tier=self.tier,
            duration_ms=int((time.monotonic() - t0) * 1000),
            metrics=[_build_metric(samples)],
            errors=errors,
        )

    # ------------------------------------------------------------------

    async def _process_entry(
        self,
        *,
        entry: CorpusEntry,
        output_dir: Path,
        builder_path: Path,
        workspace_root: Path,
        samples: list[MetricSample],
    ) -> list[str]:
        """Build → run every detector → record one sample for the entry."""
        try:
            pb = await ensure_protected(
                entry,
                output_dir=output_dir,
                builder_path=builder_path,
                workspace_root=workspace_root,
            )
        except (BuilderError, FileNotFoundError) as e:
            return [f"{entry.name}: build failed: {e}"]

        results = await self._run_detectors(pb.protected_binary)
        coverage = compute_coverage(results)

        evidence = _entry_evidence(pb.protected_binary, coverage, results)
        _LOG.info(
            "%s: anti_analysis — informative=%d/%d detected=%d skipped=%d rate=%s",
            entry.name, coverage.detectors_informative,
            coverage.detectors_total, coverage.detected, coverage.skipped,
            f"{coverage.rate:.3f}" if coverage.rate is not None else "—",
        )

        samples.append(MetricSample(
            sample_name=entry.name, value=coverage.rate, evidence=evidence,
        ))
        return []

    async def _run_detectors(
        self, binary_path: Path,
    ) -> list[DetectionResult]:
        """Walk every registered detector, fail-closed per detector."""
        out: list[DetectionResult] = []
        for det_cls in self._detectors_factory():
            detector = det_cls()
            try:
                result = await detector.detect(binary_path)
            except Exception as e:  # noqa: BLE001 — fail-closed
                _LOG.exception("detector '%s' raised", det_cls.name)
                result = DetectionResult(
                    tool=det_cls.name, detected=False,
                    error=f"{type(e).__name__}: {e}",
                )
            out.append(result)
        # asyncio.sleep(0) — stays cooperative even when every
        # detector is sync; otherwise a long detector list could
        # starve the event loop.
        await asyncio.sleep(0)
        return out


# ============================================================================
# Helpers
# ============================================================================


def _empty_metric() -> MetricResult:
    name, direction, scale = _METRIC_DEFS[0]
    return MetricResult(
        name=name, direction=direction, samples=[],
        aggregate=aggregate_numeric([]), scale=scale,
    )


def _build_metric(samples: list[MetricSample]) -> MetricResult:
    name, direction, scale = _METRIC_DEFS[0]
    return MetricResult(
        name=name, direction=direction, samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
        scale=scale,
    )


def _entry_evidence(
    binary: Path,
    coverage: DetectionCoverage,
    results: list[DetectionResult],
) -> dict:
    """Compact evidence payload for ``MetricSample.evidence``.

    Carries the per-detector verdict + a coverage summary so a
    reviewer can tell at a glance which tools fired and which
    skipped. Detector-specific ``evidence`` payloads are forwarded
    so downstream tools can drill into per-tool needle hits.
    """
    return {
        "binary": str(binary),
        "coverage": coverage.model_dump(),
        "detectors": [
            {
                "tool": r.tool,
                "detected": r.detected,
                "skipped": r.skipped,
                "skip_reason": r.skip_reason,
                "error": r.error,
                "evidence": r.evidence,
            }
            for r in results
        ],
    }
