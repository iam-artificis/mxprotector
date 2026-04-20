"""Plain-text rendering of measurement + diff structures.

Kept free of any third-party dependency so agents can receive a
summary even when the ``[viz]`` extra is not installed. Functions
here are pure — they do not touch the filesystem, logging, or the
MCP session.

Conventions:

* "Score" always refers to the ``scale.normalize(p90)`` value in
  ``[0, 1]``; metrics without a scale surface their raw p90 and a
  ``(no scale)`` note.
* Direction glyphs: ``↑`` for ``HIGHER_BETTER``, ``↓`` for
  ``LOWER_BETTER``, ``✗↓`` for ``FALSE_BEST`` (false is best → lower
  the rate).
"""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING

from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    MetricDirection,
    MetricResult,
)

if TYPE_CHECKING:
    from mx_mcp.common.baselines import BaselineDiff, MetricDiff
    from mx_mcp.tools.measure_defense import MeasureDefenseOutput


_DIRECTION_GLYPH = {
    MetricDirection.HIGHER_BETTER: "↑",
    MetricDirection.LOWER_BETTER:  "↓",
    MetricDirection.FALSE_BEST:    "✗↓",
}


def _metric_line(metric: MetricResult) -> str:
    """Single-line summary for one metric — padded for table alignment."""
    glyph = _DIRECTION_GLYPH.get(metric.direction, "?")
    agg = metric.aggregate
    p90 = agg.p90

    if p90 is None:
        right = "(no data)"
    elif metric.scale is not None:
        score = metric.scale.normalize(p90)
        right = f"score={score:.2f}  p90={p90:.4g}"
    else:
        right = f"p90={p90:.4g}  (no scale)"

    samples_info = f"n={agg.n_samples}"
    if agg.n_errors:
        samples_info += f" (errors={agg.n_errors})"

    return f"  {glyph} {metric.name:<22}  {right:<34}  {samples_info}"


def format_measurement(result: "MeasureDefenseOutput") -> str:
    """Return a multi-line summary of a ``MeasureDefenseOutput``."""
    out = StringIO()
    out.write(f"Defense measurement — corpus: {result.corpus_path}\n")
    out.write(
        f"  {result.corpus_size} sample(s), "
        f"{result.benchmark_count} benchmark(s), "
        f"{result.duration_ms} ms total\n"
    )
    if result.notes:
        for n in result.notes:
            out.write(f"  note: {n}\n")

    if not result.benchmarks:
        out.write("\n  (no benchmark results)\n")
        return out.getvalue()

    for bench in result.benchmarks:
        _write_benchmark_block(out, bench)
    return out.getvalue()


def _write_benchmark_block(out: StringIO, bench: BenchmarkResult) -> None:
    """Append one benchmark's section to ``out``."""
    out.write(
        f"\n[{bench.benchmark}] category={bench.category} "
        f"tier={bench.tier}  ({bench.duration_ms} ms)\n"
    )
    if not bench.metrics:
        out.write("  (no metrics)\n")
    else:
        for m in bench.metrics:
            out.write(_metric_line(m) + "\n")
    if bench.errors:
        out.write("  errors:\n")
        for e in bench.errors:
            out.write(f"    - {e}\n")


def _diff_line(entry: "MetricDiff") -> str:
    glyph = _DIRECTION_GLYPH.get(entry.direction, "?")
    name = f"{entry.benchmark}::{entry.metric}"

    cur = "-" if entry.current_value is None else f"{entry.current_value:.4g}"
    base = "-" if entry.baseline_value is None else f"{entry.baseline_value:.4g}"
    delta = "-" if entry.delta_pct is None else f"{entry.delta_pct:+.1f}%"

    return (
        f"  [{entry.verdict.value:<10}] {glyph} {name:<44}  "
        f"cur={cur:<10} base={base:<10} Δ={delta}"
    )


def format_diff(diff: "BaselineDiff") -> str:
    """Return a multi-line summary of a ``BaselineDiff``.

    Sections are ordered by relevance: regressions first (what blocks
    the gate), then improvements, then added / removed metrics, then
    skipped entries at the tail.
    """
    out = StringIO()
    gate = "PASS" if diff.gate_passed else "FAIL"
    out.write(
        f"Defense diff vs baseline '{diff.baseline_name}' "
        f"(gate: {gate})\n"
        f"  baseline:  {diff.baseline_timestamp}\n"
        f"  current:   {diff.current_timestamp}\n"
    )

    sections = [
        ("regressions", diff.regressions),
        ("improvements", diff.improvements),
        ("added",        diff.added),
        ("removed",      diff.removed),
        ("skipped",      diff.skipped),
        ("unchanged",    diff.unchanged),
    ]
    for title, entries in sections:
        if not entries:
            continue
        out.write(f"\n{title} ({len(entries)}):\n")
        for e in entries:
            out.write(_diff_line(e) + "\n")

    return out.getvalue()
