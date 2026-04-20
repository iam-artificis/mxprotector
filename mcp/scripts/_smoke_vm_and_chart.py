"""Calibration + visual smoke for vm_benchmark + measurement chart.

Runs both registered fast-tier benchmarks (cff + vm) against the
fixture corpus and writes the resulting PNG. Prints raw metrics so we
can retune ``_METRIC_DEFS`` scales if the current values saturate.

Usage:

    py -3 scripts/_smoke_vm_and_chart.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# ``reconfigure`` avoids UnicodeEncodeError on the default cp1251
# Windows console when we echo the chart's Unicode annotations.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

import mx_mcp.benchmarks  # noqa: F401,E402  — populate @register_benchmark
from mx_mcp.tools.measure_defense import (  # noqa: E402
    MeasureDefenseInput,
    MeasureDefenseTool,
)


async def _main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    corpus = repo_root / "mcp" / "fixtures" / "corpus"
    out_png = repo_root / "mcp" / "_smoke_chart.png"

    session = type("S", (), {"workspace_root": repo_root})()

    tool = MeasureDefenseTool()
    args = MeasureDefenseInput(
        corpus_path=str(corpus),
        tier="fast",
        output_png=str(out_png),
    )
    result = await tool.run(args, session)

    print(f"# corpus: {result.corpus_path}  size={result.corpus_size}")
    print(f"# benchmarks run: {result.benchmark_count}")
    print(f"# chart: {result.png_path or '(skipped)'} {result.png_note or ''}")
    print()

    for b in result.benchmarks:
        print(f"## {b.benchmark} — {b.category}/{b.tier}  ({b.duration_ms} ms)")
        for m in b.metrics:
            a = m.aggregate
            if a.p90 is None:
                print(f"  - {m.name:32s}  (no data)")
                continue
            score = m.scale.normalize(float(a.p90)) if m.scale else None
            score_s = f"score={score:.2f}" if score is not None else "score=-"
            print(
                f"  - {m.name:32s}  {score_s}  "
                f"p10={a.p10:.3g}  p50={a.p50:.3g}  p90={a.p90:.3g}"
            )
        if b.errors:
            print(f"  errors ({len(b.errors)}):")
            for e in b.errors:
                print(f"    * {e}")
        print()

    for n in result.notes:
        print(f"# {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
