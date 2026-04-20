"""Slow-tier smoke — runs the bindiff_resistance benchmark.

Complements ``_smoke_vm_and_chart.py`` (fast tier only). BinDiff is
slow (two builds + two IDA analyses + one bindiff run per entry),
so this script lives behind an explicit invocation rather than
firing on every fast-tier smoke.

Usage:

    MX_MCP_IDA_PATH=... MX_MCP_BINDIFF_PATH=... py -3 scripts/_smoke_bindiff.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

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
    out_png = repo_root / "mcp" / "_smoke_chart_slow.png"

    session = type("S", (), {"workspace_root": repo_root})()

    tool = MeasureDefenseTool()
    args = MeasureDefenseInput(
        corpus_path=str(corpus),
        tier="slow",
        output_png=str(out_png),
    )
    result = await tool.run(args, session)

    print(f"# corpus: {result.corpus_path}  size={result.corpus_size}")
    print(f"# benchmarks run: {result.benchmark_count}")
    print(f"# chart: {result.png_path or '(skipped)'} {result.png_note or ''}")
    print(f"# snapshot: {result.snapshot_id or '-'}")
    print()

    for b in result.benchmarks:
        print(f"## {b.benchmark} — {b.category}/{b.tier}  ({b.duration_ms} ms)")
        for m in b.metrics:
            a = m.aggregate
            if a.p90 is None:
                print(f"  - {m.name:32s}  (no data, n={a.n_samples})")
                continue
            score = m.scale.normalize(float(a.p90)) if m.scale else None
            score_s = f"score={score:.3f}" if score is not None else "score=-"
            print(
                f"  - {m.name:32s}  {score_s}  "
                f"p10={a.p10:.3g}  p50={a.p50:.3g}  p90={a.p90:.3g}  n={a.n_samples}"
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
