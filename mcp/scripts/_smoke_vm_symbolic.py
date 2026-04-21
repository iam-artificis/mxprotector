"""Slow-tier smoke: vm_symbolic benchmark + PNG.

Runs every registered ``slow``-tier benchmark against the fixture
corpus and writes the measurement PNG. The vm_symbolic benchmark
drives real angr against protected handlers; expect minutes of
wall time depending on corpus size and handler counts.

Override corpus / output path via env vars if needed:

* ``MX_SMOKE_CORPUS`` — path to a corpus root (default:
  ``mcp/fixtures/corpus``).
* ``MX_SMOKE_OUT``    — PNG output path (default:
  ``mcp/_smoke_chart_vm_symbolic.png``).

Usage::

    py -3 scripts/_smoke_vm_symbolic.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

import mx_mcp.benchmarks  # noqa: F401,E402
from mx_mcp.tools.measure_defense import (  # noqa: E402
    MeasureDefenseInput,
    MeasureDefenseTool,
)


async def _main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    corpus = Path(
        os.environ.get("MX_SMOKE_CORPUS")
        or (repo_root / "mcp" / "fixtures" / "corpus")
    )
    out_png = Path(
        os.environ.get("MX_SMOKE_OUT")
        or (repo_root / "mcp" / "_smoke_chart_vm_symbolic.png")
    )

    session = type("S", (), {"workspace_root": repo_root})()

    tool = MeasureDefenseTool()
    args = MeasureDefenseInput(
        corpus_path=str(corpus),
        # Run only the vm_symbolic slice to keep smoke focused.
        categories=["vm"],
        tier="slow",
        output_png=str(out_png),
        snapshot=False,  # smoke mode — do not pollute snapshots/
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
                print(f"  - {m.name:34s}  (no data — n_errors={a.n_errors})")
                continue
            score = m.scale.normalize(float(a.p90)) if m.scale else None
            score_s = f"score={score:.2f}" if score is not None else "score=-"
            print(
                f"  - {m.name:34s}  {score_s}  "
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
