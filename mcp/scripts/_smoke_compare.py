"""Smoke the compare_snapshots tool end-to-end.

Renders ``previous ↔ latest`` from ``mcp/snapshots/`` and writes a
PNG. Useful after a sequence of ``measure_defense`` runs to visually
verify a change in protection.

Usage:

    py -3 scripts/_smoke_compare.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

# Ensure tool + chart registries populate before we construct them.
import mx_mcp.benchmarks  # noqa: F401,E402
import mx_mcp.tools  # noqa: F401,E402
from mx_mcp.tools.compare_snapshots import (  # noqa: E402
    CompareSnapshotsInput,
    CompareSnapshotsTool,
)


async def _main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    out_png = repo_root / "mcp" / "_smoke_compare.png"

    session = type("S", (), {"workspace_root": repo_root})()

    tool = CompareSnapshotsTool()
    args = CompareSnapshotsInput(
        left="previous",
        right="latest",
        output_png=str(out_png),
    )
    result = await tool.run(args, session)

    print(f"# left  : {result.left_id}  ({result.left_git_commit or '-'})")
    print(f"# right : {result.right_id}  ({result.right_git_commit or '-'})")
    print(f"# png   : {result.png_path or '(skipped)'} {result.png_note or ''}")
    print(f"# gate  : {'PASS' if result.diff.gate_passed else 'FAIL'}")
    print()

    def _section(title: str, items):
        if not items:
            return
        print(f"## {title} ({len(items)})")
        for e in items:
            delta = (
                "-" if e.delta_pct is None else f"{e.delta_pct:+.1f}%"
            )
            print(
                f"  {e.benchmark}::{e.metric}  {delta}  "
                f"cur={e.current_value}  base={e.baseline_value}"
            )
        print()

    _section("regressed", result.diff.regressions)
    _section("improved",  result.diff.improvements)
    _section("unchanged", result.diff.unchanged)
    _section("added",     result.diff.added)
    _section("removed",   result.diff.removed)

    for n in result.notes:
        print(f"# {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
