"""Ship-gate runner — verdict aggregation over registered gates.

Two modules:

* :mod:`evaluator` — pure aggregation. Takes a list of
  :class:`~mx_mcp.common.benchmark_base.BenchmarkResult`, walks the
  registered gates from :mod:`mx_mcp.gates`, and emits a
  :class:`TierVerdict`.
* :mod:`runner` — wires :class:`evaluator.GateEvaluator` to
  :class:`~mx_mcp.tools.measure_defense.MeasureDefenseTool`. The
  MCP tool surface (:mod:`mx_mcp.tools.run_tier`) calls into the
  runner; the runner calls measure_defense to get the underlying
  metrics, then feeds them through the evaluator.

Split rationale: the evaluator is pure and unit-testable without
any MCP plumbing; the runner is the orchestration layer and pulls
in the tool stack. Keeping them apart lets tests exercise the
verdict logic without spinning up a fake builder / corpus.
"""

# Side-effect import: pulling the gates package triggers
# ``@register_gate`` on every concrete gate module so the evaluator
# sees a populated registry. Mirrors how benchmarks/__init__.py and
# tools/__init__.py auto-register their own catalogs on first import.
from mx_mcp import gates as _gates_pkg  # noqa: F401

from mx_mcp.shipgate.evaluator import (
    GateEvaluator,
    TierVerdict,
    VerdictSummary,
)
from mx_mcp.shipgate.runner import TierRunner, TierRunResult

__all__ = [
    "GateEvaluator",
    "TierRunResult",
    "TierRunner",
    "TierVerdict",
    "VerdictSummary",
]
