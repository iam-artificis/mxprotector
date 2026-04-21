"""MBA simplification backends.

P7 measures MBA resistance by extracting each VM handler's output
expression via angr, then attempting to simplify it with every
registered backend. A handler whose expression shrinks ≥50 %
counts as *simplified* for that backend; the fraction of
simplified-per-total handlers is the scored metric.

Public surface:

* :class:`MbaExpression` — canonical extractor result.
* :class:`SimplificationResult` — per-backend outcome record.
* :class:`IMbaSimplifier` — backend contract.
* :class:`ClaripySimplifier` — always-available baseline
  (claripy native simplify, bundled with angr).
* :func:`extract_handler_expression` — the angr-backed extractor
  the benchmark drives per handler.

Optional backends self-skip via :class:`BackendUnavailableError` when
their dependency is missing; benchmarks surface that as a single
error note and leave the affected metric's samples empty.
"""

from mx_mcp.deobfuscation.mba.expression import (
    AST_NODE_CAP,
    MbaExpression,
    count_ast_nodes,
)
from mx_mcp.deobfuscation.mba.extractor import (
    DEFAULT_EXTRACTOR_BUDGET,
    ExpressionBudget,
    ExtractorUnavailableError,
    extract_handler_expression,
)
from mx_mcp.deobfuscation.mba.simplifier import (
    BackendUnavailableError,
    ClaripySimplifier,
    IMbaSimplifier,
    MsynthSimplifier,
    SimplificationResult,
)

__all__ = [
    "AST_NODE_CAP",
    "BackendUnavailableError",
    "ClaripySimplifier",
    "DEFAULT_EXTRACTOR_BUDGET",
    "ExpressionBudget",
    "ExtractorUnavailableError",
    "IMbaSimplifier",
    "MbaExpression",
    "MsynthSimplifier",
    "SimplificationResult",
    "count_ast_nodes",
    "extract_handler_expression",
]
