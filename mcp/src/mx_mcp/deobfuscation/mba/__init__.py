"""MBA simplification backends.

P7 measures MBA resistance by extracting each VM handler's output
expression via angr, then attempting to simplify it with every
registered backend. A handler whose expression shrinks ≥50 %
counts as *simplified* for that backend; the fraction of
simplified-per-total handlers is the scored metric.

## Backends

* :class:`ClaripySimplifier` — always-available baseline. Wraps
  claripy's static rewrite pass; fast, conservative, not MBA-aware.
* :class:`PatternSimplifier` — always-available second peer. Drives
  a curated catalog of MBA identities through the bottom-up engine
  in :mod:`.pattern_engine`; aware of classical linear-MBA rewrites
  (``(a|b) - (a&b) → a^b`` …) that claripy alone misses.
* :class:`MsynthSimplifier` — optional, currently self-skips on
  Windows where miasm does not build. Reserved for future Linux
  / cross-platform support.

Public surface:

* :class:`MbaExpression` — canonical extractor result.
* :class:`SimplificationResult` — per-backend outcome record.
* :class:`IMbaSimplifier` — backend contract.
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
from mx_mcp.deobfuscation.mba.pattern_engine import (
    PatternEngineBudget,
    RewriteResult,
    rewrite as pattern_rewrite,
)
from mx_mcp.deobfuscation.mba.pattern_rules import ALL_RULES, MbaIdentity
from mx_mcp.deobfuscation.mba.simplifier import (
    BackendUnavailableError,
    ClaripySimplifier,
    IMbaSimplifier,
    MsynthSimplifier,
    SimplificationResult,
)
from mx_mcp.deobfuscation.mba.simplifier_pattern import (
    PatternSimplifier,
    PatternSimplifierConfig,
)

__all__ = [
    "ALL_RULES",
    "AST_NODE_CAP",
    "BackendUnavailableError",
    "ClaripySimplifier",
    "DEFAULT_EXTRACTOR_BUDGET",
    "ExpressionBudget",
    "ExtractorUnavailableError",
    "IMbaSimplifier",
    "MbaExpression",
    "MbaIdentity",
    "MsynthSimplifier",
    "PatternEngineBudget",
    "PatternSimplifier",
    "PatternSimplifierConfig",
    "RewriteResult",
    "SimplificationResult",
    "count_ast_nodes",
    "extract_handler_expression",
    "pattern_rewrite",
]
