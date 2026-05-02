"""Pattern-based MBA simplifier — second peer in the P7 ensemble.

Applies a curated catalog of MBA rewrite rules
(:mod:`.pattern_rules`) via the bottom-up engine
(:mod:`.pattern_engine`), then optionally hands the result back to
``claripy.simplify`` for trivial residual rewrites the engine does
not target (constant folding, ``a + 0``, …).

## Why this peer

``ClaripySimplifier`` runs claripy's static rewrite pipeline. That
pipeline is fast and safe but **not** MBA-aware: it does not know
that ``(a | b) - (a & b) == a ^ b``. A protector that emits handler
outputs in this kind of obfuscated form scores 0 % simplification
on the claripy peer, which would read as "MBA-strong" — but a real
attacker armed with SiMBA / MBA-Blast / msynth would collapse it
in a single pass.

This simplifier closes the gap on Windows hosts (where msynth
self-skips because miasm does not build) and gives the benchmark
an honest second signal without external dependencies.

## Threshold semantics

Identical to :class:`ClaripySimplifier`: the result's
``simplified`` flag flips only when the post-simplification AST
has fewer than ``threshold * nodes_before`` nodes. Same threshold
constant lives in :mod:`.simplifier`; we duplicate the comparison
logic locally rather than depend on it so the file stays
single-responsibility.

## Failure mode

A rewrite that itself raises (rule construction error, malformed
AST, claripy internal) is caught per call and surfaced as
``error`` on the result — fail-closed: the simplifier reports
"could not simplify" rather than letting the benchmark die on one
broken handler.
"""

from __future__ import annotations

import importlib
import logging
import time
from dataclasses import dataclass
from typing import Any, ClassVar

from mx_mcp.deobfuscation.mba.expression import (
    MbaExpression,
    count_ast_nodes,
)
from mx_mcp.deobfuscation.mba.pattern_engine import (
    PatternEngineBudget,
    rewrite,
)
from mx_mcp.deobfuscation.mba.pattern_rules import ALL_RULES, MbaIdentity
from mx_mcp.deobfuscation.mba.simplifier import (
    BackendUnavailableError,
    IMbaSimplifier,
    SimplificationResult,
)


_LOG = logging.getLogger(__name__)


# Same 50 % threshold the claripy peer uses. Kept inline (rather
# than imported from .simplifier) so the constant is reviewable
# without spelunking the sibling module.
_SIMPLIFICATION_THRESHOLD = 0.5


@dataclass(frozen=True, slots=True)
class PatternSimplifierConfig:
    """Tunable knobs.

    ``rules`` is the identity catalog the engine drives; defaulting
    to :data:`~.pattern_rules.ALL_RULES` exercises the whole catalog.
    Tests pin this to a single rule when they want to verify one
    identity in isolation.

    ``budget`` caps engine work per expression; default leaves room
    for an order of magnitude growth in rule firings beyond what
    the seed corpus needs (~20 fires per handler observed).

    ``post_simplify`` runs ``claripy.simplify`` after the rewrite
    engine. The post-pass collapses constant-fold residue (``a + 0``,
    ``-(-a)`` …) without re-running expensive MBA pattern matching;
    disabling it isolates the engine's own contribution.
    """

    rules: tuple[MbaIdentity, ...] = ALL_RULES
    budget: PatternEngineBudget = PatternEngineBudget()
    post_simplify: bool = True


class PatternSimplifier(IMbaSimplifier):
    """MBA-aware simplifier driven by a curated identity catalog.

    SOLID note (SRP): wraps the engine + rule catalog + claripy
    post-pass. Subclassing extends *which catalog runs* via the
    config; never via overriding ``simplify`` itself.
    """

    name: ClassVar[str] = "pattern"

    def __init__(self, config: PatternSimplifierConfig | None = None) -> None:
        self._config = config or PatternSimplifierConfig()

    def simplify(self, expr: MbaExpression) -> SimplificationResult:
        """Rewrite ``expr.ast`` to its canonical MBA form.

        Returns a :class:`SimplificationResult`. The ``simplified``
        flag flips iff post-rewrite node count drops below the 50 %
        threshold relative to the input.

        Raises :class:`BackendUnavailableError` only when claripy
        itself fails to import — the engine is pure-Python and has
        no other runtime dependencies.
        """
        # claripy is the runtime currency for *every* simplifier
        # peer in this package. The pattern engine itself doesn't
        # call claripy, but the post-simplify pass does, and several
        # rule rewrites construct claripy ASTs implicitly via
        # operator overloads on the bound subterms (e.g. ``a ^ b``).
        try:
            claripy = importlib.import_module("claripy")
        except ImportError as e:
            raise BackendUnavailableError(
                "claripy not installed — this is unusual since it "
                'ships with angr. Reinstall mcp with pip install -e '
                '".[angr]".'
            ) from e

        if expr.ast is None or not hasattr(expr.ast, "op"):
            return SimplificationResult(
                backend=self.name,
                simplified=False,
                nodes_before=expr.ast_nodes,
                nodes_after=expr.ast_nodes,
                wall_ms=0,
                error="input is not a claripy AST",
            )

        t0 = time.monotonic()
        try:
            engine_result = rewrite(
                expr.ast,
                rules=self._config.rules,
                budget=self._config.budget,
            )
            final_ast = engine_result.ast
            if self._config.post_simplify:
                final_ast = claripy.simplify(final_ast)
        except Exception as e:  # noqa: BLE001 — fail-closed per expression
            return SimplificationResult(
                backend=self.name,
                simplified=False,
                nodes_before=expr.ast_nodes,
                nodes_after=expr.ast_nodes,
                wall_ms=int((time.monotonic() - t0) * 1000),
                error=f"{type(e).__name__}: {e}",
            )
        wall_ms = int((time.monotonic() - t0) * 1000)

        nodes_after, _ = count_ast_nodes(final_ast)
        simplified = _is_significant_reduction(expr.ast_nodes, nodes_after)

        if engine_result.rules_fired > 0:
            _LOG.debug(
                "pattern simplifier @0x%X: %d → %d nodes "
                "(%d rule fires across %d kinds, budget_exhausted=%s)",
                expr.handler_rva, expr.ast_nodes, nodes_after,
                engine_result.rules_fired, len(engine_result.rule_hits),
                engine_result.budget_exceeded,
            )

        return SimplificationResult(
            backend=self.name,
            simplified=simplified,
            nodes_before=expr.ast_nodes,
            nodes_after=nodes_after,
            wall_ms=wall_ms,
            error=None,
        )


# ============================================================================
# Helpers
# ============================================================================


def _is_significant_reduction(nodes_before: int, nodes_after: int) -> bool:
    """True iff ``nodes_after`` dropped below ``threshold * nodes_before``."""
    if nodes_before <= 0:
        return False
    return nodes_after < _SIMPLIFICATION_THRESHOLD * nodes_before


__all__ = ["PatternSimplifier", "PatternSimplifierConfig"]
