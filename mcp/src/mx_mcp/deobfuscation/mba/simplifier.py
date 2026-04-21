"""MBA simplifier backends.

Two implementations today:

* :class:`ClaripySimplifier` — always available (claripy ships with
  angr). Wraps claripy's native rewrite-based simplifier. Serves as
  both a baseline backend and a smoke for the abstraction.
* :class:`MsynthSimplifier` — optional. Requires ``msynth`` +
  ``miasm``. Self-skips with :class:`BackendUnavailableError` when
  the dependency chain cannot be imported; the benchmark turns that
  into a single top-level error note.

Future backends (SiMBA CLI wrapper, qsynth) plug in by subclassing
:class:`IMbaSimplifier`. The benchmark drives a *list* of simplifiers;
each produces its own metric row, so adding a backend is a new file
+ one registration line.

## Contract

Each backend receives an :class:`~mx_mcp.deobfuscation.mba.expression.MbaExpression`
and returns a :class:`SimplificationResult`. The result captures:

* ``simplified`` — boolean. True iff the backend produced a
  strictly-smaller AST within the simplification budget.
* ``node_ratio`` — ``nodes_after / nodes_before`` clamped into
  ``[0, 1]``. Zero means "collapsed to a constant"; one means "no
  change". Used for the ``*_simplification_ratio_p50`` metric.
* Per-backend diagnostics (wall time, error string) for evidence.

The 50 %-reduction threshold for ``simplified`` is an opinionated
choice: a backend that trims one redundant xor but leaves the
expression's overall complexity untouched is not *really*
simplifying from a defender's perspective. The threshold balances
"strict enough to matter" against "loose enough to not miss
incremental progress."
"""

from __future__ import annotations

import importlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar

from mx_mcp.deobfuscation.mba.expression import (
    MbaExpression,
    count_ast_nodes,
)


_LOG = logging.getLogger(__name__)


# A reduction must trim the AST to less than this fraction of its
# original size to count as "simplified". 0.5 means "at least half
# the nodes are gone".
_SIMPLIFICATION_THRESHOLD = 0.5


class BackendUnavailableError(RuntimeError):
    """Raised by a simplifier when its backing library is missing."""


@dataclass(frozen=True, slots=True)
class SimplificationResult:
    """One backend's verdict on one expression."""

    backend: str
    simplified: bool
    nodes_before: int
    nodes_after: int
    wall_ms: int
    error: str | None = None

    @property
    def node_ratio(self) -> float:
        """``nodes_after / nodes_before`` clamped to ``[0, 1]``.

        Returns ``1.0`` for a zero-nodes input (degenerate; should
        not occur with any real handler). Any ratio ``> 1.0`` (a
        simplifier that grew the expression) also clamps to ``1.0``
        so the metric remains bounded.
        """
        if self.nodes_before <= 0:
            return 1.0
        raw = self.nodes_after / self.nodes_before
        if raw < 0.0:
            return 0.0
        if raw > 1.0:
            return 1.0
        return raw


# ============================================================================
# Backend interface
# ============================================================================


class IMbaSimplifier(ABC):
    """Abstract simplifier contract.

    Concrete classes declare ``name`` (short string used in metric
    names and evidence) and implement :meth:`simplify`. The contract
    is synchronous — benchmarks already run inside ``asyncio.to_thread``.
    """

    name: ClassVar[str]

    @abstractmethod
    def simplify(self, expr: MbaExpression) -> SimplificationResult:
        """Attempt to simplify ``expr``; return the verdict + diagnostics.

        Raises:
            BackendUnavailableError: the backing library is not
                available. Callers translate this to a benchmark-level
                error and skip the backend's metric row.
        """


# ============================================================================
# Claripy baseline
# ============================================================================


class ClaripySimplifier(IMbaSimplifier):
    """Claripy's built-in simplify pass.

    Claripy ships with angr, so this backend is always available. It
    applies a static rewrite pipeline (not a full SMT-based solver
    call) which is fast but conservative — complex MBA identities
    won't collapse. That matches the defender's worst-case reading:
    if even claripy can reduce the handler's output expression,
    the handler is weakly-defended.
    """

    name = "claripy"

    def simplify(self, expr: MbaExpression) -> SimplificationResult:
        try:
            claripy = importlib.import_module("claripy")
        except ImportError as e:
            raise BackendUnavailableError(
                "claripy not installed — this is unusual since it "
                'ships with angr. Reinstall mcp with pip install -e '
                '".[angr]".'
            ) from e

        if expr.ast is None or not hasattr(expr.ast, "op"):
            # Degenerate input — nothing to simplify.
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
            simplified_ast = claripy.simplify(expr.ast)
        except Exception as e:  # noqa: BLE001 — fail-closed per-expr
            return SimplificationResult(
                backend=self.name,
                simplified=False,
                nodes_before=expr.ast_nodes,
                nodes_after=expr.ast_nodes,
                wall_ms=int((time.monotonic() - t0) * 1000),
                error=f"{type(e).__name__}: {e}",
            )
        wall_ms = int((time.monotonic() - t0) * 1000)

        nodes_after, _ = count_ast_nodes(simplified_ast)
        simplified = _is_significant_reduction(expr.ast_nodes, nodes_after)

        return SimplificationResult(
            backend=self.name,
            simplified=simplified,
            nodes_before=expr.ast_nodes,
            nodes_after=nodes_after,
            wall_ms=wall_ms,
            error=None,
        )


# ============================================================================
# msynth (optional)
# ============================================================================


class MsynthSimplifier(IMbaSimplifier):
    """msynth learning-based MBA simplifier.

    Requires ``msynth`` + ``miasm``. On Windows, miasm does not
    currently build cleanly (native-code encoding quirks) — the
    backend therefore self-skips on import failure, matching every
    other optional-dep runner in this package.

    Currently wired as a stub. msynth operates on miasm ``Expr``
    objects; the extractor produces claripy ASTs. A faithful
    claripy→miasm lowering is a non-trivial chunk of work (every
    opcode has to round-trip through the IR), deferred to
    :issue:`mba-real-conversion`. The backend therefore raises
    :class:`BackendUnavailableError` on the first call with an
    explicit reason string. Installing msynth alone does not light
    the backend up — the conversion layer has to land first.
    """

    name = "msynth"

    _conversion_implemented: ClassVar[bool] = False

    def simplify(self, expr: MbaExpression) -> SimplificationResult:
        try:
            importlib.import_module("msynth")
            importlib.import_module("miasm")
        except ImportError as e:
            raise BackendUnavailableError(
                "msynth backend requires msynth + miasm. "
                'Install with: pip install "msynth @ git+https://github.com/'
                'mrphrazer/msynth.git" (miasm is a transitive dep and '
                "currently builds only on Linux)."
            ) from e

        if not self._conversion_implemented:
            raise BackendUnavailableError(
                "msynth backend present but claripy→miasm conversion "
                "is not yet implemented. Follow-up work tracks the "
                "lowering; the backend registers so the benchmark "
                "surface stays stable."
            )

        # Reached only once the conversion lands. Keeps the shape
        # the contract needs; unreachable today so intentionally
        # minimal.
        return SimplificationResult(  # pragma: no cover
            backend=self.name,
            simplified=False,
            nodes_before=expr.ast_nodes,
            nodes_after=expr.ast_nodes,
            wall_ms=0,
            error="unreachable",
        )


# ============================================================================
# Helpers
# ============================================================================


def _is_significant_reduction(nodes_before: int, nodes_after: int) -> bool:
    """True iff ``nodes_after`` dropped below ``threshold * nodes_before``."""
    if nodes_before <= 0:
        return False
    return nodes_after < _SIMPLIFICATION_THRESHOLD * nodes_before
