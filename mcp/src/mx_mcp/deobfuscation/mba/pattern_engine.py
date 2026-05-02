"""Bottom-up MBA rewrite engine.

Applies a catalog of :class:`~.pattern_rules.MbaIdentity` to a claripy
AST until no rule fires (or a budget cap is hit) and returns the
transformed AST. The driver is intentionally minimal — pattern
matching lives in the rule callables; this module owns only the
*traversal*, *fixed-point loop*, and *budget*.

## Traversal — bottom-up

Bottom-up rewriting (post-order DFS) lets a child rewrite expose a
new pattern at its parent without a second outer pass. Example:

    (~a + 1) | b      ──INVERT_PLUS_ONE──▶  (-a) | b

If we matched top-down, the outer ``|`` would see the original
``(~a + 1)`` and miss any rule on ``(-a) | b``. Bottom-up the inner
rewrite happens first; the outer step sees the canonical form.

## Hash-cons rebuild

Claripy's AST nodes are immutable — a rewrite produces a new tree.
Constructing the parent node by spreading the (possibly-rewritten)
children through the original op preserves any extra metadata
claripy attaches at construction time (variable provenance,
annotations, depth caches).

## Budget

A handler with deeply nested arithmetic could in principle expose
identity matches at every depth and trigger a long fixed-point loop.
:class:`PatternEngineBudget` caps total rule applications; the
engine bails fail-closed by returning the partially-rewritten AST
plus a ``budget_exceeded`` flag the caller can surface as evidence.

## Logging

DEBUG only. The engine fires once per handler in the slow tier;
INFO logging here would drown out the per-benchmark summary line.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from mx_mcp.deobfuscation.mba.pattern_rules import (
    ALL_RULES,
    MbaIdentity,
)


_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PatternEngineBudget:
    """Bound on engine work per AST.

    ``max_rule_applications`` caps the total number of *successful*
    rule firings. A pathological handler that triggers a rule on
    every node at every depth still terminates in linear time of the
    cap. The default is generous — handler ASTs we observe in the
    seed corpus apply 0–20 rules; 500 leaves room for an order of
    magnitude growth without retuning.
    """

    max_rule_applications: int = 500

    def __post_init__(self) -> None:
        if self.max_rule_applications <= 0:
            raise ValueError(
                f"max_rule_applications must be > 0 "
                f"(got {self.max_rule_applications})"
            )


@dataclass(frozen=True, slots=True)
class RewriteResult:
    """Engine output — the rewritten AST plus diagnostics.

    ``ast`` is the (possibly partially-)rewritten tree. ``rules_fired``
    counts successful rewrites; ``budget_exceeded`` flips on iff the
    engine bailed before reaching a fixed point.

    ``rule_hits`` is a ``rule_name → count`` map, useful in evidence
    blobs for diagnosing which identities are responsible for a
    given handler's collapse.
    """

    ast: Any
    rules_fired: int
    budget_exceeded: bool
    rule_hits: dict[str, int] = field(default_factory=dict)


# ============================================================================
# Public entry point
# ============================================================================


def rewrite(
    ast: Any,
    *,
    rules: tuple[MbaIdentity, ...] = ALL_RULES,
    budget: PatternEngineBudget | None = None,
) -> RewriteResult:
    """Bottom-up rewrite ``ast`` to fixed point under ``rules``.

    The engine returns the input unchanged when no rule matches at
    any depth — callers compare ``result.ast`` to the original via
    :func:`~mx_mcp.deobfuscation.mba.expression.count_ast_nodes` to
    decide whether a *significant* simplification occurred.

    Non-claripy inputs (None, plain ints, sentinels) round-trip
    unchanged with ``rules_fired == 0``: the engine is safe to call
    on degenerate handler outputs without raising.
    """
    if ast is None or getattr(ast, "op", None) is None:
        return RewriteResult(ast=ast, rules_fired=0, budget_exceeded=False)

    state = _State(budget=budget or PatternEngineBudget())
    rewritten = _rewrite_node(ast, rules, state)

    # Fixed-point loop: a parent that didn't match before may match
    # after children rewrote. We re-traverse until rule_hits stops
    # growing — bounded by the same budget.
    while state.fired_in_pass and not state.budget_exceeded:
        state.fired_in_pass = False
        rewritten = _rewrite_node(rewritten, rules, state)

    if state.budget_exceeded:
        _LOG.debug(
            "MBA rewrite budget exhausted after %d firings; partial result returned",
            state.total_fired,
        )

    return RewriteResult(
        ast=rewritten,
        rules_fired=state.total_fired,
        budget_exceeded=state.budget_exceeded,
        rule_hits=dict(state.rule_hits),
    )


# ============================================================================
# Internal traversal state
# ============================================================================


class _State:
    """Mutable engine state — kept off :class:`RewriteResult` so the
    public surface stays immutable."""

    __slots__ = (
        "budget", "total_fired", "rule_hits",
        "fired_in_pass", "budget_exceeded",
    )

    def __init__(self, *, budget: PatternEngineBudget) -> None:
        self.budget = budget
        self.total_fired = 0
        self.rule_hits: dict[str, int] = {}
        self.fired_in_pass = True   # primes the outer fixed-point loop
        self.budget_exceeded = False

    def record_hit(self, rule_name: str) -> None:
        self.total_fired += 1
        self.fired_in_pass = True
        self.rule_hits[rule_name] = self.rule_hits.get(rule_name, 0) + 1
        if self.total_fired >= self.budget.max_rule_applications:
            self.budget_exceeded = True


# ============================================================================
# Recursive worker — post-order DFS over the AST
# ============================================================================


def _rewrite_node(
    node: Any, rules: tuple[MbaIdentity, ...], state: _State,
) -> Any:
    """Recursively rewrite ``node`` and return its (possibly new) form.

    Order:

    1. Walk children first (post-order), rebuilding ``node`` if any
       child changed.
    2. Once children are settled, try every rule on the current node.
       The first rule to match consumes the node and recurses on the
       rewritten form so chained identities collapse without a
       second outer pass.

    The recursion guards against the engine's own cap by checking
    ``state.budget_exceeded`` at every entry — once tripped, the rest
    of the AST is returned untouched.
    """
    if state.budget_exceeded:
        return node

    op = getattr(node, "op", None)
    if op is None:
        return node

    args = getattr(node, "args", ())

    # Step 1 — rewrite each child.
    new_args: list[Any] = []
    any_child_changed = False
    for child in args:
        if getattr(child, "op", None) is None:
            new_args.append(child)
            continue
        new_child = _rewrite_node(child, rules, state)
        if new_child is not child:
            any_child_changed = True
        new_args.append(new_child)

    if any_child_changed:
        node = _rebuild(node, op, new_args)

    if state.budget_exceeded:
        return node

    # Step 2 — try every rule on the (possibly-rebuilt) node.
    for rule in rules:
        bound = rule.match(node)
        if bound is None:
            continue
        try:
            rewritten = rule.rewrite(bound)
        except Exception as e:  # noqa: BLE001 — fail-closed per rule
            _LOG.debug(
                "rule '%s' raised during rewrite: %s; skipping",
                rule.name, e,
            )
            continue
        state.record_hit(rule.name)
        if state.budget_exceeded:
            return rewritten
        # A rule fired — recurse so chained identities collapse
        # immediately rather than waiting for the next outer pass.
        return _rewrite_node(rewritten, rules, state)

    return node


def _rebuild(node: Any, op: str, new_args: list[Any]) -> Any:
    """Reconstruct ``node`` with ``new_args`` preserving the op shape.

    Preferred path: invoke the AST's own factory (``node.make_like``)
    when claripy exposes it, since that path keeps every annotation
    claripy attaches. The generic fallback works on any AST that
    accepts ``__class__(op, args, ...)`` — the public claripy AST
    classes all do.
    """
    make_like = getattr(node, "make_like", None)
    if callable(make_like):
        try:
            return make_like(op, tuple(new_args))
        except Exception:  # noqa: BLE001 — fall through to generic path
            pass

    cls = type(node)
    try:
        return cls(op, tuple(new_args), length=getattr(node, "length", None))
    except TypeError:
        return cls(op, tuple(new_args))


__all__ = ["PatternEngineBudget", "RewriteResult", "rewrite"]
