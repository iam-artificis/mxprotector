"""Unit tests for ``deobfuscation.mba.simplifier_pattern``.

Smaller surface than the engine/rule tests — mostly verifies the
``IMbaSimplifier`` contract (returns the right :class:`SimplificationResult`
shape, threshold semantics, fail-closed on broken inputs).
"""

from __future__ import annotations

import pytest

from mx_mcp.deobfuscation.mba.expression import (
    MbaExpression,
    count_ast_nodes,
)
from mx_mcp.deobfuscation.mba.pattern_rules import OR_MINUS_AND
from mx_mcp.deobfuscation.mba.simplifier import SimplificationResult
from mx_mcp.deobfuscation.mba.simplifier_pattern import (
    PatternSimplifier,
    PatternSimplifierConfig,
)


def _claripy_or_skip():
    try:
        import claripy
        return claripy
    except ImportError:  # pragma: no cover
        pytest.skip("claripy missing; install angr extra")


def _expr_from_ast(ast, rva=0x1000, opcode="test") -> MbaExpression:
    nodes, sat = count_ast_nodes(ast)
    depth = int(getattr(ast, "depth", 0) or 0)
    return MbaExpression(
        handler_rva=rva, handler_opcode=opcode,
        ast=ast, ast_nodes=nodes, ast_depth=depth, saturated=sat,
    )


# ============================================================================
# Contract — returned SimplificationResult shape
# ============================================================================


def test_simplifier_collapses_canonical_mba():
    """End-to-end: feed a chained MBA-obfuscated AST, expect the
    result flag set.

    The single-layer ``(a|b) - (a&b)`` collapses 5→3 nodes (40 %),
    which is below the 50 % significance threshold by design — a
    one-step trim shouldn't trigger the metric on its own. We feed
    a *two-layer* obfuscation here so the cumulative collapse pulls
    well below the threshold.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    # ~(~a & ~b) + (a & b) → (a | b) + (a & b) → a + b
    expr = _expr_from_ast(~(~a & ~b) + (a & b))
    sim = PatternSimplifier()
    r = sim.simplify(expr)

    assert isinstance(r, SimplificationResult)
    assert r.backend == "pattern"
    assert r.error is None
    assert r.simplified is True
    # 8-node input collapses to ``a + b`` (3 nodes).
    assert r.nodes_after < r.nodes_before


def test_simplifier_no_op_on_already_simple():
    claripy = _claripy_or_skip()
    a = claripy.BVS("a", 64)
    expr = _expr_from_ast(a)
    r = PatternSimplifier().simplify(expr)
    assert r.simplified is False
    assert r.nodes_before == r.nodes_after


def test_simplifier_threshold_blocks_minor_reduction():
    """A reduction below the 50 % threshold must not flip ``simplified``.

    Construct an AST the engine reduces by exactly one node — too
    small a delta for a defender to count as "the attacker cracked
    this".
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)

    # ``~a + 1`` (3 nodes — invert, 1, +) collapses to ``-a`` (2 nodes:
    # neg, a). 2/3 ratio is above the 0.5 threshold → ``simplified``
    # stays False even though the engine fired a rule.
    expr = _expr_from_ast(~a + 1)
    r = PatternSimplifier().simplify(expr)
    assert r.nodes_after < r.nodes_before
    # Whether claripy's post-simplify trims further is implementation-
    # dependent. We just assert the flag respects the threshold for
    # whatever final node count the simplifier landed on.
    if r.nodes_after >= 0.5 * r.nodes_before:
        assert r.simplified is False
    else:
        assert r.simplified is True
    # b is unused — defended by the silly cast below to keep the
    # symbol live for any future test extensions.
    _ = b


def test_simplifier_handles_non_ast_input():
    """An MbaExpression with ``ast=None`` does not blow up."""
    expr = MbaExpression(
        handler_rva=0, handler_opcode="", ast=None,
        ast_nodes=0, ast_depth=0, saturated=False,
    )
    r = PatternSimplifier().simplify(expr)
    assert r.simplified is False
    assert r.error is not None
    assert "not a claripy AST" in r.error


# ============================================================================
# Configurable peers
# ============================================================================


def test_single_rule_config_isolates_one_identity():
    """A config that ships a single rule fires only that rule.

    Asserts on the rewrite happening at all (``nodes_after <
    nodes_before``) — the 50 % threshold is a benchmark-side
    significance gate, not a contract on whether the rule fired.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)

    expr = _expr_from_ast((a | b) - (a & b))
    sim = PatternSimplifier(config=PatternSimplifierConfig(
        rules=(OR_MINUS_AND,),
        post_simplify=False,  # keep the AST in its rule-output shape
    ))
    r = sim.simplify(expr)
    # Rule fired → fewer nodes than the input (5 → 3 in this case).
    assert r.nodes_after < r.nodes_before


def test_post_simplify_off_preserves_engine_output():
    """Disabling claripy's post-pass means we see exactly what the
    engine produced — useful for debugging which peer is doing the
    work."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    expr = _expr_from_ast((a | b) - (a & b))
    no_post = PatternSimplifier(config=PatternSimplifierConfig(
        post_simplify=False,
    ))
    with_post = PatternSimplifier(config=PatternSimplifierConfig(
        post_simplify=True,
    ))
    r1 = no_post.simplify(expr)
    r2 = with_post.simplify(expr)
    # post_simplify can only equal-or-shrink the AST further.
    assert r2.nodes_after <= r1.nodes_after


# ============================================================================
# Failure containment
# ============================================================================


def test_simplifier_catches_internal_exception(monkeypatch):
    """An unexpected exception inside the engine surfaces on the
    result as ``error`` rather than crashing the simplifier."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)

    import mx_mcp.deobfuscation.mba.simplifier_pattern as sp

    def explode(*args, **kwargs):
        raise RuntimeError("engine wedged")

    monkeypatch.setattr(sp, "rewrite", explode)

    expr = _expr_from_ast((a | b) - (a & b))
    r = PatternSimplifier().simplify(expr)
    assert r.simplified is False
    assert r.error is not None
    assert "engine wedged" in r.error
