"""Unit tests for ``deobfuscation.mba.pattern_engine``.

Engine-level invariants — rule-correctness lives in
``test_mba_pattern_rules`` so these tests focus on:

* Bottom-up traversal order.
* Fixed-point convergence.
* Budget caps.
* Safe handling of degenerate inputs (None, scalars).
* Failure containment when a rule's rewrite raises.
"""

from __future__ import annotations

import pytest

from mx_mcp.deobfuscation.mba.pattern_engine import (
    PatternEngineBudget,
    RewriteResult,
    rewrite,
)
from mx_mcp.deobfuscation.mba.pattern_rules import (
    ALL_RULES,
    OR_MINUS_AND,
    MbaIdentity,
)


def _claripy_or_skip():
    try:
        import claripy
        return claripy
    except ImportError:  # pragma: no cover
        pytest.skip("claripy missing; install angr extra")


# ============================================================================
# Budget validation
# ============================================================================


@pytest.mark.parametrize("kwargs", [
    {"max_rule_applications": 0},
    {"max_rule_applications": -3},
])
def test_budget_rejects_nonpositive(kwargs):
    with pytest.raises(ValueError):
        PatternEngineBudget(**kwargs)


# ============================================================================
# Degenerate inputs round-trip
# ============================================================================


def test_rewrite_passes_through_none():
    res = rewrite(None)
    assert isinstance(res, RewriteResult)
    assert res.ast is None
    assert res.rules_fired == 0
    assert res.budget_exceeded is False


def test_rewrite_passes_through_non_ast():
    res = rewrite(42)
    assert res.ast == 42
    assert res.rules_fired == 0


def test_rewrite_returns_input_when_no_rule_matches():
    """A symbol with no surrounding op produces nothing to rewrite."""
    claripy = _claripy_or_skip()
    a = claripy.BVS("a", 64)
    res = rewrite(a)
    assert res.ast is a or res.ast.structurally_match(a)
    assert res.rules_fired == 0


# ============================================================================
# Fixed-point loop
# ============================================================================


def test_rewrite_reaches_fixed_point_on_chained_identities():
    """A chained obfuscation should fully collapse in one rewrite call.

    We verify by counting rule fires: more than one fire means the
    engine kept going after the first match instead of stopping at
    the top of the AST.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = ((a | b) - (a & b)) + (~(~a & ~b))  # XOR + OR (after de Morgan)
    res = rewrite(obf)
    assert res.rules_fired >= 2
    assert res.budget_exceeded is False


# ============================================================================
# Budget cap behaviour
# ============================================================================


def test_budget_cap_terminates_pathological_loop():
    """Construct a synthetic identity that always fires; cap stops it.

    Real identities terminate naturally because they shrink the AST.
    A bug — e.g. a rule that produces a different AST shape but the
    *same* abstract pattern — could in principle loop. The budget is
    the safety net: this test simulates that scenario with an
    intentionally non-terminating rule and verifies the engine bails.
    """
    claripy = _claripy_or_skip()

    a = claripy.BVS("a", 64)

    def always_match(node):
        # Match any AST that has an op — i.e. anything non-trivial.
        if getattr(node, "op", None) is None:
            return None
        return (node,)

    def echo_rewrite(args):
        # Wrap in a tautology so the AST changes shape but the
        # pattern keeps matching. ``a + 0`` is then post-simplified
        # by claripy back to ``a``, so the engine sees a fresh AST
        # but the structural pattern persists. Without a cap this
        # would loop forever.
        (n,) = args
        return n + claripy.BVV(0, 64) - claripy.BVV(0, 64)

    pathological = MbaIdentity(
        name="pathological_echo",
        description="(test) any → (any + 0 - 0)",
        match=always_match,
        rewrite=echo_rewrite,
    )

    res = rewrite(
        a + a, rules=(pathological,),
        budget=PatternEngineBudget(max_rule_applications=5),
    )
    assert res.budget_exceeded is True
    assert res.rules_fired == 5


# ============================================================================
# Failure containment
# ============================================================================


def test_rule_rewrite_exception_is_caught_and_skipped():
    """A rule that raises during rewrite leaves the AST untouched.

    The engine logs at DEBUG and moves on to the next rule rather than
    propagating the exception out — the benchmark depends on this for
    fail-closed per-handler reporting.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)

    def always_match(node):
        if getattr(node, "op", None) == "__sub__":
            return tuple(node.args)
        return None

    def boom(args):
        raise RuntimeError("rewrite blew up")

    bad_rule = MbaIdentity(
        name="bad_rule", description="(test) raises",
        match=always_match, rewrite=boom,
    )

    obf = (a | b) - (a & b)
    # bad_rule raises on the outer __sub__; OR_MINUS_AND should still
    # succeed via fall-through.
    res = rewrite(obf, rules=(bad_rule, OR_MINUS_AND))
    assert res.rules_fired >= 1
    assert "or_minus_and" in res.rule_hits


# ============================================================================
# Bottom-up ordering
# ============================================================================


def test_rewrite_processes_children_before_parent():
    """Inner pattern collapses first; the outer pattern then matches
    against the simplified child."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)

    # Outer XOR contains an inner OR_PLUS_AND-shaped expression. After
    # the inner rewrite to ``a + b``, the outer AST is just
    # ``(a + b) ^ c`` for which no rule fires — we just want to assert
    # the inner rewrite happened.
    c = claripy.BVS("c", 64)
    obf = ((a | b) + (a & b)) ^ c
    res = rewrite(obf)
    # Top op stays XOR; one of its children is now a + b instead of
    # the OR_PLUS_AND obfuscation.
    assert res.ast.op == "__xor__"
    inner = res.ast.args[0]
    assert inner.op == "__add__"


# ============================================================================
# Default catalog round-trips
# ============================================================================


def test_default_catalog_is_all_rules():
    """The engine defaults to applying the full identity catalog."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a | b) - (a & b)
    res_default = rewrite(obf)
    res_explicit = rewrite(obf, rules=ALL_RULES)
    assert res_default.rule_hits == res_explicit.rule_hits
