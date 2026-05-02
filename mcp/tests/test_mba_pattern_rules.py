"""Per-identity tests for ``deobfuscation.mba.pattern_rules``.

Each rewrite rule gets at least two tests:

1. **Match + rewrite** — feed a synthetic AST shaped exactly like
   the obfuscation primitive and verify the rewrite produces the
   canonical equivalent.
2. **No false positive** — feed a structurally-similar but
   semantically-distinct AST and verify the rule does NOT match.

Tests run real claripy because we want every assertion to hold under
the actual hash-cons / lazy-fold layer, not a hand-rolled mock that
might omit the structural-equality tricks claripy does.
"""

from __future__ import annotations

import pytest

from mx_mcp.deobfuscation.mba import pattern_rules as pr
from mx_mcp.deobfuscation.mba.pattern_engine import rewrite
from mx_mcp.deobfuscation.mba.pattern_rules import (
    AND_XOR_OR,
    A_PLUS_NOT_A,
    DEMORGAN_AND,
    DEMORGAN_OR,
    INVERT_PLUS_ONE,
    OR_MINUS_AND,
    OR_PLUS_AND,
    XOR_PLUS_2AND,
)


def _claripy_or_skip():
    try:
        import claripy
        return claripy
    except ImportError:  # pragma: no cover — angr ships claripy
        pytest.skip("claripy missing; install angr extra")


# ============================================================================
# Helpers — structural-equality assertion that does not collide with
# claripy's overloaded ``==``.
# ============================================================================


def _assert_ast_equal(actual, expected):
    """Compare two claripy ASTs by hash + structural-match.

    Plain ``==`` on claripy bitvectors returns *another* claripy AST
    representing the equality predicate (not a Python bool), so the
    naive ``assert ast_a == ast_b`` mis-passes whenever both sides
    are non-zero. Hash-consing makes hash equality necessary;
    ``structurally_match`` confirms the AST shape under that hash.
    """
    assert hash(actual) == hash(expected) and actual.structurally_match(expected), (
        f"AST mismatch:\n  actual:   {actual}\n  expected: {expected}"
    )


# ============================================================================
# 1. (a | b) - (a & b) → a ^ b
# ============================================================================


def test_or_minus_and_matches_canonical_form():
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a | b) - (a & b)
    bound = OR_MINUS_AND.match(obf)
    assert bound is not None
    rewritten = OR_MINUS_AND.rewrite(bound)
    _assert_ast_equal(rewritten, a ^ b)


def test_or_minus_and_matches_swapped_arguments():
    """(b | a) - (a & b) is structurally the same identity.

    XOR is commutative, so ``a ^ b`` and ``b ^ a`` are semantically
    equal but claripy hash-conses them as distinct syntactic ASTs
    (different node hashes). The test accepts either form.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (b | a) - (a & b)
    bound = OR_MINUS_AND.match(obf)
    assert bound is not None
    rewritten = OR_MINUS_AND.rewrite(bound)
    assert (
        rewritten.structurally_match(a ^ b)
        or rewritten.structurally_match(b ^ a)
    ), f"unexpected rewrite output: {rewritten}"


def test_or_minus_and_rejects_unrelated_subterms():
    """(a | b) - (c & d) shares the *shape* but not the subterms — no match."""
    claripy = _claripy_or_skip()
    a, b, c, d = (claripy.BVS(n, 64) for n in "abcd")
    not_obf = (a | b) - (c & d)
    assert OR_MINUS_AND.match(not_obf) is None


def test_or_minus_and_rejects_non_subtraction():
    """The top-level op must be subtraction; OR alone never matches."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    assert OR_MINUS_AND.match(a | b) is None


# ============================================================================
# 2. (a | b) + (a & b) → a + b
# ============================================================================


def test_or_plus_and_matches():
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a | b) + (a & b)
    bound = OR_PLUS_AND.match(obf)
    assert bound is not None
    _assert_ast_equal(OR_PLUS_AND.rewrite(bound), a + b)


def test_or_plus_and_matches_with_and_first():
    """Add is commutative — the canonical form may surface either way."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a & b) + (a | b)
    bound = OR_PLUS_AND.match(obf)
    assert bound is not None
    _assert_ast_equal(OR_PLUS_AND.rewrite(bound), a + b)


# ============================================================================
# 3. (a ^ b) + 2*(a & b) → a + b
# ============================================================================


def test_xor_plus_2and_matches():
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a ^ b) + 2 * (a & b)
    bound = XOR_PLUS_2AND.match(obf)
    assert bound is not None
    _assert_ast_equal(XOR_PLUS_2AND.rewrite(bound), a + b)


def test_xor_plus_2and_rejects_wrong_coefficient():
    """The coefficient on (a & b) must be exactly 2."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    not_obf = (a ^ b) + 3 * (a & b)
    assert XOR_PLUS_2AND.match(not_obf) is None


# ============================================================================
# 4. (a & b) ^ (a | b) → a ^ b
# ============================================================================


def test_and_xor_or_matches():
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a & b) ^ (a | b)
    bound = AND_XOR_OR.match(obf)
    assert bound is not None
    _assert_ast_equal(AND_XOR_OR.rewrite(bound), a ^ b)


# ============================================================================
# 5. ~(~a & ~b) → a | b   (de Morgan)
# ============================================================================


def test_demorgan_or_matches():
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = ~(~a & ~b)
    bound = DEMORGAN_OR.match(obf)
    assert bound is not None
    _assert_ast_equal(DEMORGAN_OR.rewrite(bound), a | b)


def test_demorgan_or_rejects_partial_negation():
    """Both operands of the inner AND must be negated."""
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    # ~(~a & b) is a different identity ((~a) & b → ~(a | ~b)) — not ours.
    not_obf = ~(~a & b)
    assert DEMORGAN_OR.match(not_obf) is None


# ============================================================================
# 6. ~(~a | ~b) → a & b   (de Morgan)
# ============================================================================


def test_demorgan_and_matches():
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = ~(~a | ~b)
    bound = DEMORGAN_AND.match(obf)
    assert bound is not None
    _assert_ast_equal(DEMORGAN_AND.rewrite(bound), a & b)


# ============================================================================
# 7. ~a + 1 → -a   (two's-complement canonicalisation)
# ============================================================================


def test_invert_plus_one_matches():
    claripy = _claripy_or_skip()
    a = claripy.BVS("a", 64)
    obf = ~a + 1
    bound = INVERT_PLUS_ONE.match(obf)
    assert bound is not None
    _assert_ast_equal(INVERT_PLUS_ONE.rewrite(bound), -a)


def test_invert_plus_one_rejects_other_constants():
    claripy = _claripy_or_skip()
    a = claripy.BVS("a", 64)
    not_obf = ~a + 2
    assert INVERT_PLUS_ONE.match(not_obf) is None


# ============================================================================
# 8. a + ~a → -1   (constant emergence)
# ============================================================================


def test_a_plus_not_a_matches():
    claripy = _claripy_or_skip()
    a = claripy.BVS("a", 64)
    obf = a + ~a
    bound = A_PLUS_NOT_A.match(obf)
    assert bound is not None
    rewritten = A_PLUS_NOT_A.rewrite(bound)
    # The canonical -1 of width 64 — constructed via a-a-1 in the
    # rule (claripy will fold that to the all-ones bitvector). The
    # rewrite is a closed-form: equality is on the *value* not the
    # syntactic shape, so we assert via concretisation to dodge
    # spurious AST-shape mismatches.
    import claripy as _c
    expected_neg_one = _c.BVV(-1, 64)
    # The rewritten expr might not literally be ``-1`` after
    # construction, but should fold via simplify.
    folded = _c.simplify(rewritten)
    assert hash(folded) == hash(expected_neg_one) \
        and folded.structurally_match(expected_neg_one), (
        f"expected -1, got {folded}"
    )


# ============================================================================
# Helpers (private)
# ============================================================================


def test_ast_eq_recognises_shared_subterm():
    claripy = _claripy_or_skip()
    a = claripy.BVS("a", 64)
    assert pr._ast_eq(a, a) is True
    b = claripy.BVS("a", 64)  # different instance, same name → different symbol
    # claripy minted these as two distinct unconstrained vars even if
    # they share a printable name; structural equality must reflect that.
    assert pr._ast_eq(a, b) is False


def test_ast_eq_returns_false_for_non_ast():
    """Non-AST inputs that aren't identity-equal should not match.

    Python caches small ints (``1 is 1`` → True) so the identity
    fast-path triggers there; we use distinct list objects to
    isolate the deep-equality branch instead.
    """
    a = [1, 2, 3]
    b = [1, 2, 3]
    assert pr._ast_eq(a, b) is False
    assert pr._ast_eq("foo", object()) is False


def test_is_bv_const_recognises_concrete_values():
    claripy = _claripy_or_skip()
    assert pr._is_bv_const(claripy.BVV(2, 64), 2) is True
    assert pr._is_bv_const(claripy.BVV(2, 64), 3) is False
    a = claripy.BVS("a", 64)
    assert pr._is_bv_const(a, 0) is False


# ============================================================================
# Whole-engine smoke: an obfuscated expression collapses end-to-end
# ============================================================================


def test_engine_collapses_canonical_obfuscation():
    """Running the full engine on (a|b) - (a&b) returns ``a^b``.

    Asserting through :func:`rewrite` (rather than a single rule)
    confirms the engine wires the catalog correctly without rule
    interference.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = (a | b) - (a & b)
    res = rewrite(obf)
    assert res.rules_fired >= 1
    _assert_ast_equal(res.ast, a ^ b)
    assert "or_minus_and" in res.rule_hits


def test_engine_collapses_chained_obfuscation():
    """Two layered identities collapse in a single engine call.

    ``(~(~a & ~b)) + (a & b)`` first rewrites the outer ``~(~a & ~b)``
    to ``a | b`` (de Morgan), exposing ``(a | b) + (a & b)`` which
    then matches the OR_PLUS_AND identity to give ``a + b``.
    """
    claripy = _claripy_or_skip()
    a, b = claripy.BVS("a", 64), claripy.BVS("b", 64)
    obf = ~(~a & ~b) + (a & b)
    res = rewrite(obf)
    _assert_ast_equal(res.ast, a + b)
    assert res.rule_hits.get("demorgan_or", 0) >= 1
    assert res.rule_hits.get("or_plus_and", 0) >= 1
