"""Unit tests for ``deobfuscation.mba.expression``.

Covers the pure AST-node counter. No angr / claripy dependency here —
the counter works on duck-typed objects so tests feed synthetic graphs
and assert the visitor's cap / dedup / scalar-leaf behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mx_mcp.deobfuscation.mba.expression import (
    AST_NODE_CAP,
    count_ast_nodes,
)


@dataclass
class _FakeAst:
    """Minimal claripy-like AST duck-type used by ``count_ast_nodes``."""

    op: str = "BVV"
    args: tuple = field(default_factory=tuple)


# ============================================================================
# Trivial inputs
# ============================================================================


def test_none_input_returns_zero():
    assert count_ast_nodes(None) == (0, False)


def test_plain_python_scalar_returns_one_leaf():
    # A naked int is not an AST but the visitor counts it as one node
    # (caller provided it as the "root" of something).
    assert count_ast_nodes(42) == (1, False)


def test_leaf_ast_returns_one():
    leaf = _FakeAst(op="BVS", args=())
    assert count_ast_nodes(leaf) == (1, False)


# ============================================================================
# Recursive graphs
# ============================================================================


def test_linear_chain_counts_each_node_once():
    c = _FakeAst(args=(_FakeAst(args=(_FakeAst(),)),))
    # root → child → grandchild = 3 nodes.
    assert count_ast_nodes(c) == (3, False)


def test_branching_graph_counts_every_node():
    left = _FakeAst()
    right = _FakeAst(args=(_FakeAst(),))
    root = _FakeAst(args=(left, right))
    # root + left + right + right-child = 4.
    assert count_ast_nodes(root) == (4, False)


def test_shared_subtree_is_counted_only_once():
    """Claripy ASTs are hash-consed: the same subexpression Python
    object can appear under multiple parents. The visitor must
    deduplicate by ``id`` or else inflate the count."""
    shared = _FakeAst()
    parent = _FakeAst(args=(shared, shared, shared))
    # parent + shared = 2 nodes (three ``args`` slots, one dedup).
    assert count_ast_nodes(parent) == (2, False)


def test_cyclic_graph_does_not_infinite_loop():
    """A genuinely cyclic AST (rare but not impossible with mutable
    test fakes) must terminate — the visitor uses seen-set
    deduplication, not a fixed depth."""
    a = _FakeAst()
    b = _FakeAst(args=(a,))
    a.args = (b,)  # cycle!
    count, saturated = count_ast_nodes(a)
    assert count == 2
    assert saturated is False


# ============================================================================
# Cap semantics
# ============================================================================


def test_cap_saturates_at_limit():
    # Build a linear chain larger than the cap.
    cap = 10
    node = _FakeAst()
    root = node
    for _ in range(cap * 2):
        node = _FakeAst(args=(node,))
    root = node

    count, saturated = count_ast_nodes(root, cap=cap)
    assert saturated is True
    assert count == cap


def test_cap_does_not_trip_when_graph_smaller():
    root = _FakeAst(args=(_FakeAst(), _FakeAst()))
    count, saturated = count_ast_nodes(root, cap=100)
    assert saturated is False
    assert count == 3


def test_default_cap_is_exported_and_used():
    """``count_ast_nodes`` should fall back to ``AST_NODE_CAP`` when
    no ``cap`` is passed — the module exposes the constant for the
    benchmark's evidence blob so it stays in sync."""
    assert AST_NODE_CAP > 0
    # Sanity: default invocation respects the cap.
    node = _FakeAst()
    root = node
    for _ in range(5):  # tiny graph → cap never hit
        node = _FakeAst(args=(node,))
    root = node
    count, saturated = count_ast_nodes(root)  # cap defaulted
    assert count == 6
    assert saturated is False
