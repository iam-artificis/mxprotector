"""MBA rewrite-rule catalog.

A rule maps an obfuscated MBA pattern to its canonical equivalent.
Every rule in this file is hand-verified — bitwise truth-table or
two's-complement arithmetic — so the engine can apply them without
risk of altering observable semantics.

## Why we curate, instead of synthesising

A symbolic-equivalence check (e.g. claripy ⊨ Z3) would let us prove
arbitrary identities at runtime, but the cost dwarfs the gain: each
handler in the corpus would need a Z3 round-trip per candidate
rewrite, blowing the slow-tier wall budget. Curated identities pay
the cost once (during this file's review) and the benchmark does
constant-time matching at run time. The trade-off mirrors how
SiMBA / MBA-Blast operate in practice.

## Coverage

The catalog targets the kinds of expressions an MBA-obfuscation pass
emits — the classical "linear MBA" identities plus a few two's-complement
canonicalisations. Patterns claripy already collapses on its own
(``a + 0``, ``a ^ a``, …) are intentionally omitted: the engine
delegates those to ``claripy.simplify`` as a post-pass.

## Adding a new identity

1. Add a new ``MbaIdentity`` constant near a topical neighbour.
2. Provide a ``match`` callable returning the bound subterms or
   ``None``, and a ``rewrite`` callable that builds the simplified
   AST from those subterms.
3. Add a unit test in ``tests/test_mba_pattern_rules.py``: input
   AST + expected post-rewrite AST.
4. Append the new constant to :data:`ALL_RULES`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

# Bound subterms passed from match → rewrite. We keep it as a plain
# tuple of claripy ASTs so rewrite logic stays unaware of which
# concrete identity fired.
BoundArgs = tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class MbaIdentity:
    """One MBA rewrite rule.

    ``match`` inspects an AST and returns the bound subterms (in the
    order ``rewrite`` expects) when the rule fires; ``None`` when it
    does not apply. ``rewrite`` constructs the canonical equivalent
    AST from the bound subterms.

    The two callables are split (rather than a single transform fn)
    so the engine can log "rule X fired on node Y" without re-running
    the match. Tests likewise can verify match independently of
    rewrite.
    """

    name: str
    description: str
    match: Callable[[Any], BoundArgs | None]
    rewrite: Callable[[BoundArgs], Any]


# ============================================================================
# AST helpers — small enough to live with the rules; promoting them to
# their own module would add an import without functional benefit.
# ============================================================================


def _op(ast: Any) -> str | None:
    """Return ``ast.op`` if present, else ``None``.

    Claripy ASTs always carry ``op``; plain Python scalars and BVVs
    do not. ``None`` lets matchers short-circuit on non-AST inputs
    without a try/except.
    """
    return getattr(ast, "op", None)


def _ast_eq(a: Any, b: Any) -> bool:
    """Structural equality on claripy ASTs.

    Claripy hash-conses ASTs: equivalent sub-expressions share a
    Python object, so identity is the fast-path. Newer claripy
    builds expose a ``cache_key`` for cross-process equality; older
    ones (the version pinned in this repo) only guarantee that
    ``hash`` matches under hash-consing. We try both, falling back
    to plain ``is``.

    Plain Python values (integers, sentinels in tests) are unequal
    unless ``is`` already says so — claripy's overloaded ``==``
    returns a symbolic predicate, not a bool, so we deliberately
    avoid it.
    """
    if a is b:
        return True
    # Restrict the deep-equality path to inputs that look like
    # claripy ASTs. Otherwise ``hash(1) == hash(1)`` would falsely
    # report two plain Python integers as structurally-equal AST
    # subterms, which would let bogus rule matches through on
    # degenerate test inputs.
    if not hasattr(a, "op") or not hasattr(b, "op"):
        return False
    a_key = getattr(a, "cache_key", None)
    b_key = getattr(b, "cache_key", None)
    if a_key is not None and b_key is not None:
        try:
            return bool(a_key == b_key)
        except Exception:  # noqa: BLE001 — fall through
            pass
    # Fallback: claripy AST objects are hash-consed, so equal hashes
    # imply structurally-equal ASTs.
    try:
        if hash(a) != hash(b):
            return False
    except TypeError:
        return False
    # ``structurally_match`` is the explicit deep-equality method
    # claripy exposes when the cheap hash agrees.
    matcher = getattr(a, "structurally_match", None)
    if callable(matcher):
        try:
            return bool(matcher(b))
        except Exception:  # noqa: BLE001
            return False
    return False


def _binop_args(ast: Any, op: str) -> tuple[Any, Any] | None:
    """Return the ``(lhs, rhs)`` of ``ast`` iff its op is ``op``.

    Defensive against malformed nodes — a binary op AST with the
    wrong arity is not legal claripy but we tolerate it rather than
    raise mid-rewrite.
    """
    if _op(ast) != op:
        return None
    args = getattr(ast, "args", ())
    if len(args) != 2:
        return None
    return args[0], args[1]


def _is_bv_const(ast: Any, value: int) -> bool:
    """True iff ``ast`` is a concrete bitvector with the given value.

    Concrete claripy bitvectors carry op ``BVV``; the integer value
    sits in ``args[0]``. Symbolic ASTs return ``False``.
    """
    if _op(ast) != "BVV":
        return False
    args = getattr(ast, "args", ())
    return bool(args) and args[0] == value


def _commutative_match(
    lhs: Any, rhs: Any, l_op: str, r_op: str,
) -> tuple[Any, Any] | None:
    """Match ``binop(L_op(a, b), R_op(a, b))`` modulo argument order.

    Returns the bound ``(a, b)`` when the structure fires, ``None``
    otherwise. Used for identities of the form ``f(a,b) ⊕ g(a,b)``
    where both operands are commutative — six argument orderings
    collapse to one match path.
    """
    lhs_args = _binop_args(lhs, l_op)
    rhs_args = _binop_args(rhs, r_op)
    if lhs_args is None or rhs_args is None:
        return None
    a1, b1 = lhs_args
    a2, b2 = rhs_args
    if _ast_eq(a1, a2) and _ast_eq(b1, b2):
        return a1, b1
    if _ast_eq(a1, b2) and _ast_eq(b1, a2):
        return a1, b1
    return None


# ============================================================================
# Identities
#
# Each rule is paired with a one-liner truth-table or arithmetic note
# in its description so future readers can re-check correctness without
# re-deriving the identity.
# ============================================================================


# 1. (a | b) - (a & b) == a ^ b
#
# Bitwise: |=OR, &=AND. Per bit: 0/0→0-0=0; 1/0→1-0=1; 0/1→1-0=1;
# 1/1→1-1=0. Identical to XOR. The arithmetic subtraction does not
# carry because for every bit position |≥&, so no borrow propagates.
def _match_or_minus_and(ast: Any) -> BoundArgs | None:
    args = _binop_args(ast, "__sub__")
    if args is None:
        return None
    return _commutative_match(args[0], args[1], "__or__", "__and__")


def _rewrite_xor(args: BoundArgs) -> Any:
    a, b = args
    return a ^ b


OR_MINUS_AND = MbaIdentity(
    name="or_minus_and",
    description="(a | b) - (a & b) → a ^ b",
    match=_match_or_minus_and, rewrite=_rewrite_xor,
)


# 2. (a | b) + (a & b) == a + b
#
# Each bit position contributes its sum across the two operands. OR
# collects "1 if either", AND adds the second 1 in the both-ones case.
def _match_or_plus_and(ast: Any) -> BoundArgs | None:
    args = _binop_args(ast, "__add__")
    if args is None:
        return None
    # Try lhs=OR, rhs=AND first; then the swapped order.
    bound = _commutative_match(args[0], args[1], "__or__", "__and__")
    if bound is not None:
        return bound
    return _commutative_match(args[1], args[0], "__or__", "__and__")


def _rewrite_add(args: BoundArgs) -> Any:
    a, b = args
    return a + b


OR_PLUS_AND = MbaIdentity(
    name="or_plus_and",
    description="(a | b) + (a & b) → a + b",
    match=_match_or_plus_and, rewrite=_rewrite_add,
)


# 3. (a ^ b) + 2*(a & b) == a + b
#
# XOR is the carry-free sum; (a&b) is the bit-pairs that overflow
# into the next position; doubling shifts them up by one. Standard
# adder identity.
def _match_xor_plus_2and(ast: Any) -> BoundArgs | None:
    add_args = _binop_args(ast, "__add__")
    if add_args is None:
        return None
    for xor_side, mul_side in (add_args, (add_args[1], add_args[0])):
        xor_args = _binop_args(xor_side, "__xor__")
        if xor_args is None:
            continue
        mul_args = _binop_args(mul_side, "__mul__")
        if mul_args is None:
            continue
        # Match 2 * (a & b) — coefficient may be on either side of *.
        for coeff, term in (mul_args, (mul_args[1], mul_args[0])):
            if not _is_bv_const(coeff, 2):
                continue
            and_args = _binop_args(term, "__and__")
            if and_args is None:
                continue
            a_xor, b_xor = xor_args
            a_and, b_and = and_args
            if (_ast_eq(a_xor, a_and) and _ast_eq(b_xor, b_and)) or \
               (_ast_eq(a_xor, b_and) and _ast_eq(b_xor, a_and)):
                return a_xor, b_xor
    return None


XOR_PLUS_2AND = MbaIdentity(
    name="xor_plus_2and",
    description="(a ^ b) + 2*(a & b) → a + b",
    match=_match_xor_plus_2and, rewrite=_rewrite_add,
)


# 4. (a & b) ^ (a | b) == a ^ b
#
# AND keeps bits that are 1 in both; OR keeps bits that are 1 in
# either. XOR of those is exactly the bits in the symmetric
# difference — i.e. a ^ b.
def _match_and_xor_or(ast: Any) -> BoundArgs | None:
    args = _binop_args(ast, "__xor__")
    if args is None:
        return None
    return _commutative_match(args[0], args[1], "__and__", "__or__")


AND_XOR_OR = MbaIdentity(
    name="and_xor_or",
    description="(a & b) ^ (a | b) → a ^ b",
    match=_match_and_xor_or, rewrite=_rewrite_xor,
)


# 5. ~(~a & ~b) == a | b   (de Morgan)
def _match_demorgan_or(ast: Any) -> BoundArgs | None:
    if _op(ast) != "__invert__":
        return None
    inner = ast.args[0] if getattr(ast, "args", None) else None
    inner_args = _binop_args(inner, "__and__") if inner is not None else None
    if inner_args is None:
        return None
    a_neg, b_neg = inner_args
    if _op(a_neg) != "__invert__" or _op(b_neg) != "__invert__":
        return None
    return a_neg.args[0], b_neg.args[0]


def _rewrite_or(args: BoundArgs) -> Any:
    a, b = args
    return a | b


DEMORGAN_OR = MbaIdentity(
    name="demorgan_or",
    description="~(~a & ~b) → a | b",
    match=_match_demorgan_or, rewrite=_rewrite_or,
)


# 6. ~(~a | ~b) == a & b   (de Morgan)
def _match_demorgan_and(ast: Any) -> BoundArgs | None:
    if _op(ast) != "__invert__":
        return None
    inner = ast.args[0] if getattr(ast, "args", None) else None
    inner_args = _binop_args(inner, "__or__") if inner is not None else None
    if inner_args is None:
        return None
    a_neg, b_neg = inner_args
    if _op(a_neg) != "__invert__" or _op(b_neg) != "__invert__":
        return None
    return a_neg.args[0], b_neg.args[0]


def _rewrite_and(args: BoundArgs) -> Any:
    a, b = args
    return a & b


DEMORGAN_AND = MbaIdentity(
    name="demorgan_and",
    description="~(~a | ~b) → a & b",
    match=_match_demorgan_and, rewrite=_rewrite_and,
)


# 7. ~a + 1 == -a   (two's-complement canonicalisation)
#
# Direct from the definition of two's complement. Helps later
# identities by collapsing a ubiquitous obfuscation primitive.
def _match_invert_plus_one(ast: Any) -> BoundArgs | None:
    add_args = _binop_args(ast, "__add__")
    if add_args is None:
        return None
    for inv_side, one_side in (add_args, (add_args[1], add_args[0])):
        if _op(inv_side) != "__invert__":
            continue
        if not _is_bv_const(one_side, 1):
            continue
        inner = inv_side.args[0]
        return (inner,)
    return None


def _rewrite_neg(args: BoundArgs) -> Any:
    (a,) = args
    return -a


INVERT_PLUS_ONE = MbaIdentity(
    name="invert_plus_one",
    description="~a + 1 → -a",
    match=_match_invert_plus_one, rewrite=_rewrite_neg,
)


# 8. a + ~a == -1   (constant emergence)
#
# Bitwise: every position has exactly one of (a, ~a) set to 1, sum
# yields all-ones. -1 in two's complement.
def _match_a_plus_not_a(ast: Any) -> BoundArgs | None:
    add_args = _binop_args(ast, "__add__")
    if add_args is None:
        return None
    lhs, rhs = add_args
    if _op(rhs) == "__invert__" and _ast_eq(lhs, rhs.args[0]):
        return (lhs,)
    if _op(lhs) == "__invert__" and _ast_eq(rhs, lhs.args[0]):
        return (rhs,)
    return None


def _rewrite_minus_one(args: BoundArgs) -> Any:
    (a,) = args
    # Build the all-ones constant of matching width via claripy
    # arithmetic. ``-1`` resolves to the bitvector of the same width
    # under claripy's lazy folding without us importing the library.
    return a - a - 1


A_PLUS_NOT_A = MbaIdentity(
    name="a_plus_not_a",
    description="a + ~a → -1",
    match=_match_a_plus_not_a, rewrite=_rewrite_minus_one,
)


# ============================================================================
# Catalog
#
# Order matters only for trace-output readability — the engine keeps
# applying rules until no rule fires. Putting the high-impact
# linear-MBA identities first reduces the average iteration count
# on real handlers.
# ============================================================================


ALL_RULES: tuple[MbaIdentity, ...] = (
    OR_MINUS_AND,
    OR_PLUS_AND,
    XOR_PLUS_2AND,
    AND_XOR_OR,
    DEMORGAN_OR,
    DEMORGAN_AND,
    INVERT_PLUS_ONE,
    A_PLUS_NOT_A,
)


__all__ = [
    "ALL_RULES",
    "AND_XOR_OR",
    "A_PLUS_NOT_A",
    "BoundArgs",
    "DEMORGAN_AND",
    "DEMORGAN_OR",
    "INVERT_PLUS_ONE",
    "MbaIdentity",
    "OR_MINUS_AND",
    "OR_PLUS_AND",
    "XOR_PLUS_2AND",
]
