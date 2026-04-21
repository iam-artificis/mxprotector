"""Canonical MBA expression record + AST-size helper.

A :class:`MbaExpression` captures the claripy AST that falls out of
symbolic-executing one handler. We store the AST directly (so
simplifier backends can consume it), the handler RVA (provenance for
evidence blobs), the pre-simplification node count, and the depth.

The node-count helper is shared across extractor, simplifier, and
benchmark: we need the same metric on both sides of the
simplification to compute a reduction ratio. Depth is cached off the
claripy AST's own ``depth`` property and exposed as a plain int so
pydantic serialisation stays trivial.

## Capped node count

A pathological handler could in principle emit an AST with millions
of nodes (memory-heavy loop inside the handler, symbolic-pointer
blow-up, etc). The recursive visitor bounds work at
:data:`AST_NODE_CAP` — once hit, the count saturates at the cap and
downstream metrics are computed on the cap value. This is honest:
the measured reduction ratio becomes ``0.0`` for any saturated
expression (we cannot distinguish 5M → 3M from 5M → 4.9M reliably),
and a benchmark-side note can flag the saturation when it matters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Hard ceiling on AST node traversal. Chosen so the visitor finishes
# well under 100 ms even on the slowest realistic handler and never
# spins on a pathological graph.
AST_NODE_CAP = 50_000


@dataclass(frozen=True, slots=True)
class MbaExpression:
    """One handler's symbolic output expression.

    The ``ast`` payload is opaque ``Any`` because the claripy type
    hierarchy pulls ``angr`` in transitively and we want this module
    importable without the heavy backend. Callers that need angr-
    specific operations should ``isinstance(..., claripy.ast.Base)``
    at the call site.

    ``handler_rva`` + ``handler_opcode`` are carried for evidence
    only; the simplifier backends never read them.
    """

    handler_rva: int
    handler_opcode: str
    ast: Any
    ast_nodes: int
    ast_depth: int
    saturated: bool = field(default=False)


def count_ast_nodes(ast: Any, cap: int = AST_NODE_CAP) -> tuple[int, bool]:
    """Count unique AST nodes reachable from ``ast`` up to ``cap``.

    Returns ``(count, saturated)``. ``saturated`` is ``True`` iff the
    visitor stopped at ``cap`` before exhausting the graph — in
    which case the count equals ``cap`` and downstream ratios should
    treat the value conservatively.

    Visits via stack to keep the recursion depth bounded regardless
    of AST shape. ``id()``-based deduplication catches shared
    subtrees (claripy ASTs are hash-consed so the same sub-expression
    appears via the same Python object in multiple parent slots).

    ``ast`` with no ``args`` attribute (plain python scalars, or a
    non-AST sentinel) counts as ``1``. ``None`` counts as ``0``.
    """
    if ast is None:
        return 0, False

    seen: set[int] = set()
    stack: list[Any] = [ast]
    count = 0

    while stack:
        node = stack.pop()
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        count += 1
        if count >= cap:
            return cap, True
        args = getattr(node, "args", None)
        if not args:
            continue
        for child in args:
            # claripy ASTs define ``.op`` — plain integers/bitvectors
            # do not and are not useful to recurse into.
            if getattr(child, "op", None) is not None:
                stack.append(child)

    return count, False
