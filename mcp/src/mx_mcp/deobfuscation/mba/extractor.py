"""angr-driven handler expression extractor.

Given a protected PE and a handler (RVA + size), runs angr symbolic
execution until the handler's basic block terminates — or a budget
caps the run — then reads the configured output register. The
resulting claripy AST is the handler's symbolic output expression:
the canonical input to the MBA simplifier benchmarks.

## Input register setup

Handlers in MxProtector's x64 VM do not use the normal x64 ABI.
Inner VM registers vary (``r14`` / ``r15`` per ``CLAUDE.md``), plus
``r11`` for the outer VPC and dispatch scratch in ``rax``. We do
NOT try to model the ABI: all general-purpose registers start as
fresh unconstrained symbolic variables. That way whatever register
the handler reads, it reads a clean symbol; whatever it writes,
falls out as a closed-form expression over those symbols. The
resulting AST may not correspond 1:1 to "the handler's semantic
input → output" — but its *complexity* is still an honest proxy
for "how much symbolic residue an attacker gets from running this
handler".

## Output register

MxProtector's VM handlers do not consistently use any single
register for their output — different handlers end state in
different places (``r14`` / ``r15`` for inner VM scratch, ``rax``
for ABI-return-style cases, ``[rsp]`` for stack-residing values).
The extractor therefore inspects **all** general-purpose registers
at termination and returns whichever register carries the *largest*
expression. This is an honest "maximum symbolic residue" signal:
whatever the handler leaves in a register for the dispatcher to
read, the extractor picks it up regardless of the convention.

Callers that need a specific register can override via
``output_register=``; in that mode the multi-register scan is
skipped and the named register is read directly.

## Budget

Small by design. Handlers are tiny (tens to a few hundred bytes);
they terminate in a handful of steps when given unconstrained
inputs. A 5-second wall + 100-step cap is enough headroom for any
realistic handler and keeps benchmark wall time proportional to
handler count.
"""

from __future__ import annotations

import importlib
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from mx_mcp.deobfuscation.mba.expression import (
    MbaExpression,
    count_ast_nodes,
)


_LOG = logging.getLogger(__name__)


# Test escape hatch. When truthy, :func:`extract_handler_expression`
# raises :class:`ExtractorUnavailableError` without attempting the
# import — mirrors the analogous hook in the angr symbolic runner.
_DISABLE_ENV_VAR = "MX_MCP_MBA_EXTRACTOR_DISABLED"


class ExtractorUnavailableError(RuntimeError):
    """Raised when the angr backend behind the extractor is missing."""


@dataclass(frozen=True, slots=True)
class ExpressionBudget:
    """Per-handler extraction budget. Small by design — see module docstring."""

    max_wall_clock_s: float = 5.0
    max_steps: int = 100

    def __post_init__(self) -> None:
        if self.max_wall_clock_s <= 0:
            raise ValueError(
                f"max_wall_clock_s must be > 0 (got {self.max_wall_clock_s})"
            )
        if self.max_steps <= 0:
            raise ValueError(
                f"max_steps must be > 0 (got {self.max_steps})"
            )


DEFAULT_EXTRACTOR_BUDGET = ExpressionBudget()


# Lazy import caches — same pattern as symbolic.angr.runner.
_angr_module = None
_claripy_module = None


def _load_angr_stack():
    """Import angr + claripy lazily and raise a typed error on miss."""
    global _angr_module, _claripy_module

    if os.environ.get(_DISABLE_ENV_VAR):
        raise ExtractorUnavailableError(
            f"MBA extractor disabled via {_DISABLE_ENV_VAR} environment variable"
        )

    if _angr_module is not None and _claripy_module is not None:
        return _angr_module, _claripy_module

    try:
        angr = importlib.import_module("angr")
        claripy = importlib.import_module("claripy")
    except ImportError as e:
        raise ExtractorUnavailableError(
            "angr not installed. Install with "
            'pip install -e ".[angr]" in mcp/ and re-run.'
        ) from e

    # Silence the angr/cle/pyvex/claripy loggers once — they are
    # extremely chatty, and the benchmark runs dozens of extractions.
    for name in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(name).setLevel(logging.ERROR)

    _angr_module = angr
    _claripy_module = claripy
    return angr, claripy


# x86-64 GP register names as used by angr's register file. ``blank_state``
# fills these with fresh symbols before we step, so the handler's first
# read of any GP register gets a clean symbolic input.
_GP_REGS: tuple[str, ...] = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)


def extract_handler_expression(
    binary_path: Path,
    handler_rva: int,
    handler_size: int,
    handler_opcode: str = "",
    *,
    output_register: str | None = None,
    budget: ExpressionBudget = DEFAULT_EXTRACTOR_BUDGET,
) -> MbaExpression:
    """Extract one handler's symbolic output expression.

    When ``output_register is None`` (default), scans every GP
    register at termination and returns the one with the largest AST
    node count. When set to an explicit register name, reads that
    register directly — useful for targeted experiments on handlers
    with a known convention.

    Raises:
        ExtractorUnavailableError: angr/claripy import failed or the
            kill-switch env var is set.

    Returns a :class:`MbaExpression`. If the handler errored out
    mid-simulation the function still returns a result — with the
    last-known output-register value if one was written, or a lone
    unconstrained symbol if the handler never touched the output
    register before crashing.

    ``handler_size`` is recorded in evidence but not currently used
    to bound the simulation. Future work can use it to terminate the
    simulation when execution falls outside the handler's extent
    (current budget-based termination suffices for the small handlers
    the protector emits).
    """
    angr, claripy = _load_angr_stack()

    project = angr.Project(
        str(binary_path), auto_load_libs=False, use_sim_procedures=True,
    )
    absolute = project.loader.main_object.mapped_base + handler_rva

    # Seed every GP register with a fresh symbolic variable keyed to
    # the handler's RVA so evidence blobs can correlate symbols across
    # re-runs of the same handler.
    state = project.factory.blank_state(
        addr=absolute,
        add_options={"BYPASS_UNSUPPORTED_SYSCALL", "BYPASS_UNSUPPORTED_IROP"},
    )
    for reg in _GP_REGS:
        sym = claripy.BVS(f"{reg}_{handler_rva:x}", 64)
        setattr(state.regs, reg, sym)

    simgr = project.factory.simulation_manager(state)
    t0 = time.monotonic()
    steps = 0

    while simgr.active:
        if steps >= budget.max_steps:
            break
        if (time.monotonic() - t0) >= budget.max_wall_clock_s:
            break
        try:
            simgr.step()
        except Exception:  # noqa: BLE001 — fail-closed
            break
        steps += 1

    # Pick the "best" state to read the output register from. Priority:
    # deadended (handler returned cleanly) → active (still running at
    # budget cut) → errored → original initial state. None-empty path
    # is guaranteed because the initial state always exists.
    candidate_state = _pick_state(simgr, state)

    if output_register is None:
        output_ast, chosen_reg, nodes, saturated = _pick_largest_register(
            candidate_state,
        )
    else:
        chosen_reg = output_register
        output_ast = _read_register_ast(candidate_state, output_register)
        nodes, saturated = count_ast_nodes(output_ast)

    depth = int(getattr(output_ast, "depth", 0) or 0)

    _LOG.debug(
        "handler @0x%X (%s): output %s → %d nodes, depth %d (steps=%d, %dms)",
        handler_rva, handler_opcode, chosen_reg,
        nodes, depth, steps, int((time.monotonic() - t0) * 1000),
    )

    return MbaExpression(
        handler_rva=handler_rva,
        handler_opcode=f"{handler_opcode}@{chosen_reg}" if handler_opcode else chosen_reg,
        ast=output_ast,
        ast_nodes=nodes,
        ast_depth=depth,
        saturated=saturated,
    )


def _pick_largest_register(state) -> tuple:
    """Return ``(ast, register_name, node_count, saturated)`` of the
    GP register whose value has the most AST nodes.

    Ties break toward the register earlier in :data:`_GP_REGS`
    (``rax`` first). Registers that raise while reading fall through
    silently — a best-effort scan, not a strict one.

    Guarantees a non-``None`` AST return: if every register lookup
    fails (extreme corner case), falls back to the state's ``rax``
    even if that raises — letting the error propagate is preferred
    over returning a silent ``None`` that downstream would have to
    special-case.
    """
    best_nodes = -1
    best_ast = None
    best_name = _GP_REGS[0]
    best_saturated = False

    for reg in _GP_REGS:
        try:
            ast = getattr(state.regs, reg)
        except AttributeError:
            continue
        nodes, sat = count_ast_nodes(ast)
        if nodes > best_nodes:
            best_nodes, best_ast, best_name, best_saturated = (
                nodes, ast, reg, sat,
            )

    if best_ast is None:
        # Every register raised. Let the fallback propagate whatever
        # the state decides to do on the first register — we tried.
        best_ast = state.regs.rax
        best_nodes, best_saturated = count_ast_nodes(best_ast)
        best_name = "rax"

    return best_ast, best_name, best_nodes, best_saturated


# ============================================================================
# Private helpers
# ============================================================================


def _pick_state(simgr, initial_state):
    """Return the state from ``simgr`` most likely to carry meaningful output.

    Deadended states are preferred (handler ran to a natural terminus
    like ``ret``). If no deadends exist, active states (budget hit)
    are the next best — they still carry the partial output. Errored
    states and the initial state are fallbacks that ensure the
    extractor always returns *something* callers can count nodes on.
    """
    if getattr(simgr, "deadended", None):
        return simgr.deadended[0]
    if getattr(simgr, "active", None):
        return simgr.active[0]
    if getattr(simgr, "errored", None):
        # ``simgr.errored`` elements are ErroredState wrappers — pull
        # the underlying state.
        err = simgr.errored[0]
        return getattr(err, "state", initial_state)
    return initial_state


def _read_register_ast(state, register_name: str):
    """Return ``state.regs.<register_name>`` without raising on exotic names.

    A mis-typed register name (e.g. caller passed ``"eax"`` on a 64-bit
    handler) still returns a claripy AST — the state's attribute lookup
    raises ``AttributeError`` only for genuinely unknown names, in
    which case we fall back to a fresh symbol so downstream metrics
    compute cleanly rather than crashing mid-batch.
    """
    try:
        return getattr(state.regs, register_name)
    except AttributeError:
        _LOG.warning("unknown output register %r; returning symbolic fallback",
                     register_name)
        import claripy as _claripy
        return _claripy.BVS(f"unknown_{register_name}", 64)
