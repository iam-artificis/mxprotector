"""Unicorn run-loop internals — hooks, drivers, register seeding.

Private to :mod:`mx_mcp.emulation.unicorn.runner`. Kept in a sibling
module so :mod:`runner` stays a thin orchestration layer (public API
+ backend loader + result records) — runner.py is the file everyone
reads first; the run-loop bookkeeping is much louder than the API
surface and would drown out the contract if it lived alongside.

Two halves, one each per public runner:

* **OEP-reach** — :func:`install_oep_hooks` + :func:`drive_oep_reach`.
  Hook fires on every executed instruction, snapshots PC, stops when
  PC equals the target absolute or any budget cap trips.
* **Handler replay** — :func:`install_handler_hooks` +
  :func:`drive_handler_replay`. Same shape, but the stop condition
  is "PC left the declared handler range" — which signals the
  protector's inline tail dispatch handed off control.

Shared:

* :class:`RunState` — mutable bookkeeping threaded through hooks via
  closure. Hooks are plain Python callables with no extra-args slot,
  so a state object is the only place to thread instruction counts /
  deadlines / stop reasons.
* :func:`seed_gp_registers` — deterministic GP-register init. Runs
  matter for slow-tier metrics: random seeds would inflate p90 noise.
* :func:`classify_uc_error` — translate :class:`UcError` codes to the
  fixed termination vocabulary the result records use.

All public names here are intentionally underscore-free: the leading
underscore lives on the *module*, signalling "private to the package".
That keeps runner.py's re-imports readable.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from mx_mcp.emulation.unicorn.budget import EmulationBudget


_LOG = logging.getLogger(__name__)


# Termination labels — exposed via :mod:`runner` so benchmarks + tests
# can assert on them without spelunking string literals.
TERM_REACHED_OEP = "reached_oep"
TERM_LEFT_HANDLER = "left_handler"
TERM_BUDGET_INSTR = "budget_instr"
TERM_BUDGET_WALL = "budget_wall"
TERM_UNMAPPED_FETCH = "unmapped_fetch"
TERM_CRASHED = "crashed"
TERM_ERRORED = "errored"


# ============================================================================
# RunState
# ============================================================================


class RunState:
    """Mutable state threaded through the Unicorn hooks.

    Hooks are plain Python callables; we cannot pass extra args
    directly so the state object travels via closure.
    """

    __slots__ = (
        "budget", "deadline",
        "instructions_executed", "last_pc",
        "target_addr", "reached",
        "handler_start", "handler_end", "left_handler",
        "stop_reason",
    )

    def __init__(
        self,
        *,
        budget: EmulationBudget,
        deadline: float,
        target_addr: int | None = None,
        handler_start: int | None = None,
        handler_end: int | None = None,
    ) -> None:
        self.budget = budget
        self.deadline = deadline
        self.instructions_executed = 0
        self.last_pc = 0
        self.target_addr = target_addr
        self.reached = False
        self.handler_start = handler_start
        self.handler_end = handler_end
        self.left_handler = False
        self.stop_reason: str | None = None


# ============================================================================
# Hook installers
# ============================================================================


def install_oep_hooks(uc_module, mu, state: RunState) -> None:
    """Wire a UC_HOOK_CODE that snapshots PC + enforces budgets.

    The OEP-reach hook fires on every executed instruction. We
    short-circuit emulation by calling ``mu.emu_stop()`` once any
    of: target hit / instruction cap / wall cap is set.
    """

    def code_hook(mu, address, size, _user):
        state.last_pc = address
        state.instructions_executed += 1
        if address == state.target_addr:
            state.reached = True
            state.stop_reason = TERM_REACHED_OEP
            mu.emu_stop()
            return
        if state.instructions_executed >= state.budget.max_instructions:
            state.stop_reason = TERM_BUDGET_INSTR
            mu.emu_stop()
            return
        if time.monotonic() >= state.deadline:
            state.stop_reason = TERM_BUDGET_WALL
            mu.emu_stop()

    mu.hook_add(uc_module.UC_HOOK_CODE, code_hook)


def install_handler_hooks(uc_module, mu, state: RunState) -> None:
    """Same shape as OEP-reach but stops on PC leaving the handler range."""

    def code_hook(mu, address, size, _user):
        state.last_pc = address
        state.instructions_executed += 1
        # Tail-dispatch detection — handler runs past its declared
        # extent, signalling the protector's inline tail dispatch
        # has handed off control.
        if state.handler_end is not None and (
            address < state.handler_start or address >= state.handler_end  # type: ignore[operator]
        ):
            state.left_handler = True
            state.stop_reason = TERM_LEFT_HANDLER
            mu.emu_stop()
            return
        if state.instructions_executed >= state.budget.max_instructions:
            state.stop_reason = TERM_BUDGET_INSTR
            mu.emu_stop()
            return
        if time.monotonic() >= state.deadline:
            state.stop_reason = TERM_BUDGET_WALL
            mu.emu_stop()

    mu.hook_add(uc_module.UC_HOOK_CODE, code_hook)


# ============================================================================
# Drivers — run emulation, translate outcome.
#
# Imports of result records are local (inside the function bodies) so
# this private helper module does not pull the public API names back
# into the global namespace.
# ============================================================================


def drive_oep_reach(uc_module, loaded, state: RunState, t0: float):
    """Start the emulator and translate the outcome into an OepReachUnicornResult."""
    from mx_mcp.emulation.unicorn.runner import OepReachUnicornResult

    try:
        loaded.mu.emu_start(
            loaded.entry_point, 0,
            count=state.budget.max_instructions_per_block,
        )
    except uc_module.UcError as e:
        wall_ms = int((time.monotonic() - t0) * 1000)
        reason = classify_uc_error(uc_module, e)
        return OepReachUnicornResult(
            reached=state.reached,
            instructions_executed=state.instructions_executed,
            wall_ms=wall_ms,
            termination_reason=reason,
            error=f"{type(e).__name__}: {e}",
        )
    except Exception as e:  # noqa: BLE001 — fail-closed
        wall_ms = int((time.monotonic() - t0) * 1000)
        return OepReachUnicornResult(
            reached=False,
            instructions_executed=state.instructions_executed,
            wall_ms=wall_ms, termination_reason=TERM_ERRORED,
            error=f"{type(e).__name__}: {e}",
        )

    wall_ms = int((time.monotonic() - t0) * 1000)
    reason = state.stop_reason or TERM_BUDGET_INSTR
    return OepReachUnicornResult(
        reached=state.reached,
        instructions_executed=state.instructions_executed,
        wall_ms=wall_ms, termination_reason=reason, error=None,
    )


def drive_handler_replay(
    uc_module, loaded, handler_start: int, state: RunState, t0: float,
):
    """Start the emulator and translate the outcome into a HandlerReplayResult."""
    from mx_mcp.emulation.unicorn.runner import HandlerReplayResult

    try:
        loaded.mu.emu_start(
            handler_start, 0,
            count=state.budget.max_instructions_per_block,
        )
    except uc_module.UcError as e:
        wall_ms = int((time.monotonic() - t0) * 1000)
        reason = classify_uc_error(uc_module, e)
        return HandlerReplayResult(
            completed=state.left_handler,
            instructions_executed=state.instructions_executed,
            wall_ms=wall_ms, termination_reason=reason,
            last_pc=state.last_pc,
            error=f"{type(e).__name__}: {e}",
        )
    except Exception as e:  # noqa: BLE001 — fail-closed
        wall_ms = int((time.monotonic() - t0) * 1000)
        return HandlerReplayResult(
            completed=False,
            instructions_executed=state.instructions_executed,
            wall_ms=wall_ms, termination_reason=TERM_ERRORED,
            last_pc=state.last_pc,
            error=f"{type(e).__name__}: {e}",
        )

    wall_ms = int((time.monotonic() - t0) * 1000)
    reason = state.stop_reason or TERM_BUDGET_INSTR
    return HandlerReplayResult(
        completed=state.left_handler,
        instructions_executed=state.instructions_executed,
        wall_ms=wall_ms, termination_reason=reason,
        last_pc=state.last_pc, error=None,
    )


# ============================================================================
# Helpers
# ============================================================================


def seed_gp_registers(uc_module, mu, *, base_seed: int) -> None:
    """Initialise every GP register to a deterministic constant.

    Reproducible runs matter for the slow-tier metric: random seeds
    would inflate p90 noise. We base every value on the handler RVA
    so different handlers see different inputs but a re-run on the
    same handler sees identical state.

    RSP/RBP are left alone — the loader already pointed them at the
    pre-mapped stack region.
    """
    consts = uc_module.x86_const
    for offset, reg in enumerate((
        consts.UC_X86_REG_RAX, consts.UC_X86_REG_RBX, consts.UC_X86_REG_RCX,
        consts.UC_X86_REG_RDX, consts.UC_X86_REG_RSI, consts.UC_X86_REG_RDI,
        consts.UC_X86_REG_R8, consts.UC_X86_REG_R9, consts.UC_X86_REG_R10,
        consts.UC_X86_REG_R11, consts.UC_X86_REG_R12, consts.UC_X86_REG_R13,
        consts.UC_X86_REG_R14, consts.UC_X86_REG_R15,
    )):
        mu.reg_write(reg, base_seed + offset * 0x100)


def classify_uc_error(uc_module: Any, exc: Any) -> str:
    """Map a ``UcError`` to a stable termination string.

    ``UC_ERR_FETCH_UNMAPPED`` is the canonical "stub tripped on PEB
    / IAT / missing ntdll" outcome — distinguished from generic
    crashes so evidence blobs can show the specific failure mode.
    """
    code = getattr(exc, "errno", None)
    if code == uc_module.UC_ERR_FETCH_UNMAPPED:
        return TERM_UNMAPPED_FETCH
    return TERM_CRASHED


__all__ = [
    "RunState",
    "TERM_BUDGET_INSTR",
    "TERM_BUDGET_WALL",
    "TERM_CRASHED",
    "TERM_ERRORED",
    "TERM_LEFT_HANDLER",
    "TERM_REACHED_OEP",
    "TERM_UNMAPPED_FETCH",
    "classify_uc_error",
    "drive_handler_replay",
    "drive_oep_reach",
    "install_handler_hooks",
    "install_oep_hooks",
    "seed_gp_registers",
]
