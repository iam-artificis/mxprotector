"""angr-driven OEP-reach analysis (P6 budget-to-crack metric).

Sister of :mod:`.runner` (handler summarisation). Where the handler
runner asks "can angr walk this VM handler to completion within a
budget?", this runner asks "starting from the protected binary's
visible entry point (the packer stub), how many symbolic-execution
steps does angr need to land on the *original* entry point?".

The sole public callable is :func:`analyse_oep_reach`. It takes the
protected PE plus the OEP RVA recovered from the unprotected source
binary (PE ``AddressOfEntryPoint``) and runs angr's simulation
manager under a :class:`SymbolicBudget` cap, returning an
:class:`OepReachResult` describing the outcome.

## Outcome classification

* ``reached_oep`` — at least one active state's program counter
  matches the target address inside budget. The benchmark reads
  the step count at that moment as the work an attacker would have
  burned to crack this build symbolically. Lower is worse defence.
* ``budget_steps`` / ``budget_wall`` / ``budget_paths`` — budget
  exhausted before any state hit the target. The benchmark reads
  this as "attacker did not crack within the budget"; the metric
  saturates at the budget cap. Higher is better defence.
* ``exhausted`` — the simulation manager ran out of active states
  on its own (every path landed in a terminal stash) without
  hitting the target. Treated like a budget hit at the actual step
  count: angr could not reach OEP, but for a different reason than
  budget exhaustion. The numeric metric uses the real step count.
* ``errored`` — angr crashed (bad bytes, unsupported instruction,
  loader failure). Fail-closed mirrors :mod:`.runner`: the result's
  ``steps`` is set to the budget cap so a backend glitch cannot
  inflate the defence score.

## Backend availability

``import angr`` is delegated to :func:`mx_mcp.symbolic.angr.runner._load_angr`
so backend kill-switches and import errors converge to the single
:class:`AngrNotAvailableError` shape the benchmarks already handle.

## Why ``entry_state`` (not ``blank_state``)

The packer stub sets up a real call frame, walks the PEB, and
performs IAT-style work — symbolic execution from a blank state
crashes immediately on undefined registers. ``entry_state``
materialises the OS-level init that a real loader would, so the
stub gets symbolic but plausible inputs. We still bypass
unsupported syscalls / IROPs because the packer trips a few of
them on Windows builds.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from mx_mcp.symbolic.angr.budget import SymbolicBudget
from mx_mcp.symbolic.angr.runner import (
    AngrNotAvailableError,
    _load_angr,  # private but stable; we want one shared import path
)


_LOG = logging.getLogger(__name__)


# Termination reasons for :class:`OepReachResult.termination_reason`. Kept
# as a single source of truth so the benchmark + tests can assert on
# the literal strings without spelunking through the runner.
TERM_REACHED = "reached_oep"
TERM_BUDGET_STEPS = "budget_steps"
TERM_BUDGET_WALL = "budget_wall"
TERM_BUDGET_PATHS = "budget_paths"
TERM_EXHAUSTED = "exhausted"
TERM_ERRORED = "errored"


@dataclass(frozen=True, slots=True)
class OepReachResult:
    """Per-binary OEP-reach analysis record.

    ``reached`` collapses :attr:`termination_reason` into the boolean
    the benchmark aggregator needs (true iff the symbolic engine landed
    a state at the OEP within budget).

    ``steps`` is the *attempted* step count. For ``reached_oep`` it is
    the step at which OEP was first hit (``≤ budget.max_steps``). For
    every other termination reason the value is the budget cap that
    tripped (or the actual count at exhaustion / error). The benchmark
    feeds this into ``budget_to_crack_steps_to_oep``, which is
    HIGHER_BETTER — resistant builds pin the metric near the cap.

    ``error`` is populated only when ``termination_reason ==
    'errored'`` and carries the angr exception's string form.
    """

    reached: bool
    steps: int
    paths_explored: int
    wall_ms: int
    termination_reason: str
    error: str | None = None


# ============================================================================
# Public entry point
# ============================================================================


def analyse_oep_reach(
    binary_path: Path,
    target_oep_rva: int,
    budget: SymbolicBudget,
) -> OepReachResult:
    """Run angr from the protected EP and budget the time to reach OEP.

    Blocking. The benchmark wraps this in :func:`asyncio.to_thread` so
    the event loop stays responsive under a long-running corpus.

    ``target_oep_rva`` is the original (unprotected) entry-point RVA —
    the address the packer stub eventually transfers control to.
    Caller resolves this from ``read_entry_point_rva`` on the
    *unprotected* corpus binary; we deliberately do not infer it from
    the protected PE because its ``AddressOfEntryPoint`` already points
    at the stub.

    Raises:
        AngrNotAvailableError: ``import angr`` failed or the env-var
            kill-switch is set. Benchmark converts this into a single
            top-level error rather than one per corpus entry.
    """
    angr, _ = _load_angr()

    t0 = time.monotonic()

    project = _open_project(angr, binary_path)
    if isinstance(project, OepReachResult):
        return project  # _open_project already produced an errored result

    target_addr = project.loader.main_object.mapped_base + target_oep_rva
    _LOG.debug(
        "OEP-reach %s: target rva=0x%X, abs=0x%X, budget=%s",
        binary_path.name, target_oep_rva, target_addr, budget,
    )

    state_or_err = _initial_state(angr, project, t0, budget)
    if isinstance(state_or_err, OepReachResult):
        return state_or_err
    simgr = state_or_err

    return _drive_simgr(simgr, target_addr, budget, t0)


# ============================================================================
# Simulation driver
# ============================================================================


def _drive_simgr(
    simgr,
    target_addr: int,
    budget: SymbolicBudget,
    t0: float,
) -> OepReachResult:
    """Step the simulation manager until OEP hit / budget exhausted / done.

    Order of checks per iteration:

    1. **Hit** — any active state at ``target_addr``? Done, ``reached_oep``.
       Checked first so a state that hits OEP on the very first step is
       not penalised by a budget check that fires on the same iteration.
    2. **Budget** — steps / wall / paths. Caps trip BEFORE the next
       ``step()`` so the reported step count is the count actually run.
    3. **Step** — advance one round. Symmetric crash handling: any
       angr exception under ``step()`` collapses to ``errored`` with
       the steps run so far preserved in the result for diagnosis.

    ``simgr.active`` may grow (path forks) or shrink (deadends /
    errored stashes) between iterations; we recompute the peak on
    every loop pass so the evidence reflects worst-case path-count
    pressure.
    """
    steps = 0
    paths_peak = max(1, len(simgr.active))

    while simgr.active:
        if _any_state_at(simgr.active, target_addr):
            wall_ms = int((time.monotonic() - t0) * 1000)
            return OepReachResult(
                reached=True,
                steps=steps,
                paths_explored=paths_peak,
                wall_ms=wall_ms,
                termination_reason=TERM_REACHED,
                error=None,
            )

        if steps >= budget.max_steps:
            return _budget_result(
                TERM_BUDGET_STEPS, budget.max_steps, paths_peak, t0,
            )
        if len(simgr.active) > budget.max_paths:
            return _budget_result(
                TERM_BUDGET_PATHS, steps, paths_peak, t0,
            )
        if (time.monotonic() - t0) >= budget.max_wall_clock_s:
            return _budget_result(
                TERM_BUDGET_WALL, steps, paths_peak, t0,
            )

        try:
            simgr.step()
        except Exception as e:  # noqa: BLE001 — angr raises a zoo of types
            return _errored_result(
                e, t0, "step_raised",
                steps=steps, paths_explored=paths_peak,
                budget_steps=budget.max_steps,
            )
        steps += 1
        paths_peak = max(paths_peak, len(simgr.active))

    # Active queue drained without ever hitting OEP — the reachable CFG
    # under the symbolic engine simply does not include the target.
    # Surfaces as a non-reach with the *real* step count rather than the
    # budget cap so evidence reflects how far angr actually got.
    return OepReachResult(
        reached=False,
        steps=steps,
        paths_explored=paths_peak,
        wall_ms=int((time.monotonic() - t0) * 1000),
        termination_reason=TERM_EXHAUSTED,
        error=None,
    )


# ============================================================================
# Project / state setup — broken out so each can produce its own
# errored result without nested try/except in the public function.
# ============================================================================


def _open_project(angr, binary_path: Path):  # type: ignore[no-untyped-def]
    """Create an ``angr.Project``; on failure return an errored result.

    Returning the result (rather than raising) keeps the public
    function linear: the caller does ``isinstance(... , OepReachResult)``
    once and threads the success path forward.
    """
    try:
        return angr.Project(
            str(binary_path),
            auto_load_libs=False,
            use_sim_procedures=True,
        )
    except Exception as e:  # noqa: BLE001 — cle/angr raise a zoo of types
        return _errored_result(
            e, time.monotonic(), "project_load_failed",
            steps=0, paths_explored=0, budget_steps=0,
        )


def _initial_state(angr, project, t0: float, budget: SymbolicBudget):  # type: ignore[no-untyped-def]
    """Build an entry state + simulation manager.

    Uses ``entry_state`` (not ``blank_state``) so the OS-level init
    angr's loader synthesises is in place — the packer stub immediately
    reads PEB / TEB / setup-stack pointers and would crash from a blank
    state on the first instruction.
    """
    try:
        state = project.factory.entry_state(
            add_options={
                "BYPASS_UNSUPPORTED_SYSCALL",
                "BYPASS_UNSUPPORTED_IROP",
            },
        )
        return project.factory.simulation_manager(state)
    except Exception as e:  # noqa: BLE001
        return _errored_result(
            e, t0, "state_init_failed",
            steps=0, paths_explored=0,
            budget_steps=budget.max_steps,
        )


# ============================================================================
# Helpers
# ============================================================================


def _any_state_at(active_states, target_addr: int) -> bool:
    """True iff at least one state's program counter equals ``target_addr``.

    angr's ``state.addr`` is concrete for active states (the simulation
    manager only schedules concrete-IP states). Any AttributeError from
    a non-standard fake (test seam) collapses to ``False`` so a partial
    mock cannot accidentally claim a hit.
    """
    for s in active_states:
        try:
            if int(s.addr) == target_addr:
                return True
        except (AttributeError, TypeError, ValueError):
            continue
    return False


def _budget_result(
    reason: str,
    steps: int,
    paths_peak: int,
    t0: float,
) -> OepReachResult:
    """Wrap a budget-exhaustion outcome.

    ``steps`` is the count actually executed at the moment of the cap
    check (==``budget.max_steps`` for ``budget_steps``; <cap for the
    wall / paths variants). The benchmark feeds this through into
    ``budget_to_crack_steps_to_oep`` raw, so the mean naturally tracks
    "how much compute did the attacker burn before giving up?".
    """
    return OepReachResult(
        reached=False,
        steps=steps,
        paths_explored=paths_peak,
        wall_ms=int((time.monotonic() - t0) * 1000),
        termination_reason=reason,
        error=None,
    )


def _errored_result(
    exc: BaseException,
    t0: float,
    phase: str,
    *,
    steps: int,
    paths_explored: int,
    budget_steps: int,
) -> OepReachResult:
    """Wrap a runner-side exception into an :class:`OepReachResult`.

    Fail-closed: ``steps`` reports the *budget cap* (or actual count
    if larger) so a backend crash cannot make the defence look weaker
    than it is. ``phase`` names where the exception fired and is
    embedded in ``error`` so callers can cluster errors by phase
    (``project_load_failed`` vs ``state_init_failed`` vs
    ``step_raised``).
    """
    wall_ms = int((time.monotonic() - t0) * 1000)
    return OepReachResult(
        reached=False,
        steps=max(steps, budget_steps),
        paths_explored=paths_explored,
        wall_ms=wall_ms,
        termination_reason=TERM_ERRORED,
        error=f"{phase}: {type(exc).__name__}: {exc}",
    )


# ``AngrNotAvailableError`` is imported above from ``runner``. Listing
# it here lets callers ``from mx_mcp.symbolic.angr.oep_reach import
# AngrNotAvailableError`` without reaching into the sibling module.
__all__ = [
    "AngrNotAvailableError",
    "OepReachResult",
    "TERM_BUDGET_PATHS",
    "TERM_BUDGET_STEPS",
    "TERM_BUDGET_WALL",
    "TERM_ERRORED",
    "TERM_EXHAUSTED",
    "TERM_REACHED",
    "analyse_oep_reach",
]
