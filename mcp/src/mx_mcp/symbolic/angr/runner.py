"""angr-driven handler analysis.

One public callable, :func:`analyse_handler`: given a PE binary and a
handler RVA, run angr's simulation manager with a
:class:`~mx_mcp.symbolic.angr.budget.SymbolicBudget` cap and classify
the outcome.

## Outcome classification

* ``cleanly_finished`` — the simulation manager ran out of active
  states on its own within budget. Every remaining path landed in a
  terminal stash (``deadended``, ``unconstrained``, ``errored``).
  This is the "handler is summarisable" signal: angr walked the
  whole reachable CFG without busting any cap.
* ``budget_steps`` / ``budget_wall`` / ``budget_paths`` — budget
  exhausted before every path terminated. The handler outran the
  attacker's compute. "Not summarised."
* ``errored`` — angr itself raised (bad bytes, unsupported
  instruction, broken PE). We treat this as a backend glitch, not a
  defensive win — see ``benchmark.leakage`` fail-closed rationale.
  Callers decide the per-sample mapping.

## Backend availability

``import angr`` is a heavy side effect (pulls z3, claripy, pyvex,
cle). We perform it lazily inside :func:`analyse_handler` so the
rest of the MCP stays importable on hosts without the extra. If the
import fails or ``MX_MCP_ANGR_DISABLED`` is set (test hook),
:class:`AngrNotAvailableError` is raised — benchmarks translate this
into a single benchmark-level error rather than one per handler.

## Logging

angr is extremely chatty by default. We silence the ``angr`` and
``cle`` loggers on first use to keep MCP server output readable;
callers that want angr's verbose chatter back can reconfigure
logging after import.
"""

from __future__ import annotations

import importlib
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from mx_mcp.symbolic.angr.budget import SymbolicBudget


_LOG = logging.getLogger(__name__)

# Test-only escape hatch. When set to a truthy value, :func:`analyse_handler`
# raises :class:`AngrNotAvailableError` without attempting the import.
# Used by the benchmark's self-skip test to exercise the "backend
# missing" code path without actually uninstalling angr.
_DISABLE_ENV_VAR = "MX_MCP_ANGR_DISABLED"


class AngrNotAvailableError(RuntimeError):
    """Raised when the angr backend is missing or intentionally disabled."""


@dataclass(frozen=True, slots=True)
class HandlerAnalysisResult:
    """Per-handler analysis record.

    ``summarised`` collapses ``termination_reason`` into the single
    bool the benchmark aggregator needs. It equals
    ``termination_reason == 'cleanly_finished'`` — any budget hit
    or error counts as "not summarised" in the direct sense.

    ``steps`` is the *attempted* step count. For budget-exhausted
    handlers it equals the budget cap that tripped; for cleanly
    finished ones it is the real path count (≤ budget). Downstream
    the benchmark feeds this into ``vm_symbolic_cost_mean_steps``,
    which biases the metric upward for resistant handlers.

    ``error`` is populated only when ``termination_reason ==
    'errored'``; carries the angr exception's string form.
    """

    summarised: bool
    steps: int
    paths_explored: int
    wall_ms: int
    termination_reason: str
    error: str | None = None


# ============================================================================
# Backend loader (lazy)
# ============================================================================


_angr_module = None
_cle_module = None
_silenced = False


def _load_angr():
    """Import angr + cle lazily, silencing their noisy loggers once.

    Cached after the first successful load so subsequent calls are
    cheap. A failed import is *not* cached so a re-install mid-session
    can be picked up without restarting the server (rare but cheap).
    """
    global _angr_module, _cle_module, _silenced

    if os.environ.get(_DISABLE_ENV_VAR):
        raise AngrNotAvailableError(
            f"angr backend disabled via {_DISABLE_ENV_VAR} environment variable"
        )

    if _angr_module is not None and _cle_module is not None:
        return _angr_module, _cle_module

    try:
        angr = importlib.import_module("angr")
        cle = importlib.import_module("cle")
    except ImportError as e:
        raise AngrNotAvailableError(
            "angr backend not installed. Install with "
            'pip install -e ".[angr]" in mcp/ and re-run.'
        ) from e

    if not _silenced:
        for name in ("angr", "cle", "pyvex", "claripy"):
            logging.getLogger(name).setLevel(logging.ERROR)
        _silenced = True

    _angr_module = angr
    _cle_module = cle
    return angr, cle


# ============================================================================
# Public entry point
# ============================================================================


def analyse_handler(
    binary_path: Path,
    handler_rva: int,
    handler_size: int,
    budget: SymbolicBudget,
) -> HandlerAnalysisResult:
    """Run angr symbolic execution on one handler within a budget.

    Blocking. The benchmark wraps this in :func:`asyncio.to_thread` so
    the event loop stays responsive.

    ``handler_size`` is currently unused — angr discovers the handler's
    CFG on its own — but kept on the signature because the sidecar has
    it, and future work may use it to bound CFG recovery to the handler
    slice (avoid bleeding into the next handler via fall-through).

    Raises:
        AngrNotAvailableError: ``import angr`` failed or the env-var
            kill-switch is set. Benchmark converts this into a
            top-level error once (not once-per-handler).
    """
    angr, _ = _load_angr()

    t0 = time.monotonic()

    try:
        project = angr.Project(
            str(binary_path), auto_load_libs=False, use_sim_procedures=True,
        )
    except Exception as e:  # noqa: BLE001 — cle/angr raises a zoo of types
        return _errored_result(e, t0, "project_load_failed", handler_size=handler_size)

    absolute = project.loader.main_object.mapped_base + handler_rva

    try:
        state = project.factory.blank_state(
            addr=absolute,
            add_options={"BYPASS_UNSUPPORTED_SYSCALL",
                         "BYPASS_UNSUPPORTED_IROP"},
        )
        simgr = project.factory.simulation_manager(state)
    except Exception as e:  # noqa: BLE001
        return _errored_result(e, t0, "state_init_failed", handler_size=handler_size)

    steps = 0
    paths_peak = 1
    termination = "cleanly_finished"

    try:
        while simgr.active:
            # Budget checks at the TOP of the loop so we always report
            # a ``cleanly_finished`` when the simulation truly ran out
            # of active states, even on the last step.
            if steps >= budget.max_steps:
                termination = "budget_steps"
                break
            if len(simgr.active) > budget.max_paths:
                termination = "budget_paths"
                break
            if (time.monotonic() - t0) >= budget.max_wall_clock_s:
                termination = "budget_wall"
                break

            simgr.step()
            steps += 1
            paths_peak = max(paths_peak, len(simgr.active))
    except Exception as e:  # noqa: BLE001
        return _errored_result(
            e, t0, "step_raised",
            steps=steps, paths_explored=paths_peak,
            handler_size=handler_size,
        )

    wall_ms = int((time.monotonic() - t0) * 1000)
    summarised = termination == "cleanly_finished"

    _LOG.debug(
        "handler @0x%X size=%d → %s (steps=%d, paths_peak=%d, %dms)",
        handler_rva, handler_size, termination, steps, paths_peak, wall_ms,
    )

    return HandlerAnalysisResult(
        summarised=summarised,
        steps=steps,
        paths_explored=paths_peak,
        wall_ms=wall_ms,
        termination_reason=termination,
        error=None,
    )


# ============================================================================
# Private helpers
# ============================================================================


def _errored_result(
    exc: BaseException,
    t0: float,
    phase: str,
    *,
    steps: int = 0,
    paths_explored: int = 0,
    handler_size: int = 0,  # noqa: ARG001 — kept for future use
) -> HandlerAnalysisResult:
    """Wrap a runner-side exception into a :class:`HandlerAnalysisResult`.

    ``phase`` names where the exception fired; surfaces in the result's
    ``termination_reason`` (as ``errored``) and ``error`` (as a suffix).
    A benchmark reading the batch can cluster errors by phase to tell
    "project-loader crashes" from "mid-simulation asserts" apart.
    """
    wall_ms = int((time.monotonic() - t0) * 1000)
    return HandlerAnalysisResult(
        summarised=False,
        steps=steps,
        paths_explored=paths_explored,
        wall_ms=wall_ms,
        termination_reason="errored",
        error=f"{phase}: {type(exc).__name__}: {exc}",
    )
