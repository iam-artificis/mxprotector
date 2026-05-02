"""Unicorn-driven emulation runners for P9.

Two public functions, parallel in shape to
:mod:`mx_mcp.symbolic.angr.oep_reach`:

* :func:`run_oep_reach` — emulate the protected binary from its
  visible entry point and watch for execution at the original
  entry-point RVA.
* :func:`run_handler_replay` — drop a single VM handler into a
  minimal Unicorn sandbox; count instructions retired before the
  handler tail-dispatches out of its declared range.

Both runners share:

* :func:`_load_unicorn` — lazy backend import + env kill-switch.
  Returns :class:`UnicornNotAvailableError` when the package is
  missing so benchmarks can fold the failure into one top-level
  error.
* The internal hooks / drivers / register-seeding helpers live
  alongside in :mod:`._drivers` to keep this file's responsibility
  scoped to "public API + backend loader".

## Termination reasons

Both result types use a small fixed vocabulary so evidence blobs
can be compared across runs without string-prefix juggling. The
labels are re-exported from :mod:`._drivers` so callers can
``from mx_mcp.emulation.unicorn.runner import TERM_REACHED_OEP``
without reaching into the private module.

* OEP-reach: ``reached_oep`` / ``budget_instr`` / ``budget_wall``
  / ``unmapped_fetch`` / ``crashed`` / ``errored``.
* Handler replay: ``left_handler`` (PC moved out of declared range,
  i.e. the tail dispatch fired) / ``budget_instr`` /
  ``budget_wall`` / ``crashed`` / ``errored``.

``errored`` is reserved for bugs in this module (loader raised,
hook setup blew up); ``crashed`` is the *expected* signal when a
strong defence trips Unicorn on PEB / IAT / unmapped memory.
"""

from __future__ import annotations

import importlib
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from mx_mcp.emulation.unicorn._drivers import (
    RunState,
    TERM_BUDGET_INSTR,
    TERM_BUDGET_WALL,
    TERM_CRASHED,
    TERM_ERRORED,
    TERM_LEFT_HANDLER,
    TERM_REACHED_OEP,
    TERM_UNMAPPED_FETCH,
    classify_uc_error,
    drive_handler_replay,
    drive_oep_reach,
    install_handler_hooks,
    install_oep_hooks,
    seed_gp_registers,
)
from mx_mcp.emulation.unicorn.budget import EmulationBudget
from mx_mcp.emulation.unicorn.loader import load_pe


_LOG = logging.getLogger(__name__)


# Test escape hatch — same shape as the analogous angr / extractor
# kill switches.
_DISABLE_ENV_VAR = "MX_MCP_UNICORN_DISABLED"


class UnicornNotAvailableError(RuntimeError):
    """Raised when the Unicorn backend is missing or intentionally disabled."""


# ============================================================================
# Result records
# ============================================================================


@dataclass(frozen=True, slots=True)
class OepReachUnicornResult:
    """One run of :func:`run_oep_reach`.

    ``reached`` collapses :attr:`termination_reason` to the boolean
    benchmarks aggregate. ``instructions_executed`` is the number of
    instructions Unicorn actually retired before the run ended
    (whatever the cause); ``error`` is populated only on
    ``errored`` / ``crashed`` paths.
    """

    reached: bool
    instructions_executed: int
    wall_ms: int
    termination_reason: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class HandlerReplayResult:
    """One run of :func:`run_handler_replay`."""

    completed: bool
    instructions_executed: int
    wall_ms: int
    termination_reason: str
    last_pc: int
    error: str | None = None


# ============================================================================
# Backend loader
# ============================================================================


_unicorn_module = None


def _load_unicorn():
    """Import unicorn lazily; cached, env-var killable.

    Raises :class:`UnicornNotAvailableError` when the env-var
    kill-switch is set OR the import fails. The import is *not*
    cached on failure so a re-install mid-session can be picked up
    without restarting the server (cheap; rarely triggered).
    """
    global _unicorn_module

    if os.environ.get(_DISABLE_ENV_VAR):
        raise UnicornNotAvailableError(
            f"Unicorn backend disabled via {_DISABLE_ENV_VAR} environment variable"
        )

    if _unicorn_module is not None:
        return _unicorn_module

    try:
        uc = importlib.import_module("unicorn")
        importlib.import_module("unicorn.x86_const")
    except ImportError as e:
        raise UnicornNotAvailableError(
            "unicorn not installed. Install with "
            'pip install -e ".[unicorn]" in mcp/ and re-run.'
        ) from e

    _unicorn_module = uc
    return uc


# ============================================================================
# Public entry points
# ============================================================================


def run_oep_reach(
    binary_path: Path,
    target_oep_rva: int,
    budget: EmulationBudget,
) -> OepReachUnicornResult:
    """Emulate ``binary_path`` until its execution lands at the OEP.

    Blocking. Benchmarks wrap this in :func:`asyncio.to_thread`.

    ``target_oep_rva`` is the original (unprotected) entry-point RVA
    — the caller resolves it from the unprotected source PE's
    ``AddressOfEntryPoint`` and we add the protected binary's
    ``image_base`` here to get the absolute target.

    Raises:
        UnicornNotAvailableError: import / kill-switch failure. The
            benchmark surfaces this as a single top-level error.
    """
    uc = _load_unicorn()

    t0 = time.monotonic()
    try:
        loaded = load_pe(uc, binary_path)
    except Exception as e:  # noqa: BLE001 — fail-closed
        return OepReachUnicornResult(
            reached=False, instructions_executed=0,
            wall_ms=int((time.monotonic() - t0) * 1000),
            termination_reason=TERM_ERRORED,
            error=f"loader_failed: {type(e).__name__}: {e}",
        )

    target_addr = loaded.image_base + target_oep_rva
    state = RunState(
        budget=budget,
        deadline=t0 + budget.max_wall_clock_s,
        target_addr=target_addr,
    )

    install_oep_hooks(uc, loaded.mu, state)

    return drive_oep_reach(uc, loaded, state, t0)


def run_handler_replay(
    binary_path: Path,
    handler_rva: int,
    handler_size: int,
    budget: EmulationBudget,
) -> HandlerReplayResult:
    """Emulate one VM handler in isolation.

    Sets every GP register (except RSP/RBP, which the loader
    initialises to a real stack address) to a deterministic
    constant so the metric is reproducible. Stops when:

    * PC leaves the half-open ``[handler_rva, handler_rva + size)``
      range — the tail dispatch fired (``left_handler``).
    * The instruction count or wall budget trips.
    * Unicorn raises (``crashed`` / ``unmapped_fetch``).
    """
    uc = _load_unicorn()

    t0 = time.monotonic()
    try:
        loaded = load_pe(uc, binary_path)
    except Exception as e:  # noqa: BLE001 — fail-closed
        return HandlerReplayResult(
            completed=False, instructions_executed=0,
            wall_ms=int((time.monotonic() - t0) * 1000),
            termination_reason=TERM_ERRORED, last_pc=0,
            error=f"loader_failed: {type(e).__name__}: {e}",
        )

    handler_start = loaded.image_base + handler_rva
    handler_end = handler_start + handler_size

    seed_gp_registers(uc, loaded.mu, base_seed=handler_rva)

    state = RunState(
        budget=budget,
        deadline=t0 + budget.max_wall_clock_s,
        handler_start=handler_start,
        handler_end=handler_end,
    )
    install_handler_hooks(uc, loaded.mu, state)

    return drive_handler_replay(uc, loaded, handler_start, state, t0)


__all__ = [
    "HandlerReplayResult",
    "OepReachUnicornResult",
    "TERM_BUDGET_INSTR",
    "TERM_BUDGET_WALL",
    "TERM_CRASHED",
    "TERM_ERRORED",
    "TERM_LEFT_HANDLER",
    "TERM_REACHED_OEP",
    "TERM_UNMAPPED_FETCH",
    "UnicornNotAvailableError",
    "classify_uc_error",
    "run_handler_replay",
    "run_oep_reach",
]
