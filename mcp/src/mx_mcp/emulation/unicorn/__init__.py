"""Unicorn emulation backend (P9).

Two public runners share one loader and one budget model:

* :func:`run_oep_reach` — dynamic-emulation analogue of the angr
  ``budget_to_crack`` benchmark. Loads the protected PE, starts
  emulation at the visible entry point (the packer stub) and
  watches whether execution lands at the *original* entry-point
  RVA recovered from the unprotected source binary. The packer
  stub depends on PEB/IAT plumbing that Unicorn does not provide,
  so a fail-closed crash is the *expected* outcome on a strong
  build — that *is* the defence signal.
* :func:`run_handler_replay` — drops a single VM handler into a
  minimal Unicorn sandbox (stack page + GP registers seeded with
  deterministic constants) and counts the instructions the handler
  executes before either tail-dispatching out of its declared range
  or busting the budget. The number is a HIGHER_BETTER proxy for
  "how much native work hides inside one VM handler".

Public surface:

* :class:`EmulationBudget` — wall-clock + instruction caps.
* :class:`OepReachUnicornResult` / :class:`HandlerReplayResult`
  — outcome records.
* :class:`UnicornNotAvailableError` — raised when the backend is
  missing or disabled. Benchmarks fold this into one top-level
  error rather than per-entry noise.
"""

from mx_mcp.emulation.unicorn.budget import EmulationBudget
from mx_mcp.emulation.unicorn.runner import (
    HandlerReplayResult,
    OepReachUnicornResult,
    UnicornNotAvailableError,
    run_handler_replay,
    run_oep_reach,
)

__all__ = [
    "EmulationBudget",
    "HandlerReplayResult",
    "OepReachUnicornResult",
    "UnicornNotAvailableError",
    "run_handler_replay",
    "run_oep_reach",
]
