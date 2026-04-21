"""Symbolic-execution budget model.

The P6 benchmark asks a question of shape: "within budget B, can angr
summarise handler H?" The :class:`SymbolicBudget` captures the three
axes that independently cap an attacker's compute:

* **Wall clock** — actual seconds burned per handler. Wall clock is
  the ultimate ceiling because it covers opaque angr internals (CFG
  recovery, SMT solver calls, loop unrolling) that ``max_steps``
  alone does not.
* **Steps** — count of ``SimulationManager.step()`` iterations.
  Proxies for "basic blocks executed per path × paths explored".
* **Paths** — ``len(simgr.active)`` cap. Controls exponential blow-up
  on handlers with branching opaque predicates.

All three bounds are enforced at the *top* of each step loop in
:mod:`.runner`, so the actual wall time may overshoot the cap by up
to one step (angr cannot mid-step). Callers reading
``HandlerAnalysisResult.wall_ms`` should not treat the field as a
strict upper bound.

Defaults are tuned for the ``slow`` tier budget (<30 min per
:doc:`MCP.md`). A 10-entry corpus × 32-handlers-per-entry × 10s cap
= ~50 min worst-case; in practice most handlers terminate in well
under a second, so the real runtime lands much lower. Retune
``max_wall_clock_s`` downward if the corpus grows, or sample a
subset of handlers per entry via ``max_handlers_per_entry`` on the
benchmark itself.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SymbolicBudget:
    """Per-handler compute cap for symbolic execution."""

    max_wall_clock_s: float = 10.0
    max_steps: int = 500
    max_paths: int = 50

    def __post_init__(self) -> None:
        if self.max_wall_clock_s <= 0:
            raise ValueError(
                f"max_wall_clock_s must be > 0 (got {self.max_wall_clock_s})"
            )
        if self.max_steps <= 0:
            raise ValueError(
                f"max_steps must be > 0 (got {self.max_steps})"
            )
        if self.max_paths <= 0:
            raise ValueError(
                f"max_paths must be > 0 (got {self.max_paths})"
            )
