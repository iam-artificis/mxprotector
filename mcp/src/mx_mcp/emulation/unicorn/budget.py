"""Emulation budget for the P9 Unicorn runners.

Mirrors :mod:`mx_mcp.symbolic.angr.budget` in spirit — three knobs
capping the per-binary / per-handler cost — but tuned for native
emulation instead of symbolic stepping.

* **Wall clock** — seconds Unicorn may spend on one run. Hard upper
  bound for both benchmarks; trips even when the emulator is happy
  but spinning on an internal loop.
* **Instructions** — a code-hook counter feeds back to the runner
  loop. Trips when the protected stub spirals on a decryption loop
  or the handler enters an obfuscated tight loop. Reads as the raw
  metric value for HIGHER_BETTER instruction-count rows.
* **Instructions per ``emu_start`` block** — how many instructions
  Unicorn is allowed to execute in a single ``emu_start`` invocation
  before our hook breaks back out for budget bookkeeping. Smaller
  values give tighter budget enforcement at the cost of throughput;
  defaults are tuned for the seed corpus.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EmulationBudget:
    """Per-run Unicorn cap.

    Defaults are advisory — tier runners override them when the corpus
    grows or the protector adds new emulation-resistant primitives.
    """

    max_wall_clock_s: float = 5.0
    max_instructions: int = 100_000
    max_instructions_per_block: int = 4096

    def __post_init__(self) -> None:
        if self.max_wall_clock_s <= 0:
            raise ValueError(
                f"max_wall_clock_s must be > 0 (got {self.max_wall_clock_s})"
            )
        if self.max_instructions <= 0:
            raise ValueError(
                f"max_instructions must be > 0 (got {self.max_instructions})"
            )
        if self.max_instructions_per_block <= 0:
            raise ValueError(
                "max_instructions_per_block must be > 0 "
                f"(got {self.max_instructions_per_block})"
            )
