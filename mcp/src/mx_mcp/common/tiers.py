"""Tier classification for benchmarks.

Three tiers describe *when* a benchmark runs and *how much budget* it
gets before being killed. Each ``IBenchmark`` declares a tier via its
``tier`` class attribute; callers filter by tier to pick the subset
that fits the current context (pre-commit, pre-PR, nightly).

Gate policy (enforced by tier runners in a later phase):

* **fast** — every build, hard budget <5 min. Failure blocks commit.
  Contents: cheap static sidecar metrics, msynth, IDA microcode,
  pe-sieve, Unicorn OEP-reach, Frida smoke.
* **slow** — pre-PR review, budget <30 min. Failure blocks merge.
  Contents: angr handler-summarization, SiMBA ensemble, d810,
  diffing-resistance, anti-analysis coverage, constant-recovery,
  budget-to-crack.
* **nightly** — mainline only, budget several hours. Failure files an
  issue rather than blocking. Contents: Z3 equivalence ground truth,
  full 100+ corpus, public unpacker baselines. *MVP keeps an empty
  set here — nightly contents live in FUTURE.md.*

Budgets are advisory in P1 (no runner enforces them yet); a later
phase wires the tier runners with signal-based timeouts per
benchmark.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mx_mcp.common.benchmark_base import IBenchmark


class Tier(str, Enum):
    """Discrete tier labels — string-valued so they serialise cleanly."""

    FAST = "fast"
    SLOW = "slow"
    NIGHTLY = "nightly"


# Advisory suggested budget per tier. Runner-side enforcement lands
# with the tier-runner wiring phase (P9 in MCP.md). Keys are raw
# string values so the table is comfortable to read.
TIER_BUDGET_SECONDS: dict[Tier, int] = {
    Tier.FAST: 300,        # 5 min
    Tier.SLOW: 1800,       # 30 min
    Tier.NIGHTLY: 18000,   # 5 hours
}


def parse_tier(label: str) -> Tier:
    """Case-insensitive tier lookup.

    Raises ``ValueError`` with the list of accepted labels if unknown —
    standard pydantic-style error so callers can surface the message
    without post-processing.
    """
    normalised = label.strip().lower()
    for t in Tier:
        if t.value == normalised:
            return t
    raise ValueError(
        f"unknown tier '{label}'; expected one of {sorted(t.value for t in Tier)}"
    )


def filter_by_tier(
    benchmarks: list[type["IBenchmark"]], tier: Tier
) -> list[type["IBenchmark"]]:
    """Return benchmarks whose declared tier equals ``tier``.

    The comparison is on the string value (benchmarks declare
    ``tier: str`` on the class, not the ``Tier`` enum, to keep the ABC
    import-cycle free).
    """
    return [b for b in benchmarks if b.tier == tier.value]
