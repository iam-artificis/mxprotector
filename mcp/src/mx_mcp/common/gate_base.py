"""IGate ABC + decorator-based registry (OCP) for ship-gate evaluation.

Every gate is one file under :mod:`mx_mcp.gates`. A gate maps a
specific ``(benchmark, metric)`` pair to a hard threshold and emits
a :class:`GateOutcome` of level PASS / WARN / FAIL / SKIPPED.

Adding a new gate = new file in ``gates/`` + one import line in
``gates/__init__.py``. Zero edits to the registry, zero edits to the
runner that aggregates outcomes — the OCP shape mirrors
:mod:`benchmark_base` and :mod:`tool_base`.

## Design rationale

* **One gate per (benchmark, metric).** A single benchmark can emit
  several metrics; each gets its own gate so thresholds can be
  reviewed in isolation. A future gate covering "the *aggregate* of
  metrics A, B, C" is still possible — it just declares its own
  ``benchmark/metric`` keys (or registers as a composite).
* **Tier-scoped blocking.** Each gate declares which tier it can
  block (``fast`` / ``slow`` / ``any``). A FAIL on a slow-tier-only
  gate during a fast-tier run becomes a WARN: blocking the commit
  on a metric the fast tier did not run is a UX bug.
* **Fail-closed defaults.** If the metric is missing (the benchmark
  errored, the corpus had no matching entries) the outcome is
  SKIPPED rather than PASS — silent passes are forbidden.
* **No global state.** Concrete gates may be stateless dataclasses
  or full classes; they receive their input via the ``evaluate``
  argument and return a fresh outcome each time.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import ClassVar

from pydantic import BaseModel, Field

from mx_mcp.common.benchmark_base import MetricResult


_LOG = logging.getLogger(__name__)


# ============================================================================
# Tier scope — which run a gate can block
# ============================================================================


class GateScope(str, Enum):
    """Which tier(s) a gate is authoritative for.

    * ``fast`` — the gate may block a commit. Only consulted when the
      caller runs the ``fast`` tier.
    * ``slow`` — the gate may block a merge. Only consulted when the
      caller runs the ``slow`` tier.
    * ``any``  — the gate runs in both tiers (used for cross-cutting
      gates like ``no_metadata_leakage``).
    """

    FAST = "fast"
    SLOW = "slow"
    ANY = "any"


# ============================================================================
# Outcome model
# ============================================================================


class GateLevel(str, Enum):
    """Per-gate outcome level.

    * ``pass``    — the metric cleared the threshold.
    * ``warn``    — the metric drifted past a soft band but did not
                    breach the hard threshold; informational only.
    * ``fail``    — the hard threshold was breached. Blocks the tier
                    iff the gate's :class:`GateScope` is in scope.
    * ``skipped`` — the metric was unavailable (benchmark errored,
                    corpus empty, fail-closed reasons). Distinguished
                    from PASS so the runner cannot inflate a verdict.
    """

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIPPED = "skipped"


class GateOutcome(BaseModel):
    """Single-gate evaluation record.

    ``observed`` is the value the gate compared against the threshold
    (typically ``aggregate.p90`` for higher/lower-better metrics or
    ``aggregate.mean`` for FALSE_BEST). ``threshold_repr`` is a
    human-readable rendering of the threshold ("≥ 0.70", "= 0",
    "p90 ≥ 800") so reviewers can grok the gate without reading code.
    ``evidence`` carries arbitrary diagnostic payloads — typically
    the benchmark's own metric evidence forwarded for context.
    """

    gate: str = Field(description="Gate name (matches IGate.name).")
    benchmark: str
    metric: str
    level: GateLevel
    scope: GateScope
    threshold_repr: str
    observed: float | None
    message: str
    evidence: dict = Field(default_factory=dict)

    def is_blocking(self, tier: str) -> bool:
        """True iff this outcome is a FAIL in scope for ``tier``.

        ``tier`` is the caller's run tier (``"fast"`` / ``"slow"``).
        A FAIL on a gate scoped to a different tier is non-blocking
        (the runner downgrades it to WARN before this check fires,
        so most callers do not need this method directly).
        """
        if self.level is not GateLevel.FAIL:
            return False
        if self.scope is GateScope.ANY:
            return True
        return self.scope.value == tier


# ============================================================================
# IGate ABC
# ============================================================================


class IGate(ABC):
    """Single ship-gate.

    Subclasses declare class-level metadata and implement
    :meth:`evaluate`. The runner walks the registry, looks up each
    gate's ``(benchmark, metric)`` in the measurement result, and
    invokes ``evaluate`` once per match.

    Stateless — no constructor args, no global state. Tests may
    subclass for injection if needed; production gates instantiate
    with the zero-arg constructor.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    benchmark: ClassVar[str]
    metric: ClassVar[str]
    scope: ClassVar[GateScope]

    @abstractmethod
    def evaluate(self, metric_result: MetricResult) -> GateOutcome:
        """Return a :class:`GateOutcome` for ``metric_result``.

        Implementations decide which aggregate (``p90`` / ``mean`` /
        ``p50``) drives the verdict and how to render the threshold
        for ``threshold_repr``. The runner caps wall time at the
        ``measure_defense`` outer timeout so gates need not enforce
        their own budgets.
        """


# ============================================================================
# Registry
# ============================================================================


_REGISTRY: list[type[IGate]] = []


def register_gate(cls: type[IGate]) -> type[IGate]:
    """Class decorator: register a gate at import time.

    Validates the contract (required class attrs, unique name, known
    ``scope``) so misconfigured gates fail fast at module load rather
    than on first call.
    """
    if not issubclass(cls, IGate):
        raise TypeError(f"{cls.__name__} must subclass IGate")

    for required in ("name", "description", "benchmark", "metric", "scope"):
        if not hasattr(cls, required):
            raise TypeError(
                f"{cls.__name__} missing required class attr '{required}'"
            )

    for existing in _REGISTRY:
        if existing.name == cls.name:
            raise ValueError(
                f"gate name collision on '{cls.name}': "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )

    _LOG.debug(
        "registered gate: %s (%s/%s, %s)",
        cls.name, cls.benchmark, cls.metric, cls.scope.value,
    )
    _REGISTRY.append(cls)
    return cls


def all_gates() -> list[type[IGate]]:
    """Return registered gate classes in registration order."""
    return list(_REGISTRY)


__all__ = [
    "GateLevel",
    "GateOutcome",
    "GateScope",
    "IGate",
    "all_gates",
    "register_gate",
]
