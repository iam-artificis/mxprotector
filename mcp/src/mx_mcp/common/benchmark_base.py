"""IBenchmark ABC + decorator-based registry (OCP).

Every defense benchmark is a single file under
``mx_mcp.benchmarks`` that declares one ``IBenchmark`` subclass
decorated with ``@register_benchmark``. The registry is populated at
import time; ``tools.measure_defense`` walks it to run the full
suite or a filtered subset.

Adding a new benchmark = new file, one import line in the benchmarks
package ``__init__.py``, zero edits to existing code.

Design notes:

* Benchmarks produce **distributions**, not single numbers. Each metric
  carries per-corpus-sample values plus an ``AggregateStats`` with
  p10/p50/p90/mean/stddev. Gates in later phases decide on p90 (or
  worse percentile) so a single broken hot-sample cannot hide behind
  the mean.
* **Fail-closed** is baked into the data model: when a backend crashes
  on a sample, ``MetricSample.value`` is ``None`` and the sample counts
  toward ``AggregateStats.n_errors``. Aggregators treat ``None``
  consistently as worst-case.
* All shared types are ``pydantic.BaseModel`` so they serialise
  cleanly through MCP tool outputs without additional adapters.
"""

from __future__ import annotations

import logging
import statistics
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Sequence

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from mx_mcp.common.corpus import Corpus
    from mx_mcp.dynamic.frida.session import Session


_LOG = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================


class MetricDirection(str, Enum):
    """Which direction of the metric is "better" — used by diff logic.

    ``higher_better`` — entropy, handler diversity, decompiler noise.
    ``lower_better`` — d810 recovery rate, msynth simplification rate,
    symbolic handler-summarization rate.
    ``false_best``  — a boolean where ``False`` is the good outcome
    (pe-sieve dumped successfully = bad).
    """

    HIGHER_BETTER = "higher_better"
    LOWER_BETTER = "lower_better"
    FALSE_BEST = "false_best"


# ============================================================================
# Data models
# ============================================================================


class MetricSample(BaseModel):
    """One value of one metric on one corpus sample.

    ``value is None`` encodes a backend error on this sample (see
    fail-closed principle in ``MCP.md``). ``evidence`` carries free-form
    diagnostic data (counts, offsets, tool output fragments) that the
    agent can inspect when a gate triggers.
    """

    sample_name: str
    value: float | int | bool | None
    evidence: dict[str, Any] = Field(default_factory=dict)


class AggregateStats(BaseModel):
    """Distribution summary over non-``None`` metric values.

    ``p10`` / ``p50`` / ``p90`` use linear-interpolation percentiles.
    ``stddev`` is ``None`` when fewer than two valid samples remain.
    ``n_samples`` counts every input including errors; ``n_errors``
    counts the error-only subset (``value is None``).
    """

    p10: float | None
    p50: float | None
    p90: float | None
    mean: float | None
    stddev: float | None
    n_samples: int
    n_errors: int


class MetricScale(BaseModel):
    """Linear normalisation bounds for visualisation / human scoring.

    Maps ``weak_value`` → ``0.0`` (defence is ineffective for this
    metric) and ``strong_value`` → ``1.0`` (defence is working well).
    Values outside the range clamp to ``[0, 1]``. A zero-span scale
    (weak == strong) returns ``0.5`` as a neutral fallback.

    The same linear formula handles all three directions uniformly —
    callers set the bounds consistently with the metric's direction:

    * ``HIGHER_BETTER`` — ``weak < strong`` (e.g. ``weak=1``,
      ``strong=30`` for microcode-block counts).
    * ``LOWER_BETTER``  — ``weak > strong`` (e.g. ``weak=1.0``,
      ``strong=0.0`` for an MBA-simplification rate).
    * ``FALSE_BEST``    — ``weak=1.0`` (always fails) to
      ``strong=0.0`` (never fails).

    Normalisation is **opt-in per metric**: a benchmark that does not
    declare scales emits ``scale=None`` on its ``MetricResult`` and
    downstream renderers fall back to a raw-value presentation.
    """

    weak_value: float = Field(
        description="Value that maps to 0.0 (weakest defence for this metric)."
    )
    strong_value: float = Field(
        description="Value that maps to 1.0 (strongest defence for this metric)."
    )

    def normalize(self, v: float) -> float:
        """Project ``v`` onto ``[0, 1]`` using the declared bounds.

        Zero-span (``weak == strong``) returns ``0.5`` as a
        well-defined neutral — callers usually treat this as "no
        signal" rather than special-case the branch.

        IEEE-754 signed zero note: when ``v == weak`` and ``span`` is
        negative (LOWER_BETTER direction where ``weak > strong``),
        the raw ratio is ``-0.0``. ``<= 0.0`` clamps that to a plain
        ``0.0`` so downstream ``f"{score:.2f}"`` renders "0.00"
        rather than the distracting "-0.00".
        """
        span = self.strong_value - self.weak_value
        if span == 0:
            return 0.5
        ratio = (v - self.weak_value) / span
        if ratio <= 0.0:
            return 0.0
        if ratio >= 1.0:
            return 1.0
        return ratio


class MetricResult(BaseModel):
    """Full result for one metric emitted by one benchmark.

    ``scale`` is optional. When set, renderers present the metric on a
    normalised ``[0, 1]`` axis via ``scale.normalize``. When ``None``,
    renderers fall back to raw p10/p50/p90 bars (or skip the metric
    entirely, per renderer policy).
    """

    name: str
    direction: MetricDirection
    samples: list[MetricSample]
    aggregate: AggregateStats
    scale: MetricScale | None = None


class BenchmarkResult(BaseModel):
    """Full output of a single benchmark run over the corpus.

    ``errors`` accumulates backend-level failures that affected the
    whole benchmark (not per-sample — those live inside
    ``MetricSample.value is None``).
    """

    benchmark: str
    category: str
    tier: str
    duration_ms: int
    metrics: list[MetricResult]
    errors: list[str] = Field(default_factory=list)


# ============================================================================
# Aggregation helper
# ============================================================================


def _linear_percentile(sorted_values: list[float], p: float) -> float:
    """Linear-interpolation percentile for a sorted list.

    Precondition: ``sorted_values`` is non-empty and already sorted
    ascending. Percentile ``p`` is in ``[0, 100]``.

    Single-value case: returns the value. Matches NumPy's default
    ``linear`` interpolation for multi-value cases.
    """
    if len(sorted_values) == 1:
        return sorted_values[0]
    idx = (p / 100.0) * (len(sorted_values) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = idx - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def aggregate_numeric(
    values: Sequence[float | int | bool | None],
) -> AggregateStats:
    """Compute p10/p50/p90/mean/stddev over a sequence of metric values.

    ``None`` values are treated as errors and excluded from the
    distribution but counted in ``n_errors``. When *every* value is
    ``None`` (or the input is empty) all percentiles are ``None`` and
    ``n_samples == n_errors``.

    Booleans are implicitly cast to ``float`` (``True``→1.0,
    ``False``→0.0) so ``false_best`` metrics surface as a failure rate
    — a property downstream gates can threshold just like any other
    numeric metric.
    """
    values_list = list(values)
    n_total = len(values_list)
    valid = [float(v) for v in values_list if v is not None]
    n_errors = n_total - len(valid)

    if not valid:
        return AggregateStats(
            p10=None, p50=None, p90=None, mean=None, stddev=None,
            n_samples=n_total, n_errors=n_errors,
        )

    sorted_vals = sorted(valid)
    p10 = _linear_percentile(sorted_vals, 10.0)
    p50 = _linear_percentile(sorted_vals, 50.0)
    p90 = _linear_percentile(sorted_vals, 90.0)
    mean = statistics.fmean(valid)
    stddev = statistics.stdev(valid) if len(valid) >= 2 else None

    return AggregateStats(
        p10=p10, p50=p50, p90=p90, mean=mean, stddev=stddev,
        n_samples=n_total, n_errors=n_errors,
    )


# ============================================================================
# ABC
# ============================================================================


class IBenchmark(ABC):
    """Contract for one defense benchmark.

    Subclasses declare class-level metadata and implement ``run`` which
    takes the full corpus (plus a ``Session`` for backends that need
    Frida) and returns a ``BenchmarkResult``.

    Tag-based pre-filtering: if ``corpus_tags`` is non-empty, the
    caller passes only matching corpus entries to ``run``. A benchmark
    that needs the whole corpus (e.g. diffing-resistance) declares an
    empty set.

    Async to match ``ITool.run`` and to allow natural ``await
    asyncio.to_thread(...)`` on blocking subprocess calls.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[str]
    tier: ClassVar[str]
    corpus_tags: ClassVar[frozenset[str]] = frozenset()

    @abstractmethod
    async def run(
        self, corpus: "Corpus", session: "Session"
    ) -> BenchmarkResult:
        """Execute the benchmark. Must return a ``BenchmarkResult``."""


# ============================================================================
# Registry
# ============================================================================


_REGISTRY: list[type[IBenchmark]] = []


def register_benchmark(cls: type[IBenchmark]) -> type[IBenchmark]:
    """Class decorator: register a benchmark at import time.

    Validates the contract (required class attrs, unique name, known
    ``category`` / ``tier``) so misconfigured benchmarks fail fast at
    module load time rather than on first call.
    """
    if not issubclass(cls, IBenchmark):
        raise TypeError(f"{cls.__name__} must subclass IBenchmark")

    for required in ("name", "description", "category", "tier"):
        if not hasattr(cls, required):
            raise TypeError(
                f"{cls.__name__} missing required class attr '{required}'"
            )

    for existing in _REGISTRY:
        if existing.name == cls.name:
            raise ValueError(
                f"benchmark name collision on '{cls.name}': "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )

    _LOG.debug("registered benchmark: %s (%s/%s)", cls.name, cls.category, cls.tier)
    _REGISTRY.append(cls)
    return cls


def all_benchmarks() -> list[type[IBenchmark]]:
    """Return registered benchmark classes in registration order."""
    return list(_REGISTRY)
