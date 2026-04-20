"""Baseline store + diff logic for defense metrics.

Baselines are per-repository-state snapshots of the full
``measure_defense`` output. A reviewer captures one before a set of
builder changes (``record_baseline``), then compares the current
state against it (``diff_defense_baseline``) to see what improved,
what regressed, and whether the changes cleared the gate.

## On-disk format

One JSON file per baseline in ``mcp/baselines/data/<name>.json``.
Schema v1; pydantic rejects unknown majors so an older MCP cannot
misread a newer baseline silently.

The files are committed to git deliberately — baselines are historical
facts about the builder at a point in time, reviewable in PR diffs,
and cheaply version-pinned.

## Diff semantics

Per-metric verdict hinges on **direction** and a numeric tolerance:

| Direction        | Improved                    | Regressed                    |
|------------------|-----------------------------|------------------------------|
| ``higher_better``| current.p90 > baseline.p90 * (1 + tol) | current.p90 < baseline.p90 * (1 - tol) |
| ``lower_better`` | current.p90 < baseline.p90 * (1 - tol) | current.p90 > baseline.p90 * (1 + tol) |
| ``false_best``   | current.mean < baseline.mean - tol_abs | current.mean > baseline.mean + tol_abs |

Metrics missing the chosen aggregate on either side are reported as
"skipped" rather than silently "unchanged" — fail-closed at the
comparison level.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    MetricDirection,
)


_LOG = logging.getLogger(__name__)


BASELINE_SCHEMA_VERSION = 1


# ============================================================================
# On-disk model
# ============================================================================


class BaselineDoc(BaseModel):
    """One baseline snapshot."""

    schema_version: int = Field(description="Baseline schema version.")
    name: str = Field(description="Stable identifier; matches the file stem.")
    timestamp: str = Field(description="ISO-8601 UTC when the baseline was captured.")
    git_commit: str | None = Field(
        default=None,
        description="Git HEAD at capture time; None if git was unavailable.",
    )
    builder_level: str = Field(description="Protection level used during capture.")
    builder_args: list[str] = Field(
        default_factory=list,
        description="Extra CLI args passed to mxprotector_builder at capture time.",
    )
    benchmarks: list[BenchmarkResult] = Field(
        default_factory=list,
        description="Raw benchmark results, one entry per registered benchmark.",
    )

    @field_validator("schema_version")
    @classmethod
    def _check_version(cls, v: int) -> int:
        if v != BASELINE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported baseline schema_version={v} "
                f"(this MCP reads v{BASELINE_SCHEMA_VERSION})"
            )
        return v


# ============================================================================
# Store ABC + JSON file store
# ============================================================================


class BaselineNotFoundError(FileNotFoundError):
    """Raised when a baseline with the requested name does not exist."""


class BaselineExistsError(FileExistsError):
    """Raised when saving would overwrite an existing baseline without ``overwrite=True``."""


class IBaselineStore(ABC):
    """Storage contract. A future phase may add a git-native store
    that tags commits; for MVP only ``JsonFileStore`` is needed."""

    @abstractmethod
    def load(self, name: str) -> BaselineDoc:
        """Load baseline ``name`` or raise ``BaselineNotFoundError``."""

    @abstractmethod
    def save(self, doc: BaselineDoc, overwrite: bool = False) -> Path:
        """Persist ``doc``; returns the on-disk path written.

        Raises ``BaselineExistsError`` if the target exists and
        ``overwrite`` is ``False``.
        """

    @abstractmethod
    def list_baselines(self) -> list[str]:
        """Return the sorted list of known baseline names."""


class JsonFileStore(IBaselineStore):
    """Baselines live as one ``<name>.json`` per file under ``root``.

    The root is ``mcp/baselines/data/`` by convention. Names are used
    as file stems; accepted characters are alphanumerics plus ``-``
    and ``_`` — anything else rejects at save time to avoid accidental
    path escapes.
    """

    _NAME_OK: frozenset[str] = frozenset(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-_."
    )

    def __init__(self, root: Path) -> None:
        self._root = root

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _path_for(self, name: str) -> Path:
        self._validate_name(name)
        return self._root / f"{name}.json"

    @classmethod
    def _validate_name(cls, name: str) -> None:
        if not name:
            raise ValueError("baseline name must be non-empty")
        bad = {ch for ch in name if ch not in cls._NAME_OK}
        if bad:
            raise ValueError(
                f"baseline name '{name}' contains disallowed characters: "
                f"{sorted(bad)}"
            )

    # ------------------------------------------------------------------
    # IBaselineStore
    # ------------------------------------------------------------------

    def load(self, name: str) -> BaselineDoc:
        path = self._path_for(name)
        if not path.exists():
            raise BaselineNotFoundError(
                f"baseline '{name}' not found at {path}. "
                f"Known baselines: {self.list_baselines() or '(none)'}"
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        return BaselineDoc.model_validate(data)

    def save(self, doc: BaselineDoc, overwrite: bool = False) -> Path:
        path = self._path_for(doc.name)
        if path.exists() and not overwrite:
            raise BaselineExistsError(
                f"baseline '{doc.name}' already exists at {path}; "
                f"pass overwrite=True to replace"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            doc.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        _LOG.info("saved baseline '%s' → %s", doc.name, path)
        return path

    def list_baselines(self) -> list[str]:
        if not self._root.exists():
            return []
        return sorted(p.stem for p in self._root.glob("*.json"))


# ============================================================================
# Diff logic
# ============================================================================


class DiffVerdict(str, Enum):
    """Per-metric outcome of a baseline comparison."""

    IMPROVED = "improved"
    REGRESSED = "regressed"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"  # insufficient data on one side
    ADDED = "added"      # metric new since baseline
    REMOVED = "removed"  # metric disappeared since baseline


@dataclass(frozen=True, slots=True)
class MetricKey:
    """Unique per-metric identity across a full baseline."""

    benchmark: str
    metric: str


class MetricDiff(BaseModel):
    """Per-metric diff entry.

    ``current_value`` / ``baseline_value`` are the values that drove
    the verdict (p90 for higher/lower-better, mean for false-best);
    ``delta_pct`` is their relative change when both are present.
    """

    benchmark: str
    metric: str
    direction: MetricDirection
    verdict: DiffVerdict
    current_value: float | None
    baseline_value: float | None
    delta_pct: float | None
    note: str = ""


class BaselineDiff(BaseModel):
    """Aggregated diff of a full measurement against a stored baseline."""

    baseline_name: str
    baseline_timestamp: str
    current_timestamp: str
    gate_passed: bool
    improvements: list[MetricDiff] = Field(default_factory=list)
    regressions: list[MetricDiff] = Field(default_factory=list)
    unchanged: list[MetricDiff] = Field(default_factory=list)
    skipped: list[MetricDiff] = Field(default_factory=list)
    added: list[MetricDiff] = Field(default_factory=list)
    removed: list[MetricDiff] = Field(default_factory=list)


def _representative_value(
    aggregate_p90: float | None,
    aggregate_mean: float | None,
    direction: MetricDirection,
) -> float | None:
    """Pick the aggregate field that drives the verdict for a direction.

    * ``false_best`` compares ``mean`` (failure rate).
    * ``higher_better`` / ``lower_better`` compare ``p90`` — stricter
      than mean, guards against hot-function regression masking.
    """
    if direction is MetricDirection.FALSE_BEST:
        return aggregate_mean
    return aggregate_p90


def _classify(
    direction: MetricDirection,
    current: float,
    baseline: float,
    tolerance_pct: float,
) -> tuple[DiffVerdict, float]:
    """Decide verdict + compute relative delta.

    ``tolerance_pct`` is a **relative** band for higher/lower-better
    (5.0 means ±5%) and an **absolute** band for ``false_best``
    (0.05 means ±0.05 in the rate).
    """
    if direction is MetricDirection.FALSE_BEST:
        absolute_delta = current - baseline
        if absolute_delta < -tolerance_pct / 100.0:
            return DiffVerdict.IMPROVED, absolute_delta * 100.0
        if absolute_delta > tolerance_pct / 100.0:
            return DiffVerdict.REGRESSED, absolute_delta * 100.0
        return DiffVerdict.UNCHANGED, absolute_delta * 100.0

    # Numeric (higher_better / lower_better) — relative delta.
    if baseline == 0:
        # Cannot compute a relative delta against a zero baseline.
        # Treat as unchanged iff current is also zero, else report as
        # regressed/improved based on direction alone.
        if current == 0:
            return DiffVerdict.UNCHANGED, 0.0
        sign = 1.0 if current > 0 else -1.0
        relative = float("inf") * sign
    else:
        relative = (current - baseline) / abs(baseline) * 100.0

    threshold = tolerance_pct
    improved_by_sign = 1 if direction is MetricDirection.HIGHER_BETTER else -1

    if relative * improved_by_sign > threshold:
        return DiffVerdict.IMPROVED, relative
    if relative * improved_by_sign < -threshold:
        return DiffVerdict.REGRESSED, relative
    return DiffVerdict.UNCHANGED, relative


def diff_baselines(
    current_benchmarks: list[BenchmarkResult],
    baseline: BaselineDoc,
    tolerance_pct: float = 5.0,
    current_timestamp: str = "",
) -> BaselineDiff:
    """Compute a full baseline diff.

    ``tolerance_pct`` controls both the relative band for numeric
    metrics and the absolute band for ``false_best`` rates (see
    ``_classify``). Callers usually pass the tool-input value unchanged.

    ``gate_passed`` is ``len(regressions) == 0`` in MVP; later phases
    layer per-metric gate thresholds on top of this basic check.
    """
    current_by_key: dict[MetricKey, tuple[str, MetricDirection, float | None]] = {}
    for bench in current_benchmarks:
        for metric in bench.metrics:
            key = MetricKey(bench.benchmark, metric.name)
            rep = _representative_value(
                metric.aggregate.p90, metric.aggregate.mean, metric.direction,
            )
            current_by_key[key] = (bench.benchmark, metric.direction, rep)

    baseline_by_key: dict[MetricKey, tuple[str, MetricDirection, float | None]] = {}
    for bench in baseline.benchmarks:
        for metric in bench.metrics:
            key = MetricKey(bench.benchmark, metric.name)
            rep = _representative_value(
                metric.aggregate.p90, metric.aggregate.mean, metric.direction,
            )
            baseline_by_key[key] = (bench.benchmark, metric.direction, rep)

    improvements: list[MetricDiff] = []
    regressions: list[MetricDiff] = []
    unchanged: list[MetricDiff] = []
    skipped: list[MetricDiff] = []
    added: list[MetricDiff] = []
    removed: list[MetricDiff] = []

    all_keys = set(current_by_key) | set(baseline_by_key)
    for key in sorted(all_keys, key=lambda k: (k.benchmark, k.metric)):
        cur = current_by_key.get(key)
        base = baseline_by_key.get(key)

        if cur is None:
            # metric existed in baseline, missing now
            _, direction, base_value = base  # type: ignore[misc]
            removed.append(MetricDiff(
                benchmark=key.benchmark,
                metric=key.metric,
                direction=direction,
                verdict=DiffVerdict.REMOVED,
                current_value=None,
                baseline_value=base_value,
                delta_pct=None,
                note="metric no longer emitted",
            ))
            continue

        if base is None:
            _, direction, cur_value = cur
            added.append(MetricDiff(
                benchmark=key.benchmark,
                metric=key.metric,
                direction=direction,
                verdict=DiffVerdict.ADDED,
                current_value=cur_value,
                baseline_value=None,
                delta_pct=None,
                note="metric introduced since baseline",
            ))
            continue

        _, direction, cur_value = cur
        _, _, base_value = base

        if cur_value is None or base_value is None:
            skipped.append(MetricDiff(
                benchmark=key.benchmark,
                metric=key.metric,
                direction=direction,
                verdict=DiffVerdict.SKIPPED,
                current_value=cur_value,
                baseline_value=base_value,
                delta_pct=None,
                note="aggregate unavailable on at least one side",
            ))
            continue

        verdict, delta = _classify(direction, cur_value, base_value, tolerance_pct)
        diff_entry = MetricDiff(
            benchmark=key.benchmark,
            metric=key.metric,
            direction=direction,
            verdict=verdict,
            current_value=cur_value,
            baseline_value=base_value,
            delta_pct=delta,
        )
        if verdict is DiffVerdict.IMPROVED:
            improvements.append(diff_entry)
        elif verdict is DiffVerdict.REGRESSED:
            regressions.append(diff_entry)
        else:
            unchanged.append(diff_entry)

    return BaselineDiff(
        baseline_name=baseline.name,
        baseline_timestamp=baseline.timestamp,
        current_timestamp=current_timestamp,
        gate_passed=len(regressions) == 0,
        improvements=improvements,
        regressions=regressions,
        unchanged=unchanged,
        skipped=skipped,
        added=added,
        removed=removed,
    )
