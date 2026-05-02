"""Budget-to-crack benchmark — angr symbolic steps to reach OEP.

P6 second half. Pair with :mod:`.vm_symbolic_benchmark` (handler
summarisation): that benchmark scores per-handler resistance; this
one scores end-to-end stub resistance — the work an attacker would
spend to symbolically follow the packer stub through to the original
entry point.

## Metric model

Two metrics, both per corpus entry:

1. ``budget_to_crack_steps_to_oep`` — ``HIGHER_BETTER``, integer.
   Number of ``simgr.step()`` iterations angr ran before either
   landing on the original entry point or busting a budget cap. A
   reachable build pins this metric low; a build that forces angr
   to exhaust the step / wall / path cap pins it at the cap.
2. ``budget_to_crack_oep_reached`` — ``FALSE_BEST``, bool. True if
   any active state landed at the OEP within budget. Read directly
   from :class:`OepReachResult.reached`. Surfaces the binary
   "did the attacker crack it at all?" question separately from the
   continuous "how much compute" view.

Pre-protected entries are rejected — we need the *unprotected*
binary's ``AddressOfEntryPoint`` to know what address counts as
"reached". Pre-protected legacy entries lack that ground truth.

## Fail-closed semantics

Three failure shapes are distinguished:

* **Backend missing** — ``import angr`` raised
  :class:`AngrNotAvailableError`. One benchmark-level error is
  emitted and *no* samples are recorded. Budget-to-crack is
  honestly unavailable rather than misleadingly "perfect".
* **Per-entry runner crash** — angr crashed on one binary. The
  entry contributes ``steps = budget.max_steps`` and
  ``oep_reached = False`` (fail-closed: a measurement glitch
  cannot make the defence look weak).
* **Unprotected EP unreadable** — ``read_entry_point_rva`` raised
  on the source binary. Per-entry error, no sample emitted.

## Tier

``slow``: at most one angr project load + one bounded simulation
per buildable corpus entry. Budget caps wall clock per entry; the
default 30 s × ~3 buildable seed entries = ~90 s worst case in
practice.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
import time
from pathlib import Path

from mx_mcp.common.benchmark_base import (
    BenchmarkResult,
    IBenchmark,
    MetricDirection,
    MetricResult,
    MetricSample,
    MetricScale,
    aggregate_numeric,
    register_benchmark,
)
from mx_mcp.common.builder import (
    BuilderError,
    ensure_protected,
    resolve_builder_path,
)
from mx_mcp.common.corpus import CorpusEntry
from mx_mcp.common.pe_reader import NotAPeError, read_entry_point_rva
from mx_mcp.symbolic.angr import (
    AngrNotAvailableError,
    OepReachResult,
    SymbolicBudget,
    analyse_oep_reach,
)


_LOG = logging.getLogger(__name__)


# Wider per-entry budget than the per-handler one. The full packer
# stub is heavier than any single VM handler — IAT walk + decryptor
# loop alone consume a few hundred steps before user code runs — so
# we lift the step / wall cap to give angr a fair shot at reaching
# OEP on weak builds (which we want to score low).
DEFAULT_OEP_BUDGET = SymbolicBudget(
    max_wall_clock_s=30.0,
    max_steps=2000,
    max_paths=100,
)


# Metric scales — calibrated against the slow-tier defaults above.
#
# * ``budget_to_crack_steps_to_oep`` — HIGHER_BETTER. weak=50 (angr
#   walked the stub in <50 steps → trivial to symbolically devirt) /
#   strong=1800 (close to the 2000-step cap → defence forces angr to
#   give up). The strong anchor sits below the cap on purpose so a
#   build that pegs the cap still reads as 1.00.
# * ``budget_to_crack_oep_reached`` — FALSE_BEST. weak=1.0 / strong=0.0.
#   A bool surfaced through the standard linear scale: True (1.0) →
#   defence broken, False (0.0) → defence held.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("budget_to_crack_steps_to_oep",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=50.0, strong_value=1800.0)),
    ("budget_to_crack_oep_reached",
     MetricDirection.FALSE_BEST,
     MetricScale(weak_value=1.0, strong_value=0.0)),
)


@register_benchmark
class BudgetToCrackBenchmark(IBenchmark):
    """Symbolic-step count for angr to reach OEP from the packer stub."""

    name = "budget_to_crack_oep"
    description = (
        "Run angr symbolic execution from the protected binary's visible "
        "entry point (the packer stub) and count steps until any active "
        "state's program counter equals the original entry-point RVA "
        "recovered from the unprotected source. steps_to_oep is "
        "HIGHER_BETTER (resistant builds peg the budget cap); "
        "oep_reached is a FALSE_BEST bool (True means angr cracked the "
        "stub within budget). Slow tier — backend missing self-skips "
        "with a benchmark-level error."
    )
    category = "budget_to_crack"
    tier = "slow"
    corpus_tags = frozenset({"packer", "exe"})

    def __init__(
        self,
        *,
        budget: SymbolicBudget | None = None,
        # Test-injection seam — production always uses the real runner.
        analyse_fn=analyse_oep_reach,
        # Test-injection seam — production reads the unprotected PE.
        read_entry_point_fn=read_entry_point_rva,
    ) -> None:
        self._budget = budget or DEFAULT_OEP_BUDGET
        self._analyse_fn = analyse_fn
        self._read_entry_point_fn = read_entry_point_fn

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags, match_all=True)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=["no corpus entries tagged 'packer' + 'exe'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_b2c_") as td:
            td_path = Path(td)
            for entry in entries:
                entry_errors = await self._process_entry(
                    entry=entry,
                    output_dir=td_path,
                    builder_path=builder_path,
                    workspace_root=session.workspace_root,
                    samples_by_metric=samples_by_metric,
                )
                errors.extend(entry_errors)
                if any("angr backend" in e for e in entry_errors):
                    # Backend missing — abort the loop the same way
                    # vm_symbolic_benchmark does: one error, no further
                    # builds.
                    break

        metrics = [
            _build_metric(name, direction, scale, samples_by_metric[name])
            for name, direction, scale in _METRIC_DEFS
        ]
        return BenchmarkResult(
            benchmark=self.name, category=self.category, tier=self.tier,
            duration_ms=int((time.monotonic() - t0) * 1000),
            metrics=metrics, errors=errors,
        )

    # ------------------------------------------------------------------
    # Per-entry flow
    # ------------------------------------------------------------------

    async def _process_entry(
        self,
        *,
        entry: CorpusEntry,
        output_dir: Path,
        builder_path: Path,
        workspace_root: Path,
        samples_by_metric: dict[str, list[MetricSample]],
    ) -> list[str]:
        """Build → recover OEP RVA → angr OEP-reach → samples.

        Pre-protected entries are rejected up-front: we need the
        unprotected source's ``AddressOfEntryPoint`` as ground truth,
        and a legacy ``.exe.packed`` does not carry it.
        """
        if entry.is_pre_protected:
            return [
                f"{entry.name}: pre-protected — original EP RVA unrecoverable"
            ]
        if entry.unprotected_binary is None:
            return [f"{entry.name}: corpus entry has no unprotected source"]

        try:
            target_oep_rva = self._read_entry_point_fn(entry.unprotected_binary)
        except (NotAPeError, OSError, ValueError) as e:
            return [
                f"{entry.name}: cannot read unprotected EP RVA: "
                f"{type(e).__name__}: {e}"
            ]

        try:
            pb = await ensure_protected(
                entry,
                output_dir=output_dir,
                builder_path=builder_path,
                # Keep packer ON: budget-to-crack is precisely about the
                # full-stack stub. Disabling the packer here would
                # measure VM/CFF only and miss the metric's intent.
                workspace_root=workspace_root,
            )
        except (BuilderError, FileNotFoundError) as e:
            return [f"{entry.name}: build failed: {e}"]

        try:
            result = await asyncio.to_thread(
                self._analyse_fn,
                pb.protected_binary, target_oep_rva, self._budget,
            )
        except AngrNotAvailableError as e:
            return [f"{entry.name}: angr backend unavailable: {e}"]
        except Exception as e:  # noqa: BLE001 — fail-closed
            return [
                f"{entry.name}: angr OEP-reach raised: "
                f"{type(e).__name__}: {e}"
            ]

        _record_samples(
            entry_name=entry.name,
            target_oep_rva=target_oep_rva,
            result=result,
            budget=self._budget,
            samples_by_metric=samples_by_metric,
        )
        return []


# ============================================================================
# Private helpers — module level so tests can exercise them directly.
# ============================================================================


def _empty_metric(
    name: str, direction: MetricDirection, scale: MetricScale,
) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=[],
        aggregate=aggregate_numeric([]), scale=scale,
    )


def _build_metric(
    name: str,
    direction: MetricDirection,
    scale: MetricScale,
    samples: list[MetricSample],
) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
        scale=scale,
    )


def _record_samples(
    *,
    entry_name: str,
    target_oep_rva: int,
    result: OepReachResult,
    budget: SymbolicBudget,
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    """Translate one :class:`OepReachResult` into the two metric samples.

    ``steps_to_oep`` reads the result's ``steps`` directly: the runner
    already does the right thing — for ``reached_oep`` it's the step
    at which OEP was first hit; for budget hits / errors it's the
    budget cap (or actual count at exhaustion). HIGHER_BETTER.

    ``oep_reached`` is a bool surfaced through ``aggregate_numeric``'s
    bool-to-float coercion so the standard scale machinery handles it
    without a special-case in the renderer.
    """
    evidence = {
        "target_oep_rva":      target_oep_rva,
        "termination_reason":  result.termination_reason,
        "wall_ms":             result.wall_ms,
        "paths_explored":      result.paths_explored,
        "budget_max_steps":    budget.max_steps,
        "budget_max_wall_s":   budget.max_wall_clock_s,
        "budget_max_paths":    budget.max_paths,
        "error":               result.error,
    }

    _LOG.info(
        "%s: budget_to_crack — reached=%s steps=%d/%d reason=%s wall=%dms",
        entry_name, result.reached, result.steps, budget.max_steps,
        result.termination_reason, result.wall_ms,
    )

    samples_by_metric["budget_to_crack_steps_to_oep"].append(MetricSample(
        sample_name=entry_name, value=result.steps, evidence=evidence,
    ))
    samples_by_metric["budget_to_crack_oep_reached"].append(MetricSample(
        sample_name=entry_name, value=result.reached, evidence=evidence,
    ))
