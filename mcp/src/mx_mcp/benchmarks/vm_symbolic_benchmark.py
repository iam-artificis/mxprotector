"""VM symbolic benchmark — angr handler-summarization + budget-to-crack.

Covers P6 in the MCP roadmap. Pair with the static :class:`VmStaticBenchmark`
from ``vm_benchmark``: that one measures the shape of the VM section
(density, entropy, coverage); this one measures whether a symbolic
engine can still reason about each handler's behaviour inside a budget.

## Metric model

Two metrics, both per corpus entry:

1. ``vm_handler_summarization_rate`` — ``LOWER_BETTER``, value in
   ``[0, 1]``. ``summarised_count / handlers_attempted``. A high rate
   means angr walked most handlers to completion inside its budget —
   an attacker porting MxProtector to an automated deobfuscator would
   find ``rate·N`` handlers trivially summarisable. Low rate = VM
   resistance.
2. ``vm_symbolic_cost_mean_steps`` — ``HIGHER_BETTER``, non-negative.
   Mean of :attr:`HandlerAnalysisResult.steps` across every attempted
   handler — including budget-exhausted ones, which contribute the
   budget cap. A handler that angr had to give up on after burning
   the full step cap pins this metric high; handlers that terminate
   in a few steps pull it down. Reads as "how much compute per
   handler on average to crack one".

Pre-protected entries are rejected (no sidecar → no handler list).
Entries without any VM handlers in the sidecar contribute no samples
and surface a per-entry error.

## Fail-closed semantics

Three failure shapes are distinguished:

* **Backend missing** — ``import angr`` raised
  :class:`AngrNotAvailableError`. One benchmark-level error is
  emitted and *no* samples are recorded. The measurement is honestly
  unavailable rather than misleadingly "perfect".
* **Per-handler error** — angr crashed on one handler. The handler
  is counted toward the rate denominator AND as "summarised" (so
  the defence score does not inflate on measurement glitches). The
  error is captured in evidence.
* **Zero handlers in sidecar** — entry emits no sample; a per-entry
  error records the reason.

## Budget and sampling

:class:`~mx_mcp.symbolic.angr.budget.SymbolicBudget` caps each handler
at 10 s wall clock / 500 steps / 50 paths (slow-tier defaults). To
keep wall-time bounded on large corpora, the benchmark additionally
samples at most ``max_handlers_per_entry`` handlers per sidecar
(``32`` by default, deterministic slice — first-N in sidecar order
so runs are reproducible).

## Tier

``slow``: one angr project load + up to ``max_handlers_per_entry``
simulations per buildable VM entry. Seed corpus × handlers times
budget cap puts the worst-case run well under the slow-tier ceiling.
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
from mx_mcp.common.sidecar import Sidecar, load_sidecar
from mx_mcp.symbolic.angr import (
    AngrNotAvailableError,
    HandlerAnalysisResult,
    SymbolicBudget,
    analyse_handler,
)


_LOG = logging.getLogger(__name__)


# Metric declarations. Calibrated against slow-tier defaults; retune
# once real angr runs give us per-corpus distributions.
#
# * ``vm_handler_summarization_rate`` — LOWER_BETTER. weak=0.9
#   (attacker cracks ≥90 % of handlers → defence effectively broken)
#   / strong=0.10 (≤10 % summarised → resistant). Mid-range baseline
#   gives the chart headroom in either direction.
# * ``vm_symbolic_cost_mean_steps`` — HIGHER_BETTER. weak=25 (mean
#   cost under 25 angr steps → trivial) / strong=400 (close to the
#   step cap → handlers routinely exhaust budget). The step cap
#   itself is 500; strong_value is deliberately below to leave room
#   for "most handlers pin the cap" to still read as 1.00.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("vm_handler_summarization_rate",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=0.9, strong_value=0.10)),
    ("vm_symbolic_cost_mean_steps",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=25.0, strong_value=400.0)),
)


DEFAULT_MAX_HANDLERS_PER_ENTRY = 32


@register_benchmark
class VmSymbolicBenchmark(IBenchmark):
    """VM handler-summarization rate + mean symbolic cost."""

    name = "vm_symbolic"
    description = (
        "Run angr symbolic execution on every VM handler listed in the "
        "sidecar (capped per-entry to avoid runaway wall time). "
        "handler_summarization_rate = handlers angr walked to completion "
        "within its per-handler budget. symbolic_cost_mean_steps = "
        "average step count attempted per handler including budget-hit "
        "ones. Slow tier — backend missing self-skips with a benchmark "
        "error."
    )
    category = "vm"
    tier = "slow"
    corpus_tags = frozenset({"vm"})

    def __init__(
        self,
        *,
        budget: SymbolicBudget | None = None,
        max_handlers_per_entry: int = DEFAULT_MAX_HANDLERS_PER_ENTRY,
        # Test-injection seam — production always uses the real runner.
        analyse_fn=analyse_handler,
    ) -> None:
        self._budget = budget or SymbolicBudget()
        self._max_handlers = max_handlers_per_entry
        self._analyse_fn = analyse_fn

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=["no corpus entries tagged 'vm'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="mx_mcp_vm_sym_") as td:
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
                    # Backend is missing — stop iterating so we do not
                    # spend time (re)building every corpus entry only
                    # to bounce off the same import failure per sample.
                    # The single benchmark-level error already captured
                    # the root cause.
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
        """Build → sidecar → per-handler angr → per-metric samples."""
        if entry.is_pre_protected:
            return [
                f"{entry.name}: pre-protected — no sidecar to enumerate "
                f"handlers from"
            ]
        if entry.unprotected_binary is None:
            return [f"{entry.name}: corpus entry has no unprotected source"]

        try:
            pb = await ensure_protected(
                entry,
                output_dir=output_dir,
                builder_path=builder_path,
                # --no-packer so angr sees plaintext handler bytes; the
                # packer section otherwise hides .vm behind RC4.
                extra_args=["--no-packer"],
                workspace_root=workspace_root,
            )
        except (BuilderError, FileNotFoundError) as e:
            return [f"{entry.name}: build failed: {e}"]

        sidecar_or_err = _load_sidecar_or_error(pb.sidecar_path, entry.name)
        if isinstance(sidecar_or_err, str):
            return [sidecar_or_err]
        sidecar: Sidecar = sidecar_or_err

        handlers = list(sidecar.vm.handlers)
        if not handlers:
            return [
                f"{entry.name}: sidecar has no VM handlers — VM pass "
                f"disabled or no MX_VM_BEGIN/END markers"
            ]

        # Deterministic first-N slice. Random sampling would vary the
        # signal across runs and make the corpus/gate pipeline noisy;
        # a stable slice keeps p90 drift bounded to real defence
        # changes.
        sampled = handlers[: self._max_handlers]

        try:
            per_handler = await asyncio.to_thread(
                _analyse_batch,
                pb.protected_binary, sampled, self._budget, self._analyse_fn,
            )
        except AngrNotAvailableError as e:
            return [f"{entry.name}: angr backend unavailable: {e}"]
        except Exception as e:  # noqa: BLE001 — fail-closed
            return [f"{entry.name}: angr batch raised: {type(e).__name__}: {e}"]

        _record_samples(
            entry_name=entry.name,
            sidecar=sidecar,
            sampled_total=len(sampled),
            handler_total=len(handlers),
            results=per_handler,
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


def _analyse_batch(
    binary_path: Path,
    handlers,
    budget: SymbolicBudget,
    analyse_fn,
) -> list[HandlerAnalysisResult]:
    """Run the analyse_fn over every handler in sequence.

    Sequential on purpose: angr's global solver state + cle's loader
    caches are not safe for parallel execution in-process. The
    benchmark already lives in a ``to_thread`` so the outer event
    loop is unblocked.
    """
    out: list[HandlerAnalysisResult] = []
    for h in handlers:
        out.append(analyse_fn(binary_path, h.rva, h.size, budget))
    return out


def _record_samples(
    *,
    entry_name: str,
    sidecar: Sidecar,
    sampled_total: int,
    handler_total: int,
    results: list[HandlerAnalysisResult],
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    """Translate per-handler :class:`HandlerAnalysisResult`s into metric samples.

    Rate counts ``summarised=True`` as numerator and the sampled total
    as denominator. Per-handler angr crashes (``termination_reason ==
    'errored'``) are counted as summarised so a measurement glitch
    cannot accidentally inflate the defence score.

    Mean cost averages :attr:`HandlerAnalysisResult.steps` across every
    sampled handler — budget-hit ones contribute the cap they tripped
    on, so the metric biases upward for resistant handlers.
    """
    if sampled_total == 0:
        return

    summarised_effective = sum(
        1 for r in results if r.summarised or r.termination_reason == "errored"
    )
    summarised_real = sum(1 for r in results if r.summarised)
    errored = sum(1 for r in results if r.termination_reason == "errored")
    budget_hit_by_reason: dict[str, int] = {}
    for r in results:
        if r.termination_reason.startswith("budget_"):
            budget_hit_by_reason[r.termination_reason] = (
                budget_hit_by_reason.get(r.termination_reason, 0) + 1
            )

    rate = summarised_effective / float(sampled_total)
    mean_steps = (
        sum(r.steps for r in results) / float(sampled_total)
        if sampled_total else 0.0
    )
    mean_wall_ms = (
        sum(r.wall_ms for r in results) / float(sampled_total)
        if sampled_total else 0.0
    )

    evidence = {
        "handler_total":             handler_total,
        "handlers_sampled":          sampled_total,
        "handlers_truncated":        handler_total > sampled_total,
        "summarised":                summarised_real,
        "summarised_effective":      summarised_effective,
        "errored":                   errored,
        "budget_hits_by_reason":     budget_hit_by_reason,
        "mean_steps":                round(mean_steps, 2),
        "mean_wall_ms":              round(mean_wall_ms, 2),
        "dispatcher_rva":            sidecar.vm.dispatcher_rva,
        "handler_table_rva":         sidecar.vm.handler_table_rva,
    }

    _LOG.info(
        "%s: vm_symbolic — sampled=%d/%d summarised=%d errored=%d "
        "rate=%.3f mean_steps=%.1f",
        entry_name, sampled_total, handler_total,
        summarised_real, errored, rate, mean_steps,
    )

    samples_by_metric["vm_handler_summarization_rate"].append(MetricSample(
        sample_name=entry_name, value=rate, evidence=evidence,
    ))
    samples_by_metric["vm_symbolic_cost_mean_steps"].append(MetricSample(
        sample_name=entry_name, value=mean_steps, evidence=evidence,
    ))


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    if sidecar_path is None:
        return (
            f"{entry_name}: build produced no sidecar (trace-hints off?) "
            f"— benchmark cannot enumerate VM handlers"
        )
    try:
        return load_sidecar(sidecar_path)
    except Exception as e:  # noqa: BLE001 — fail-closed: one entry
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"
