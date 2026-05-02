"""VM handler replay benchmark — Unicorn-driven per-handler instruction count.

Sister of :mod:`.vm_symbolic_benchmark` (angr) and
:mod:`.vm_mba_benchmark` (msynth/pattern). Where those measure
"can a symbolic / algebraic engine collapse the handler?", this one
measures "how much native machine work hides inside one handler under
emulation".

## Metric

``vm_handler_unicorn_mean_instructions`` — ``HIGHER_BETTER``.
Mean instruction count across the sampled handlers. Larger numbers
mean handlers run more native instructions before tail-dispatching;
the protector pushes the metric up via opaque predicates,
substitutions, and MBA inside handler bodies.

## Why one metric, not two

We deliberately do *not* surface a "fraction completed" metric:
under MxProtector's inline tail dispatch, *every* handler reaches
``left_handler`` reliably, so a completion-rate row would be
constant 1.0 across the corpus and add noise to the chart without
discriminating. The instruction-count distribution on its own
captures the protection signal.

## Tier

``slow`` — one Unicorn project per entry × ``max_handlers_per_entry``
replays. Per-handler wall is bounded by the budget; overall ceiling
fits the 30 min slow-tier budget at any reasonable corpus size.

## Fail-closed

* Backend missing → one benchmark-level error, no samples, loop
  aborts.
* Per-handler crash (Unicorn raised) → contributes the partial
  instruction count to the mean — fail-closed: a measurement glitch
  cannot inflate the defence score.
* Empty sidecar → per-entry error, no sample.
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
from mx_mcp.emulation.unicorn import (
    EmulationBudget,
    HandlerReplayResult,
    UnicornNotAvailableError,
    run_handler_replay,
)


_LOG = logging.getLogger(__name__)


# Slow-tier defaults — the per-handler budget is small (handlers are
# tens of instructions each), the per-entry sample cap keeps total
# wall bounded.
DEFAULT_REPLAY_BUDGET = EmulationBudget(
    max_wall_clock_s=2.0,
    max_instructions=4096,
    max_instructions_per_block=4096,
)
DEFAULT_MAX_HANDLERS_PER_ENTRY = 16


# Scale anchors calibrated to seed-corpus handler shapes (~40-150 inst
# per handler at strong level). weak=10 (handler runs in <10 native
# instructions → trivial) / strong=200 (handler is meaningfully heavy).
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("vm_handler_unicorn_mean_instructions",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=10.0, strong_value=200.0)),
)


@register_benchmark
class VmHandlerReplayBenchmark(IBenchmark):
    """Per-handler Unicorn replay — instruction count per handler."""

    name = "vm_handler_replay"
    description = (
        "For every sidecar-declared VM handler, drop it into a "
        "minimal Unicorn sandbox and count instructions executed "
        "before the handler tail-dispatches out of its declared "
        "range or trips the budget. Mean per-corpus-entry is the "
        "metric (HIGHER_BETTER). Slow tier — backend missing "
        "self-skips with a benchmark error."
    )
    category = "vm"
    tier = "slow"
    corpus_tags = frozenset({"vm"})

    def __init__(
        self,
        *,
        budget: EmulationBudget | None = None,
        max_handlers_per_entry: int = DEFAULT_MAX_HANDLERS_PER_ENTRY,
        # Test-injection seam.
        replay_fn=run_handler_replay,
    ) -> None:
        self._budget = budget or DEFAULT_REPLAY_BUDGET
        self._max_handlers = max_handlers_per_entry
        self._replay_fn = replay_fn

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

        with tempfile.TemporaryDirectory(prefix="mx_mcp_uc_replay_") as td:
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
                if any("unicorn backend" in e for e in entry_errors):
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

    async def _process_entry(
        self,
        *,
        entry: CorpusEntry,
        output_dir: Path,
        builder_path: Path,
        workspace_root: Path,
        samples_by_metric: dict[str, list[MetricSample]],
    ) -> list[str]:
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
                # --no-packer so handler bytes are plaintext on disk —
                # without this, Unicorn would emulate ciphertext until
                # the (un-runnable) packer stub decrypted it.
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

        sampled = handlers[: self._max_handlers]

        try:
            results = await asyncio.to_thread(
                _replay_batch,
                pb.protected_binary, sampled, self._budget, self._replay_fn,
            )
        except UnicornNotAvailableError as e:
            return [f"{entry.name}: unicorn backend unavailable: {e}"]
        except Exception as e:  # noqa: BLE001 — fail-closed
            return [
                f"{entry.name}: unicorn replay batch raised: "
                f"{type(e).__name__}: {e}"
            ]

        _record_samples(
            entry_name=entry.name, sidecar=sidecar,
            sampled_total=len(sampled), handler_total=len(handlers),
            results=results, samples_by_metric=samples_by_metric,
        )
        return []


# ============================================================================
# Private helpers
# ============================================================================


def _empty_metric(
    name: str, direction: MetricDirection, scale: MetricScale,
) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=[],
        aggregate=aggregate_numeric([]), scale=scale,
    )


def _build_metric(
    name: str, direction: MetricDirection, scale: MetricScale,
    samples: list[MetricSample],
) -> MetricResult:
    return MetricResult(
        name=name, direction=direction, samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
        scale=scale,
    )


def _replay_batch(
    binary_path: Path,
    handlers,
    budget: EmulationBudget,
    replay_fn,
) -> list[HandlerReplayResult]:
    """Run the replay over every handler in sequence.

    Sequential because each replay creates its own Unicorn instance
    and concurrent handles risk colliding on the global engine state.
    """
    out: list[HandlerReplayResult] = []
    for h in handlers:
        out.append(replay_fn(binary_path, h.rva, h.size, budget))
    return out


def _record_samples(
    *,
    entry_name: str,
    sidecar: Sidecar,
    sampled_total: int,
    handler_total: int,
    results: list[HandlerReplayResult],
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    if sampled_total == 0:
        return

    instr_counts = [r.instructions_executed for r in results]
    completed = sum(1 for r in results if r.completed)
    crashed = sum(1 for r in results if r.error is not None)
    mean_instr = sum(instr_counts) / float(len(instr_counts))
    reasons: dict[str, int] = {}
    for r in results:
        reasons[r.termination_reason] = reasons.get(r.termination_reason, 0) + 1

    evidence = {
        "handler_total":      handler_total,
        "handlers_sampled":   sampled_total,
        "handlers_truncated": handler_total > sampled_total,
        "completed":          completed,
        "crashed":            crashed,
        "termination_breakdown": reasons,
        "mean_instructions":  round(mean_instr, 2),
        "dispatcher_rva":     sidecar.vm.dispatcher_rva,
    }

    _LOG.info(
        "%s: vm_handler_replay — sampled=%d/%d completed=%d crashed=%d mean_instr=%.1f",
        entry_name, sampled_total, handler_total,
        completed, crashed, mean_instr,
    )

    samples_by_metric["vm_handler_unicorn_mean_instructions"].append(MetricSample(
        sample_name=entry_name, value=round(mean_instr, 2), evidence=evidence,
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
    except Exception as e:  # noqa: BLE001 — fail-closed
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"
