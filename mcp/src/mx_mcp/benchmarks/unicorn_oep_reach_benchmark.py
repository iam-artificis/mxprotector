"""Unicorn OEP-reach benchmark — fast-tier dynamic-emulation analogue
of the angr ``budget_to_crack`` benchmark.

Loads the protected PE, starts emulation at its visible entry point
(the packer stub) and watches for execution at the unprotected
binary's ``AddressOfEntryPoint``. A defensive packer that depends
on PEB / IAT / ntdll plumbing trips Unicorn long before reaching
OEP — that crash *is* the defence signal.

## Metrics

1. ``unicorn_oep_reached`` — ``FALSE_BEST``. Did Unicorn ever land
   PC at the original OEP?  False = defence held.
2. ``unicorn_instructions_to_oep`` — ``LOWER_BETTER``. Number of
   instructions Unicorn retired before stopping (whatever the
   reason). High values mean the stub tolerated more emulation
   before crashing → less defensive coupling to the OS environment.
   Low values (or zero, on immediate crash) mean the stub bound
   itself tightly to PEB/IAT → strong against trivial Unicorn
   unpacking.

We deliberately do NOT use HIGHER_BETTER for the count: an
attacker armed with a more capable emulator (Qiling, scripted
Unicorn with PEB stubs) would push the count higher, so a build
that lets cheap Unicorn run far is in worse shape against the
*next* tier of attacker.

## Tier

``fast`` — sub-second per entry on the seed corpus (Unicorn crashes
fast), with no symbolic backend warm-up. Pre-protected entries
reject because we need the unprotected source's
``AddressOfEntryPoint`` for ground truth.

## Fail-closed

* Backend missing → one benchmark-level error, no samples, loop
  aborts (mirrors :mod:`.budget_to_crack_benchmark`).
* Per-entry runner crash → entry contributes a sample with
  ``instructions_executed`` from the partial run + ``reached=False``
  so a measurement glitch cannot inflate the defence score.
* Unprotected EP unreadable → per-entry error, no sample.
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
from mx_mcp.emulation.unicorn import (
    EmulationBudget,
    OepReachUnicornResult,
    UnicornNotAvailableError,
    run_oep_reach,
)


_LOG = logging.getLogger(__name__)


# Fast-tier budget: keep the per-entry wall under ~1 s so the whole
# benchmark fits the 5-min fast-tier ceiling on a 10-entry corpus.
DEFAULT_OEP_BUDGET = EmulationBudget(
    max_wall_clock_s=2.0,
    max_instructions=200_000,
    max_instructions_per_block=4096,
)


# Metric scales calibrated on the seed corpus at strong level:
#
# * ``unicorn_oep_reached`` — FALSE_BEST. weak=1.0 / strong=0.0.
# * ``unicorn_instructions_to_oep`` — LOWER_BETTER. weak=200_000
#   (cheap Unicorn ran the entire budget without crashing → packer
#   tolerates emulation → weak) / strong=0 (stub trips on the very
#   first PEB read → strong). The seed corpus pegs near 0 on every
#   entry.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("unicorn_oep_reached",
     MetricDirection.FALSE_BEST,
     MetricScale(weak_value=1.0, strong_value=0.0)),
    ("unicorn_instructions_to_oep",
     MetricDirection.LOWER_BETTER,
     MetricScale(weak_value=200_000.0, strong_value=0.0)),
)


@register_benchmark
class UnicornOepReachBenchmark(IBenchmark):
    """Dynamic-emulation OEP recovery via Unicorn."""

    name = "unicorn_oep_reach"
    description = (
        "Load the protected PE into Unicorn, start emulation at the "
        "visible entry point (packer stub), and watch for execution "
        "at the unprotected source's AddressOfEntryPoint. Two "
        "metrics: oep_reached (FALSE_BEST bool — did the emulator "
        "ever land at OEP?) + instructions_to_oep (LOWER_BETTER — "
        "how many instructions executed before the run ended). Fast "
        "tier — backend missing self-skips with a benchmark error."
    )
    category = "packer"
    tier = "fast"
    corpus_tags = frozenset({"packer", "exe"})

    def __init__(
        self,
        *,
        budget: EmulationBudget | None = None,
        # Test-injection seams.
        run_fn=run_oep_reach,
        read_entry_point_fn=read_entry_point_rva,
    ) -> None:
        self._budget = budget or DEFAULT_OEP_BUDGET
        self._run_fn = run_fn
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

        with tempfile.TemporaryDirectory(prefix="mx_mcp_uc_oep_") as td:
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
                # Packer ON: this benchmark is *about* the full stub.
                workspace_root=workspace_root,
            )
        except (BuilderError, FileNotFoundError) as e:
            return [f"{entry.name}: build failed: {e}"]

        try:
            result = await asyncio.to_thread(
                self._run_fn,
                pb.protected_binary, target_oep_rva, self._budget,
            )
        except UnicornNotAvailableError as e:
            return [f"{entry.name}: unicorn backend unavailable: {e}"]
        except Exception as e:  # noqa: BLE001 — fail-closed
            return [
                f"{entry.name}: unicorn OEP-reach raised: "
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


def _record_samples(
    *,
    entry_name: str,
    target_oep_rva: int,
    result: OepReachUnicornResult,
    budget: EmulationBudget,
    samples_by_metric: dict[str, list[MetricSample]],
) -> None:
    evidence = {
        "target_oep_rva":         target_oep_rva,
        "termination_reason":     result.termination_reason,
        "wall_ms":                result.wall_ms,
        "budget_max_instr":       budget.max_instructions,
        "budget_max_wall_s":      budget.max_wall_clock_s,
        "error":                  result.error,
    }

    _LOG.info(
        "%s: unicorn_oep_reach — reached=%s instr=%d/%d reason=%s wall=%dms",
        entry_name, result.reached, result.instructions_executed,
        budget.max_instructions, result.termination_reason, result.wall_ms,
    )

    samples_by_metric["unicorn_oep_reached"].append(MetricSample(
        sample_name=entry_name, value=result.reached, evidence=evidence,
    ))
    samples_by_metric["unicorn_instructions_to_oep"].append(MetricSample(
        sample_name=entry_name, value=result.instructions_executed,
        evidence=evidence,
    ))
