"""VM MBA benchmark — extractor + simplifier ensemble over handlers.

Pair with ``vm_static`` (section-level entropy / footprint) and
``vm_symbolic`` (angr handler summarisation). Where those measure
"how big is the VM" and "can angr walk a handler", this one measures
"how messy is the symbolic expression a handler computes, and can a
stock MBA simplifier collapse it back to something simple?"

## Pipeline per corpus entry

1. Build a protected PE + sidecar (``--no-packer`` so handler bytes
   are plaintext on disk).
2. For the first ``max_handlers_per_entry`` handlers in the sidecar:
   a. Extract the output-register symbolic expression via
      :func:`~mx_mcp.deobfuscation.mba.extract_handler_expression`.
   b. For every registered simplifier backend, attempt a
      simplification and record the ratio.
3. Aggregate per-entry metrics:

   * ``vm_mba_expression_mean_ast_nodes`` — HIGHER_BETTER. Mean pre-
     simplification AST node count across sampled handlers. Proxy
     for "how much work an attacker sees per handler".
   * ``vm_mba_{backend}_simplification_rate`` — LOWER_BETTER, one per
     backend that completed successfully on this entry. Fraction of
     handlers where the backend trimmed the AST below the 50 %
     significance threshold.

## Backend self-skip

If a backend raises :class:`BackendUnavailableError` on its first
handler, the benchmark drops it for the whole run and emits a single
error note. Benchmarks-per-backend are computed *per entry*; a backend
that works on entry A but fails on entry B emits a per-entry error
and skips the sample for B only.

## Fail-closed

* Extractor error on one handler → the handler contributes
  ``None`` to the AST-size metric and is excluded from every
  backend's simplification-rate denominator. The root error is
  recorded in evidence.
* Build / sidecar / handler-enumeration errors → per-entry error
  note, no samples from that entry.
* angr backend missing → single benchmark-level error, no samples,
  no further builds.

## Tier

``slow`` — one angr project load per entry + per-handler extraction.
Comparable to vm_symbolic in wall time for the seed corpus.
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
from mx_mcp.deobfuscation.mba import (
    BackendUnavailableError,
    ClaripySimplifier,
    ExpressionBudget,
    ExtractorUnavailableError,
    IMbaSimplifier,
    MbaExpression,
    SimplificationResult,
    extract_handler_expression,
)


_LOG = logging.getLogger(__name__)


# Shared metric: expression AST-node count (always measured).
#
# Scale anchors calibrated against the seed corpus at strong level.
# The pure_vm / mixed handlers produce output ASTs in the ~20-200
# node range; large values hint at heavy symbolic propagation through
# the handler body, small values at trivial expressions an attacker
# sees instantly. weak=1 (handler output is a lone symbol → trivial)
# / strong=80 (handler output is meaningfully convoluted) gives the
# current baseline mid-range headroom. Retune as the corpus grows.
_AST_NODES_METRIC = (
    "vm_mba_expression_mean_ast_nodes",
    MetricDirection.HIGHER_BETTER,
    MetricScale(weak_value=1.0, strong_value=80.0),
)


# Per-backend simplification-rate metric template. One row per
# backend gets emitted in ``metrics`` at run time; the scale is
# shared (weak=0.9 = "most handlers simplify cleanly" → weak defence,
# strong=0.1 = "few simplify" → strong).
_RATE_SCALE = MetricScale(weak_value=0.9, strong_value=0.1)


DEFAULT_MAX_HANDLERS_PER_ENTRY = 24


@register_benchmark
class VmMbaBenchmark(IBenchmark):
    """Handler output-expression complexity + simplifier simplification rates."""

    name = "vm_mba"
    description = (
        "For every sidecar-declared VM handler, extract the output-register "
        "symbolic expression via angr and feed it through each registered "
        "MBA simplifier backend. Metrics: mean pre-simplification AST node "
        "count (HIGHER_BETTER) + per-backend simplification rate "
        "(LOWER_BETTER = defence). Optional backends self-skip when their "
        "library is missing."
    )
    category = "vm"
    tier = "slow"
    corpus_tags = frozenset({"vm"})

    def __init__(
        self,
        *,
        extractor_budget: ExpressionBudget | None = None,
        simplifiers: list[IMbaSimplifier] | None = None,
        max_handlers_per_entry: int = DEFAULT_MAX_HANDLERS_PER_ENTRY,
        # Test-injection seams.
        extract_fn=extract_handler_expression,
    ) -> None:
        self._budget = extractor_budget or ExpressionBudget()
        # Default simplifier line-up: claripy (always-on baseline).
        # msynth is registered as a second backend but self-skips
        # today; once the claripy→miasm conversion lands it will
        # light up automatically. Future SiMBA wrapper appends here.
        self._simplifiers: list[IMbaSimplifier] = (
            simplifiers if simplifiers is not None
            else [ClaripySimplifier()]
        )
        self._max_handlers = max_handlers_per_entry
        self._extract_fn = extract_fn

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name, category=self.category, tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[_empty_ast_metric()]
                        + [_empty_rate_metric(s.name) for s in self._simplifiers],
                errors=["no corpus entries tagged 'vm'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        ast_samples: list[MetricSample] = []
        rate_samples_by_backend: dict[str, list[MetricSample]] = {
            s.name: [] for s in self._simplifiers
        }
        errors: list[str] = []
        # Backends that raised BackendUnavailableError — dropped for
        # the rest of the run to avoid re-raising per handler.
        dead_backends: set[str] = set()

        with tempfile.TemporaryDirectory(prefix="mx_mcp_vm_mba_") as td:
            td_path = Path(td)
            for entry in entries:
                entry_errors = await self._process_entry(
                    entry=entry,
                    output_dir=td_path,
                    builder_path=builder_path,
                    workspace_root=session.workspace_root,
                    ast_samples=ast_samples,
                    rate_samples_by_backend=rate_samples_by_backend,
                    dead_backends=dead_backends,
                )
                errors.extend(entry_errors)
                if any("extractor unavailable" in e for e in entry_errors):
                    # angr (or the extractor kill-switch) is off —
                    # subsequent entries will fail the same way.
                    break

        metrics: list[MetricResult] = [
            MetricResult(
                name=_AST_NODES_METRIC[0],
                direction=_AST_NODES_METRIC[1],
                samples=ast_samples,
                aggregate=aggregate_numeric([s.value for s in ast_samples]),
                scale=_AST_NODES_METRIC[2],
            ),
        ]
        for simplifier in self._simplifiers:
            metric_name = _rate_metric_name(simplifier.name)
            samples = rate_samples_by_backend[simplifier.name]
            metrics.append(MetricResult(
                name=metric_name,
                direction=MetricDirection.LOWER_BETTER,
                samples=samples,
                aggregate=aggregate_numeric([s.value for s in samples]),
                scale=_RATE_SCALE,
            ))

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
        ast_samples: list[MetricSample],
        rate_samples_by_backend: dict[str, list[MetricSample]],
        dead_backends: set[str],
    ) -> list[str]:
        """Build → sidecar → per-handler extract+simplify → record."""
        if entry.is_pre_protected:
            return [
                f"{entry.name}: pre-protected — no sidecar to enumerate handlers"
            ]
        if entry.unprotected_binary is None:
            return [f"{entry.name}: corpus entry has no unprotected source"]

        try:
            pb = await ensure_protected(
                entry,
                output_dir=output_dir,
                builder_path=builder_path,
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
            batch = await asyncio.to_thread(
                _analyse_batch,
                pb.protected_binary, sampled, self._budget,
                self._extract_fn,
                [s for s in self._simplifiers if s.name not in dead_backends],
            )
        except ExtractorUnavailableError as e:
            return [f"{entry.name}: extractor unavailable: {e}"]
        except Exception as e:  # noqa: BLE001 — fail-closed
            return [f"{entry.name}: MBA batch raised: {type(e).__name__}: {e}"]

        entry_errors = _record_samples(
            entry=entry,
            sidecar=sidecar,
            sampled_total=len(sampled),
            handler_total=len(handlers),
            batch=batch,
            simplifiers=self._simplifiers,
            dead_backends=dead_backends,
            ast_samples=ast_samples,
            rate_samples_by_backend=rate_samples_by_backend,
        )
        return entry_errors


# ============================================================================
# Batch aggregate type
# ============================================================================


class _HandlerBatchRow:
    """Mutable per-handler record built during the batch loop."""

    __slots__ = ("expression", "simplifications", "extract_error")

    def __init__(self) -> None:
        self.expression: MbaExpression | None = None
        self.simplifications: dict[str, SimplificationResult] = {}
        self.extract_error: str | None = None


# ============================================================================
# Private — analysis batch
# ============================================================================


def _analyse_batch(
    binary_path: Path,
    handlers,
    budget: ExpressionBudget,
    extract_fn,
    simplifiers: list[IMbaSimplifier],
) -> tuple[list[_HandlerBatchRow], dict[str, str]]:
    """Run extract + every active simplifier over every handler.

    Returns ``(rows, dead_backend_reasons)``. Each row carries the
    extractor's expression (or an error), and per-backend simplification
    results for backends that did not raise :class:`BackendUnavailableError`.

    A backend that raises :class:`BackendUnavailableError` on its
    first handler is declared dead for the batch: its name lands in
    ``dead_backend_reasons`` with the exception message, and
    subsequent handlers skip it.
    """
    rows: list[_HandlerBatchRow] = []
    dead_reasons: dict[str, str] = {}

    for h in handlers:
        row = _HandlerBatchRow()
        try:
            row.expression = extract_fn(
                binary_path, h.rva, h.size, h.opcode, budget=budget,
            )
        except ExtractorUnavailableError:
            raise
        except Exception as e:  # noqa: BLE001 — fail-closed per handler
            row.extract_error = f"{type(e).__name__}: {e}"
            rows.append(row)
            continue

        for s in simplifiers:
            if s.name in dead_reasons:
                continue
            try:
                row.simplifications[s.name] = s.simplify(row.expression)
            except BackendUnavailableError as e:
                dead_reasons[s.name] = str(e)

        rows.append(row)

    return rows, dead_reasons


# ============================================================================
# Sample emission
# ============================================================================


def _record_samples(
    *,
    entry: CorpusEntry,
    sidecar: Sidecar,
    sampled_total: int,
    handler_total: int,
    batch,
    simplifiers: list[IMbaSimplifier],
    dead_backends: set[str],
    ast_samples: list[MetricSample],
    rate_samples_by_backend: dict[str, list[MetricSample]],
) -> list[str]:
    """Translate batch rows into benchmark samples.

    Emits:
        * one AST-node-mean sample (``None`` if every handler's
          extractor errored);
        * one simplification-rate sample per simplifier that survived
          the batch.

    Returns a list of entry-scoped error strings (handler-level
    extractor errors + newly-declared-dead backends for this entry).
    """
    rows, newly_dead = batch
    errors: list[str] = []

    for backend_name, reason in newly_dead.items():
        if backend_name not in dead_backends:
            dead_backends.add(backend_name)
            errors.append(
                f"{entry.name}: simplifier '{backend_name}' unavailable "
                f"— dropping from rest of run: {reason}"
            )

    ast_counts: list[int] = []
    extractor_errors = 0
    saturated = 0
    for row in rows:
        if row.expression is None:
            extractor_errors += 1
            continue
        ast_counts.append(row.expression.ast_nodes)
        if row.expression.saturated:
            saturated += 1

    evidence_common = {
        "handler_total":          handler_total,
        "handlers_sampled":       sampled_total,
        "handlers_truncated":     handler_total > sampled_total,
        "extractor_errors":       extractor_errors,
        "saturated_expressions":  saturated,
        "dispatcher_rva":         sidecar.vm.dispatcher_rva,
    }

    if ast_counts:
        mean_ast = sum(ast_counts) / len(ast_counts)
        _LOG.info(
            "%s: vm_mba — sampled=%d/%d extractor_err=%d ast_mean=%.1f",
            entry.name, sampled_total, handler_total,
            extractor_errors, mean_ast,
        )
        ast_samples.append(MetricSample(
            sample_name=entry.name,
            value=round(mean_ast, 2),
            evidence=evidence_common,
        ))
    else:
        ast_samples.append(MetricSample(
            sample_name=entry.name, value=None,
            evidence={**evidence_common,
                      "note": "every handler hit an extractor error"},
        ))
        return errors

    # Per-simplifier rate. A backend that didn't run on any handler
    # for this entry (e.g. declared dead on the first one) yields a
    # ``None`` sample so the aggregator's ``n_errors`` counts it.
    for simplifier in simplifiers:
        backend_name = simplifier.name
        results = [
            row.simplifications[backend_name]
            for row in rows
            if row.expression is not None
            and backend_name in row.simplifications
        ]
        if not results:
            rate_samples_by_backend[backend_name].append(MetricSample(
                sample_name=entry.name, value=None,
                evidence={**evidence_common,
                          "note": f"{backend_name} produced no results"},
            ))
            continue
        simplified = sum(1 for r in results if r.simplified)
        errored = sum(1 for r in results if r.error is not None)
        mean_ratio = sum(r.node_ratio for r in results) / len(results)
        rate = simplified / float(len(results))
        rate_samples_by_backend[backend_name].append(MetricSample(
            sample_name=entry.name,
            value=rate,
            evidence={
                **evidence_common,
                "backend":           backend_name,
                "evaluated":         len(results),
                "simplified":        simplified,
                "backend_errors":    errored,
                "mean_node_ratio":   round(mean_ratio, 4),
            },
        ))

    return errors


# ============================================================================
# Helpers
# ============================================================================


def _rate_metric_name(backend_name: str) -> str:
    return f"vm_mba_{backend_name}_simplification_rate"


def _empty_ast_metric() -> MetricResult:
    return MetricResult(
        name=_AST_NODES_METRIC[0], direction=_AST_NODES_METRIC[1],
        samples=[], aggregate=aggregate_numeric([]),
        scale=_AST_NODES_METRIC[2],
    )


def _empty_rate_metric(backend_name: str) -> MetricResult:
    return MetricResult(
        name=_rate_metric_name(backend_name),
        direction=MetricDirection.LOWER_BETTER,
        samples=[], aggregate=aggregate_numeric([]),
        scale=_RATE_SCALE,
    )


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
