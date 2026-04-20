"""CFF microcode benchmark — first real benchmark using the IDA backend.

## Method

For every CFF-tagged corpus entry:

1. Build a protected version using the current ``mxprotector_builder``.
2. Run IDA (headless) with the ``cff_metrics`` IDAPython script.
3. Parse the per-function metrics the script emits.
4. Emit one ``MetricSample`` per *function* (not per entry), keyed by
   ``{entry}::{fn_name}``.

Per-function aggregation is deliberate: per-MCP.md the gate is p90
across *functions* so that a single broken hot function cannot hide
behind the per-binary mean.

## Metrics

All four are ``higher_better`` — a stronger CFF pass inflates every
count:

* ``mc_blocks``          — microcode basic-block count.
* ``mc_gotos``           — m_goto / m_ijmp tail count (CFF dispatcher
                           signature).
* ``mc_cyclomatic``      — ``E - N + 2`` on the microcode CFG.
* ``mc_backedge_ratio``  — heuristic back-edge fraction.

See ``static/ida/scripts/cff_metrics.py`` for the exact extraction.

## Failure modes

Fail-closed: build failures, IDA launch failures, and Hex-Rays
unavailable all appear in ``BenchmarkResult.errors`` with one line
per affected entry. Samples from successful entries still aggregate
so the benchmark reports something useful even in a partial run.
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from pathlib import Path

import mx_mcp.static.ida as _ida_pkg
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
from mx_mcp.common.sidecar import Sidecar, load_sidecar
from mx_mcp.static.ida.runner import (
    IdaNotFoundError,
    run_ida_script,
)


_LOG = logging.getLogger(__name__)


# Path to the IDAPython companion script. Resolved relative to the
# ``static.ida`` package so the benchmark can move between
# ``benchmarks/`` subfolders without touching this constant.
SCRIPT_PATH = (
    Path(_ida_pkg.__file__).parent / "scripts" / "cff_metrics.py"
)


# Metric declarations: (name, direction, scale).
#
# Scales anchor a *whole-section* metric. The benchmark measures the
# entire cff section's microcode per corpus entry — dispatcher(s) +
# state handlers + MBA-transition blocks all land in one ``mba_t``.
# The numbers below therefore reflect aggregate counts across the
# section, not per-function values.
#
# Calibration targets score ≈ 0.5 at the current ``strong`` defence
# level on the seed corpus (measured: 92.8 mc_blocks /
# 43 mc_gotos / 42.9 mc_cyclomatic / 0.29 mc_backedge_ratio).
# Keeping scores mid-scale leaves room to flag both improvements and
# regressions — a saturated 1.0 hides gains; an anchored 0.0 hides
# losses.
#
# ``strong`` end rationale per metric:
#
# * ``mc_blocks``         — 200 blocks = dense dispatcher array with
#                            many flattened states + MBA transitions;
#                            saturates an attacker's CFG visualiser.
# * ``mc_gotos``          — 90 = tight goto-mesh, every original
#                            branch re-encoded as a dispatcher jump.
# * ``mc_cyclomatic``     — 90 = a CFG most human analysts abandon
#                            without tool assistance.
# * ``mc_backedge_ratio`` — 0.6 = substantial irreducibility (half the
#                            edges point backwards in quasi-topological
#                            order).
#
# Re-tune when the corpus grows or the CFF pass materially changes.
# The scale is a declarative contract with the reporting layer — no
# runtime code branches on these numbers.
_METRIC_DEFS: tuple[tuple[str, MetricDirection, MetricScale], ...] = (
    ("mc_blocks",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=200.0)),
    ("mc_gotos",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=90.0)),
    ("mc_cyclomatic",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=90.0)),
    ("mc_backedge_ratio",
     MetricDirection.HIGHER_BETTER,
     MetricScale(weak_value=0.0, strong_value=0.6)),
)


@register_benchmark
class CffMicrocodeBenchmark(IBenchmark):
    """HexRays microcode CFF metrics — per-function distribution."""

    name = "cff_microcode"
    description = (
        "HexRays microcode complexity on CFF-tagged corpus entries. "
        "Emits mc_blocks / mc_gotos / mc_cyclomatic / mc_backedge_ratio "
        "as per-function samples aggregated into p10 / p50 / p90."
    )
    category = "cff"
    tier = "fast"
    corpus_tags = frozenset({"cff"})

    async def run(self, corpus, session) -> BenchmarkResult:
        t0 = time.monotonic()

        entries = corpus.with_tags(*self.corpus_tags)
        if not entries:
            return BenchmarkResult(
                benchmark=self.name,
                category=self.category,
                tier=self.tier,
                duration_ms=int((time.monotonic() - t0) * 1000),
                metrics=[
                    _empty_metric(name, direction, scale)
                    for name, direction, scale in _METRIC_DEFS
                ],
                errors=["no corpus entries tagged 'cff'"],
            )

        builder_path = resolve_builder_path(session.workspace_root)

        samples_by_metric: dict[str, list[MetricSample]] = {
            name: [] for name, _, _ in _METRIC_DEFS
        }
        errors: list[str] = []

        # Protected binaries land in a temp dir that disappears at the
        # end of the benchmark — we don't persist them between runs.
        with tempfile.TemporaryDirectory(prefix="mx_mcp_cff_bench_") as td:
            td_path = Path(td)
            for entry in entries:
                entry_errors = await _process_entry(
                    entry=entry,
                    output_dir=td_path,
                    builder_path=builder_path,
                    workspace_root=session.workspace_root,
                    samples_by_metric=samples_by_metric,
                )
                errors.extend(entry_errors)

        metrics = [
            _build_metric(name, direction, scale, samples_by_metric[name])
            for name, direction, scale in _METRIC_DEFS
        ]
        return BenchmarkResult(
            benchmark=self.name,
            category=self.category,
            tier=self.tier,
            duration_ms=int((time.monotonic() - t0) * 1000),
            metrics=metrics,
            errors=errors,
        )


# ============================================================================
# Private helpers
# ============================================================================


def _empty_metric(
    name: str, direction: MetricDirection, scale: MetricScale,
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=[],
        aggregate=aggregate_numeric([]),
        scale=scale,
    )


def _build_metric(
    name: str,
    direction: MetricDirection,
    scale: MetricScale,
    samples: list[MetricSample],
) -> MetricResult:
    return MetricResult(
        name=name,
        direction=direction,
        samples=samples,
        aggregate=aggregate_numeric([s.value for s in samples]),
        scale=scale,
    )


async def _process_entry(
    *,
    entry,
    output_dir: Path,
    builder_path: Path,
    workspace_root: Path,
    samples_by_metric: dict[str, list[MetricSample]],
) -> list[str]:
    """Build + IDA + extract for one corpus entry.

    Returns the list of error strings accumulated for this entry
    (empty on full success). Successful per-function samples are
    appended in place to ``samples_by_metric``.
    """
    errors: list[str] = []

    try:
        pb = await ensure_protected(
            entry,
            output_dir=output_dir,
            builder_path=builder_path,
            # ``--no-packer`` keeps the CFF / VM / string sections
            # as plaintext in the on-disk file. Packed builds encrypt
            # those sections at build time (they're decrypted only at
            # runtime by the stub), so IDA loads encrypted bytes and
            # cannot analyse dispatchers. Benchmarking CFF therefore
            # requires the non-packed variant — packer quality gets
            # its own benchmark in a later phase. Ignored for
            # pre-protected entries (no build).
            extra_args=["--no-packer"],
            workspace_root=workspace_root,
        )
    except (BuilderError, FileNotFoundError) as e:
        return [f"{entry.name}: build failed: {e}"]

    # Sidecar is MANDATORY — the benchmark reads ``sections["cff"]``
    # (range) from it to tell IDA exactly what byte range contains the
    # dispatcher code. A build that did not emit a sidecar has no way
    # to convey that range, so we abort the entry.
    sidecar = _load_sidecar_or_error(pb.sidecar_path, entry.name)
    if isinstance(sidecar, str):
        return [sidecar]

    cff_section = sidecar.sections.get("cff")
    if cff_section is None or cff_section.size == 0:
        return [
            f"{entry.name}: sidecar has no (non-empty) 'cff' section — "
            f"CFF disabled or --no-cfg-flattening in effect"
        ]

    # Hand IDA exactly one region to measure. The script uses
    # ``gen_microcode`` directly on this byte range, bypassing
    # ``ida_funcs.get_func`` — necessary because IDA does not create
    # functions at CFF dispatcher entries (only the .text trampolines
    # are found through the entry-point call-graph, and they are
    # tiny jmp stubs). See ``static/ida/scripts/cff_metrics.py``.
    regions = [{
        "name": "cff_section",
        "rva": cff_section.rva,
        "size": cff_section.size,
    }]

    try:
        ida_result = await run_ida_script(
            binary=pb.protected_binary,
            script=SCRIPT_PATH,
            extra_env={"MX_MCP_IDA_REGIONS": json.dumps(regions)},
        )
    except IdaNotFoundError as e:
        return [f"{entry.name}: IDA missing: {e}"]
    except FileNotFoundError as e:
        return [f"{entry.name}: IDA launch: {e}"]

    if not ida_result.ok or ida_result.output is None:
        return [f"{entry.name}: IDA: {ida_result.error or 'no output'}"]

    ida_out = ida_result.output
    if not ida_out.get("hexrays_available", False):
        return [f"{entry.name}: Hex-Rays not available in IDA"]

    records = ida_out.get("functions", [])

    _LOG.info(
        "%s: cff region [0x%X..0x%X) → %d IDA record(s)",
        entry.name, cff_section.rva, cff_section.rva + cff_section.size,
        len(records),
    )

    if not records:
        errors.append(
            f"{entry.name}: gen_microcode produced no blocks for the "
            f"cff section [0x{cff_section.rva:X}..{cff_section.rva + cff_section.size:X}) "
            f"— bytes may be encrypted (packer on?) or invalid"
        )

    for fn in records:
        fn_name = fn.get("name") or f"region_{fn.get('rva', 0):X}"
        sample_name = f"{entry.name}::{fn_name}"
        evidence_base = {
            "ea": fn.get("ea"),
            "rva": fn.get("rva"),
            "fn_size": fn.get("size"),
            "mba_maturity": fn.get("mba_maturity"),
        }
        for metric_name, _direction, _scale in _METRIC_DEFS:
            samples_by_metric[metric_name].append(MetricSample(
                sample_name=sample_name,
                value=fn.get(metric_name),
                evidence=evidence_base,
            ))

    for err in ida_out.get("errors", []):
        errors.append(f"{entry.name}: ida-region: {err}")

    return errors


def _load_sidecar_or_error(
    sidecar_path: Path | None, entry_name: str,
) -> Sidecar | str:
    """Return the parsed sidecar or an error-string suitable for the
    entry's ``errors`` list.

    Split out as a helper so the main control flow above reads top-
    to-bottom — one successful path, early returns for each failure
    mode.
    """
    if sidecar_path is None:
        return (
            f"{entry_name}: build produced no sidecar (trace-hints off?) "
            f"— benchmark cannot identify the cff section"
        )
    try:
        return load_sidecar(sidecar_path)
    except Exception as e:  # noqa: BLE001 — fail-closed: one entry, not the whole run
        return f"{entry_name}: sidecar load failed: {type(e).__name__}: {e}"


