"""MCP tool: evaluate registered invariants against a protected PE.

Runs the binary under Frida exactly once with the union of probes
required by the selected invariants (empty union = no spawn), then
dispatches the collected event stream + sidecar to every invariant's
``evaluate`` and aggregates verdicts.

Overall status rules:
  fail — at least one invariant returned fail.
  pass — at least one returned pass, none failed.
  skip — every invariant returned skip (nothing applicable).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mx_tracing.events import summarize
from mx_tracing.invariants import (  # noqa: F401  — triggers registration
    base as _invariants_base,
)
from mx_tracing.invariants.base import (
    InvariantContext,
    InvariantVerdict,
    VerdictStatus,
    all_invariants,
)
from mx_tracing.sidecar import load_sidecar, sidecar_path_for
from mx_tracing.tools.base import ITool, register_tool


def _resolve(path_str: str, workspace_root: Path) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (workspace_root / p).resolve()


def _overall(verdicts: list[InvariantVerdict]) -> VerdictStatus:
    statuses = {v.status for v in verdicts}
    if VerdictStatus.FAIL in statuses:
        return VerdictStatus.FAIL
    if VerdictStatus.PASS in statuses:
        return VerdictStatus.PASS
    return VerdictStatus.SKIP


class VerifyInvariantsInput(BaseModel):
    binary_path: str = Field(
        description="Path to the protected PE (requires --trace-hints sidecar)."
    )
    only: list[str] | None = Field(
        None,
        description=(
            "Optional subset of invariant names to run; default: all "
            "registered invariants."
        ),
    )
    timeout_s: float = Field(
        30.0, description="Max seconds to wait for the traced process to exit."
    )
    run_args: list[str] = Field(
        default_factory=list,
        description="Command-line args for the protected PE.",
    )


class InvariantResult(BaseModel):
    name: str
    status: str  # "pass" | "fail" | "skip"
    message: str
    evidence: dict[str, Any]


class VerifyInvariantsOutput(BaseModel):
    binary_path: str
    sidecar_path: str
    overall_status: str
    invariants: list[InvariantResult]
    ran_under_frida: bool
    enabled_probes: list[str]
    timed_out: bool | None
    duration_ms: int | None
    event_count: int | None
    events_summary: dict[str, int] | None


@register_tool
class VerifyProtectionInvariantsTool(
    ITool[VerifyInvariantsInput, VerifyInvariantsOutput]
):
    name = "verify_protection_invariants"
    description = (
        "Run each registered protection invariant against a protected PE "
        "(built with --trace-hints). Spawns the binary under Frida once "
        "with the union of probes required by selected invariants and "
        "returns per-invariant verdicts + an aggregate status."
    )
    input_schema = VerifyInvariantsInput
    output_schema = VerifyInvariantsOutput

    async def run(
        self, args: VerifyInvariantsInput, session
    ) -> VerifyInvariantsOutput:
        binary = _resolve(args.binary_path, session.workspace_root)
        sidecar = sidecar_path_for(binary)
        doc = load_sidecar(sidecar)

        selected = [
            cls for cls in all_invariants()
            if args.only is None or cls.name in args.only
        ]
        if args.only is not None:
            known = {cls.name for cls in all_invariants()}
            unknown = sorted(set(args.only) - known)
            if unknown:
                raise ValueError(
                    f"unknown invariant(s): {unknown}; "
                    f"registered: {sorted(known)}"
                )

        union_probes = sorted({p for cls in selected for p in cls.probes})

        events = []
        timed_out: bool | None = None
        duration_ms: int | None = None

        if union_probes:
            mem_ranges = [
                {"role": role, "rva": s.rva, "size": s.size}
                for role, s in doc.sections.items()
                if role in ("packer", "strings", "guard", "vm", "cff")
            ]
            result = await session.run_probed(
                binary=binary,
                enabled_probes=union_probes,
                config_extras={"mem_ranges": mem_ranges},
                args=args.run_args,
                timeout_s=args.timeout_s,
            )
            events = result.events
            timed_out = result.timed_out
            duration_ms = result.duration_ms

        verdicts: list[InvariantVerdict] = []
        for cls in selected:
            ctx = InvariantContext(
                events=events, sidecar=doc, binary_path=binary
            )
            verdicts.append(cls().evaluate(ctx))

        return VerifyInvariantsOutput(
            binary_path=str(binary),
            sidecar_path=str(sidecar),
            overall_status=_overall(verdicts).value,
            invariants=[
                InvariantResult(
                    name=v.name,
                    status=v.status.value,
                    message=v.message,
                    evidence=v.evidence,
                )
                for v in verdicts
            ],
            ran_under_frida=bool(union_probes),
            enabled_probes=union_probes,
            timed_out=timed_out,
            duration_ms=duration_ms,
            event_count=len(events) if union_probes else None,
            events_summary=summarize(events) if union_probes else None,
        )
