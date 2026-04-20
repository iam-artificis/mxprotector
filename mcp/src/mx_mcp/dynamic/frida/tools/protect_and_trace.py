"""MCP tool: build with ``--trace-hints``, optionally trace under Frida.

Flow:
  1. Invoke ``mxprotector_builder`` on the input PE with ``--trace-hints``.
  2. Load the produced sidecar to surface roles + (if run=True) to seed
     the ``mem_region`` probe with RVA/size per role.
  3. Spawn the protected PE under Frida with the enabled probes and
     collect events up to ``timeout_s``.

Returns raw event counts so the agent can sanity-check that tracing is
live. Typed invariant evaluation lives in
``tools/verify_protection_invariants.py``.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from mx_mcp.common.sidecar import load_sidecar, sidecar_path_for
from mx_mcp.common.tool_base import ITool, register_tool


_BUILDER_REL = Path("build") / "src" / "builder" / "Release" / "mxprotector_builder.exe"
# Roles whose sections are likely interesting to watch for memory
# access. Adjust here — no need to touch the probe.
_WATCHED_ROLES: frozenset[str] = frozenset({"packer", "strings", "guard", "vm", "cff"})


def _resolve(path_str: str, workspace_root: Path) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (workspace_root / p).resolve()


def _default_output_path(input_pe: Path) -> Path:
    return input_pe.parent / f"{input_pe.stem}.mx{input_pe.suffix}"


def _tail(text: str, limit: int = 2048) -> str:
    return text if len(text) <= limit else text[-limit:]


class ProtectAndTraceInput(BaseModel):
    input_pe: str = Field(
        description="Input PE path (absolute or workspace-relative)."
    )
    output_pe: str | None = Field(
        None,
        description="Protected output path; default: <stem>.mx<ext> next to input.",
    )
    level: str = Field(
        "strong",
        description="Protection level: minimal | standard | strong | maximum.",
    )
    extra_builder_args: list[str] = Field(
        default_factory=list,
        description="Extra CLI args forwarded to mxprotector_builder.",
    )
    run: bool = Field(
        True,
        description="Execute the protected PE under Frida after build.",
    )
    probes: list[str] = Field(
        default_factory=lambda: ["api_call", "mem_region"],
        description="Probe names to enable (match files in probes/).",
    )
    run_args: list[str] = Field(
        default_factory=list,
        description="Command-line args for the protected PE.",
    )
    timeout_s: float = Field(
        30.0, description="Max seconds to wait for the process to exit."
    )
    builder_path: str | None = Field(
        None,
        description=(
            "Override the builder executable; default: "
            "build/src/builder/Release/mxprotector_builder.exe."
        ),
    )


class ProtectAndTraceOutput(BaseModel):
    build_ok: bool
    builder_stdout_tail: str
    builder_stderr_tail: str
    output_pe: str
    sidecar_path: str
    sidecar_sections_roles: list[str]

    ran: bool
    timed_out: bool | None
    exit_code: int | None
    duration_ms: int | None
    event_count: int | None
    events_summary: dict[str, int] | None


@register_tool
class ProtectAndTraceTool(ITool[ProtectAndTraceInput, ProtectAndTraceOutput]):
    name = "protect_and_trace"
    description = (
        "Protect an input PE with mxprotector_builder --trace-hints and "
        "(unless run=false) trace the protected binary under Frida with "
        "the requested probes. Returns the sidecar path, run status, and "
        "per-kind event counts."
    )
    input_schema = ProtectAndTraceInput
    output_schema = ProtectAndTraceOutput

    async def run(
        self, args: ProtectAndTraceInput, session
    ) -> ProtectAndTraceOutput:
        input_pe = _resolve(args.input_pe, session.workspace_root)
        output_pe = (
            _resolve(args.output_pe, session.workspace_root)
            if args.output_pe
            else _default_output_path(input_pe)
        )
        output_pe.parent.mkdir(parents=True, exist_ok=True)

        builder = (
            _resolve(args.builder_path, session.workspace_root)
            if args.builder_path
            else session.workspace_root / _BUILDER_REL
        )

        build_cmd = [
            str(builder),
            "-i", str(input_pe),
            "-o", str(output_pe),
            "-l", args.level,
            "--trace-hints",
            *args.extra_builder_args,
        ]
        # Builder emits UTF-8 (see /utf-8 MSVC flag in src/builder/
        # CMakeLists.txt). Force UTF-8 decoding here so a non-UTF-8
        # host locale (cp1251 on RU Windows) doesn't fail on the
        # reader thread.
        proc = await asyncio.to_thread(
            subprocess.run,
            build_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(session.workspace_root),
        )
        build_ok = proc.returncode == 0 and output_pe.exists()
        sidecar = sidecar_path_for(output_pe)

        out = ProtectAndTraceOutput(
            build_ok=build_ok,
            builder_stdout_tail=_tail(proc.stdout),
            builder_stderr_tail=_tail(proc.stderr),
            output_pe=str(output_pe),
            sidecar_path=str(sidecar),
            sidecar_sections_roles=[],
            ran=False,
            timed_out=None,
            exit_code=None,
            duration_ms=None,
            event_count=None,
            events_summary=None,
        )

        if not build_ok:
            return out

        doc = load_sidecar(sidecar)
        out.sidecar_sections_roles = sorted(doc.sections.keys())

        if not args.run:
            return out

        mem_ranges = [
            {"role": role, "rva": s.rva, "size": s.size}
            for role, s in doc.sections.items()
            if role in _WATCHED_ROLES
        ]

        result = await session.run_probed(
            binary=output_pe,
            enabled_probes=args.probes,
            config_extras={"mem_ranges": mem_ranges},
            args=args.run_args,
            timeout_s=args.timeout_s,
        )

        out.ran = True
        out.timed_out = result.timed_out
        out.exit_code = result.exit_code
        out.duration_ms = result.duration_ms
        out.event_count = len(result.events)
        out.events_summary = result.events_summary
        return out
