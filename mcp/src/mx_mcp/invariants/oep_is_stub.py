"""Invariant: the PE entry point falls inside the packer section.

Static check — no runtime events needed. Reads ``AddressOfEntryPoint``
from the protected PE header and compares it against the packer
section range recorded in the sidecar.

Status meaning:
  pass — entry point ∈ [packer.rva, packer.rva + packer.size).
  fail — packer section present, but entry point points elsewhere
         (almost always a build regression).
  skip — no packer section in the sidecar.
"""

from __future__ import annotations

from mx_mcp.common.invariant_base import (
    IInvariant,
    InvariantContext,
    InvariantVerdict,
    VerdictStatus,
    register_invariant,
)
from mx_mcp.common.pe_reader import NotAPeError, read_entry_point_rva


@register_invariant
class OepIsStubInvariant(IInvariant):
    name = "oep_is_stub"
    description = (
        "Confirm the protected PE's entry point lies inside the packer "
        "section, proving the packer owns first execution."
    )
    probes: list[str] = []  # static-only

    def evaluate(self, ctx: InvariantContext) -> InvariantVerdict:
        packer = ctx.sidecar.sections.get("packer")
        if packer is None:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.SKIP,
                message="no packer section in sidecar",
                evidence={},
            )

        try:
            ep_rva = read_entry_point_rva(ctx.binary_path)
        except (NotAPeError, OSError) as e:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.FAIL,
                message=f"could not read PE entry point: {e}",
                evidence={"error": str(e)},
            )

        packer_start = packer.rva
        packer_end = packer.rva + packer.size  # exclusive
        in_range = packer_start <= ep_rva < packer_end

        evidence = {
            "entry_point_rva": ep_rva,
            "packer_rva": packer_start,
            "packer_size": packer.size,
            "packer_end_exclusive": packer_end,
        }

        if in_range:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.PASS,
                message=(
                    f"entry point 0x{ep_rva:X} is inside packer "
                    f"[0x{packer_start:X}..0x{packer_end:X})"
                ),
                evidence=evidence,
            )

        return InvariantVerdict(
            name=self.name,
            status=VerdictStatus.FAIL,
            message=(
                f"entry point 0x{ep_rva:X} is OUTSIDE packer "
                f"[0x{packer_start:X}..0x{packer_end:X}) — "
                f"packer stub did not claim OEP"
            ),
            evidence=evidence,
        )
