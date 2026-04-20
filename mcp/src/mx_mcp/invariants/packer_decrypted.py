"""Invariant: the protected PE's packer section was touched at runtime.

If ``sections.packer`` is present in the sidecar, at least one
``section_access`` event with ``role == 'packer'`` must fire during
the traced run. A working protected binary always satisfies this —
the packer stub itself lives in that section and is the entry point,
so first execution arms the ``MemoryAccessMonitor`` immediately.

Status meaning:
  pass — one or more section_access events targeted the packer role.
  fail — packer section exists in the sidecar but zero events saw it
         (either the stub never ran or mem_region probe was silenced).
  skip — no packer section in the sidecar (build with --no-packer or
         level=minimal/standard).
"""

from __future__ import annotations

from mx_mcp.common.invariant_base import (
    IInvariant,
    InvariantContext,
    InvariantVerdict,
    VerdictStatus,
    register_invariant,
)


@register_invariant
class PackerDecryptedInvariant(IInvariant):
    name = "packer_decrypted"
    description = (
        "Confirm the packer section recorded in the sidecar is actually "
        "touched at runtime (proves the packer stub executed)."
    )
    probes = ["mem_region"]

    def evaluate(self, ctx: InvariantContext) -> InvariantVerdict:
        packer = ctx.sidecar.sections.get("packer")
        if packer is None:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.SKIP,
                message="no packer section in sidecar (level=minimal/standard or --no-packer)",
                evidence={},
            )

        hits = [
            e for e in ctx.events
            if e.kind == "section_access" and e.payload.get("role") == "packer"
        ]

        if not hits:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.FAIL,
                message=(
                    "packer section present but received zero section_access events — "
                    "either the stub never ran or mem_region probe was disabled"
                ),
                evidence={
                    "packer_rva": packer.rva,
                    "packer_size": packer.size,
                    "section_access_count": 0,
                },
            )

        operations = sorted({
            str(e.payload.get("operation")) for e in hits
            if e.payload.get("operation") is not None
        })

        return InvariantVerdict(
            name=self.name,
            status=VerdictStatus.PASS,
            message=(
                f"packer section observed at runtime "
                f"({len(hits)} events, ops={operations or ['?']})"
            ),
            evidence={
                "packer_rva": packer.rva,
                "packer_size": packer.size,
                "section_access_count": len(hits),
                "operations": operations,
            },
        )
