"""Invariant: no protector-identifying literals in the shipped PE.

Static-only (probes=[]). Runs the forbidden-literal scan from
:mod:`mx_mcp.common.leakage_scan` against the protected binary and
fails hard on any hit.

Status meaning:
  pass — zero forbidden literals in the file.
  fail — at least one forbidden literal is present (regression or
         build-configuration slip — e.g. packer stub suddenly linked
         against debug-info-bearing .obj files).
  skip — never: the scan is cheap and applies to every PE.

The complementary :mod:`mx_mcp.benchmarks.leakage_benchmark` tracks
softer signals (PDB paths, Rich header) as regression-visible
metrics without gating. This invariant is the hard block.
"""

from __future__ import annotations

from mx_mcp.common.invariant_base import (
    IInvariant,
    InvariantContext,
    InvariantVerdict,
    VerdictStatus,
    register_invariant,
)
from mx_mcp.common.leakage_scan import (
    LeakHit,
    forbidden_literals,
    scan_forbidden_literals,
)


# Evidence payload guard: if a future misconfiguration produces
# thousands of hits, the JSON blob would swamp the tool output. Cap
# per-literal sample count so evidence stays bounded while still
# naming every offending pattern.
_MAX_OFFSETS_PER_LITERAL = 8


@register_invariant
class NoProtectorMetadataLeakedInvariant(IInvariant):
    name = "no_protector_metadata_leaked"
    description = (
        "Confirm the shipped PE does not contain any protector-identifying "
        "literal (pass names, SDK markers, 'MxProtector'). Scans both ASCII "
        "and UTF-16LE encodings. Hard block — any hit is a regression."
    )
    probes: list[str] = []  # static-only

    def evaluate(self, ctx: InvariantContext) -> InvariantVerdict:
        try:
            hits = scan_forbidden_literals(ctx.binary_path)
        except OSError as e:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.FAIL,
                message=f"could not read binary: {e}",
                evidence={"error": str(e)},
            )

        if not hits:
            return InvariantVerdict(
                name=self.name,
                status=VerdictStatus.PASS,
                message=(
                    f"clean — scanned {len(forbidden_literals())} forbidden "
                    f"literals × 2 encodings, zero matches"
                ),
                evidence={
                    "forbidden_literal_count": len(forbidden_literals()),
                    "total_hits": 0,
                },
            )

        return InvariantVerdict(
            name=self.name,
            status=VerdictStatus.FAIL,
            message=(
                f"{len(hits)} forbidden-literal hit(s) across "
                f"{len({h.literal for h in hits})} distinct literal(s) — "
                f"protector metadata is leaking into the shipped PE"
            ),
            evidence=_build_evidence(hits),
        )


def _build_evidence(hits: list[LeakHit]) -> dict:
    """Shape the per-literal breakdown for the verdict evidence blob.

    Groups hits by ``literal`` and records first ``_MAX_OFFSETS_PER_LITERAL``
    (offset, encoding) pairs + total count. Output is deterministic
    (literals sorted alphabetically, offsets ascending) so snapshot
    comparisons in tests stay stable.
    """
    by_literal: dict[str, list[LeakHit]] = {}
    for h in hits:
        by_literal.setdefault(h.literal, []).append(h)

    breakdown: list[dict] = []
    for literal in sorted(by_literal):
        lit_hits = sorted(by_literal[literal], key=lambda h: h.offset)
        breakdown.append({
            "literal": literal,
            "hit_count": len(lit_hits),
            "first_offsets": [
                {"offset": h.offset, "encoding": h.encoding}
                for h in lit_hits[:_MAX_OFFSETS_PER_LITERAL]
            ],
            "truncated": len(lit_hits) > _MAX_OFFSETS_PER_LITERAL,
        })

    return {
        "total_hits": len(hits),
        "distinct_literals": len(by_literal),
        "breakdown": breakdown,
    }
