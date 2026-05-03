/**
 * @file function_atom_source.hpp
 * @brief Per-function movable atoms driven by `.pdata` (B.4.11.2).
 *
 * Code shuffle at the *function* level is the smallest unit at
 * which we can guarantee correctness without rewriting control
 * flow. Functions are bracketed by unconditional control transfers
 * (RET, JMP) at their entry/exit, so reordering whole functions
 * never breaks fallthrough — every cross-function transition is
 * a CALL or JMP that we patch via the refmap.
 *
 * The `.pdata` Exception Directory is x64's authoritative function
 * map: every byte that the unwinder has to walk is bracketed by a
 * `RUNTIME_FUNCTION` entry (BeginAddress, EndAddress, UnwindData).
 * We use that as the function table source — no decoding, no
 * heuristics.
 *
 * Two adjustments against raw `.pdata` ranges:
 *
 *   1. **Round start DOWN** to the nearest 8-byte boundary. Most
 *      x64 compilers align function entry points to 16 bytes, so
 *      this is usually a no-op; the rare unaligned function entry
 *      gets a few bytes of preceding padding (INT3) absorbed into
 *      the atom.
 *
 *   2. **Round size UP** to a multiple of 8. Functions end at
 *      arbitrary RVAs (the `RET` byte). Padding the size up so
 *      atom END is 8-aligned guarantees every chunk boundary is
 *      8-aligned, which in turn guarantees no naturally-aligned
 *      8-byte value spans the boundary.
 *
 * After both adjustments the atom may overlap the next function's
 * atom by 0-7 bytes; `AtomTable::normalize` merges overlapping
 * atoms into one larger movable atom — the merged atom still
 * shuffles as a unit, just at coarser granularity.
 *
 * SOLID:
 *   * SRP — the source emits function-shaped atoms; cluster-level
 *     emission stays elsewhere.
 *   * OCP — the source can be added/removed without touching the
 *     planner or other sources.
 *
 * Threading: stateless apart from a `.pdata` parse — re-create
 * the source per call.
 */

#pragma once

#include <cstdint>

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief `.pdata`-driven function atom source — see file header.
 */
class FunctionAtomSource final : public IAtomSource {
public:
    /// Boundary alignment for emitted atoms. 8 is the minimum that
    /// keeps every 8-aligned 8-byte value in one chunk.
    static constexpr std::uint32_t kBoundaryAlignment = 8;

    FunctionAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
