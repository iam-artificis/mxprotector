/**
 * @file instruction_cluster_atom_source.hpp
 * @brief Atom source that groups consecutive instructions into
 *        clusters (B.4.10.2).
 *
 * Where `InstructionAtomSource` emits one atom per decoded x86
 * instruction, this source groups runs of `[min_insns, max_insns]`
 * consecutive instructions into a single cluster atom. The cluster
 * size for each new run is sampled from the range using a
 * deterministic per-source `Randomizer` seeded at construction.
 *
 * Why cluster:
 *   * Fewer atoms → smaller `AtomTable`, faster planning.
 *   * Larger movable units → control-flow internal to a cluster
 *     (typically 4-15 instructions, ~30-150 B) keeps every short
 *     `rel8` branch and most `rel32` calls intact. Only boundary
 *     branches need patching, which the refmap pipeline already
 *     handles.
 *   * Cluster atoms remain movable (`alignment == 1`); clusters
 *     can be permuted among themselves while pinned PE structures
 *     stay anchored.
 *
 * On decode failure the source emits a 1-byte
 * `instruction_undecoded` atom (matching the per-instruction
 * source's behaviour) and resets the in-progress cluster, so the
 * next cluster starts at the byte after the unparseable byte.
 *
 * SOLID:
 *   * SRP — one source, one concern (cluster-grained code atoms).
 *   * OCP — `InstructionAtomSource` and this source coexist; the
 *     planner picks whichever is registered.
 *
 * Threading: every `emit_atoms` call constructs a fresh
 * `Randomizer` from the stored seed, so concurrent calls on
 * disjoint tables are safe. The pipeline is single-threaded by
 * construction.
 */

#pragma once

#include <cstdint>

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Cluster-granularity instruction atom source — see file header.
 */
class InstructionClusterAtomSource final : public IAtomSource {
public:
    /// Default cluster size range — chosen so a cluster carries enough
    /// internal control flow to keep most short branches intact while
    /// remaining small enough that the shuffle still meaningfully
    /// rearranges the code section.
    static constexpr std::uint32_t kDefaultMinInsns = 4;
    static constexpr std::uint32_t kDefaultMaxInsns = 15;

    /**
     * @brief Construct the source.
     *
     * @param seed       Seed for the per-call `Randomizer`. Holding
     *                   a seed (rather than a `Randomizer&`) keeps
     *                   the source const-correct and lets every
     *                   `emit_atoms` reproduce the exact same
     *                   cluster boundaries given identical input.
     * @param min_insns  Minimum instructions per cluster (≥ 1).
     * @param max_insns  Maximum instructions per cluster
     *                   (≥ `min_insns`).
     *
     * Invalid pre-conditions (`min == 0`, `max < min`) are silently
     * clamped to `kDefault…` rather than thrown — atom sources
     * MUST NOT throw.
     */
    explicit InstructionClusterAtomSource(
        std::uint64_t seed,
        std::uint32_t min_insns = kDefaultMinInsns,
        std::uint32_t max_insns = kDefaultMaxInsns) noexcept;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;

private:
    std::uint64_t seed_;
    std::uint32_t min_insns_;
    std::uint32_t max_insns_;
};

} // namespace mx::pe::chaos
