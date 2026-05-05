/**
 * @file chaos_atom_source_registry.hpp
 * @brief Register the canonical atom-source line-up with an
 *        `AtomicChunkPlanner` + parse the per-build random seed.
 *
 * @details Two helpers extracted from `chaos_layout.cpp`:
 *
 *            * `register_atom_sources(planner)` — pushes every atom
 *              source the chaos pipeline relies on (movable sub-block
 *              + section movable-blocks + pinned data sections + every
 *              PE directory the loader walks linearly) onto the
 *              planner. New movable-block atom sources should be
 *              added here; new movable section emitters should
 *              register `pe::SectionInfo::movable_blocks` so the
 *              section-movable-block source picks them up
 *              automatically.
 *
 *            * `fresh_seed()` — returns the planner seed for this
 *              build. Honours the `MX_CHAOS_SEED` environment
 *              variable for deterministic debug builds; otherwise
 *              draws a fresh seed from `std::random_device`.
 */

#pragma once

#include <cstdint>

#include "mxprotector/pe/chaos/atomic_chunk_planner.hpp"

namespace mx::pe::chaos {

/// Loose-chunk size range. Values are rounded DOWN to a multiple
/// of 8 inside the planner, so the practical range is 64 / 96 in
/// 8-byte increments.
inline constexpr std::uint32_t kMinLooseChunkSize = 64;
inline constexpr std::uint32_t kMaxLooseChunkSize = 96;

/**
 * @brief Push the canonical atom-source line-up onto @p planner.
 *
 * @details The order below groups by abstraction depth: code
 *          (function atoms) first, then PE-format directory
 *          structures, then the data-section blanket pin.
 *          `InstructionAtomSource` / `InstructionClusterAtomSource`
 *          are intentionally NOT registered: per-instruction shuffle
 *          without rewriting control flow corrupts fall-through
 *          transitions.
 */
void register_atom_sources(AtomicChunkPlanner& planner);

/**
 * @brief Return the per-build random seed for the chaos planner.
 *
 * @details Reads `MX_CHAOS_SEED` (16-hex-digit value) when present —
 *          the entire chaos plan is then deterministic for the run,
 *          which is what the stability-bug debugger needs to capture
 *          corrupted bytes and re-run with the same chunk layout.
 *          Otherwise draws from `std::random_device` via
 *          `Randomizer::next_u64()`.
 */
[[nodiscard]] std::uint64_t fresh_seed();

} // namespace mx::pe::chaos
