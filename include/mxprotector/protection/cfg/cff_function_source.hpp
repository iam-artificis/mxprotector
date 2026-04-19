/**
 * @file cff_function_source.hpp
 * @brief Candidate discovery for CFG flattening.
 *
 * Three sources, in priority order:
 *
 *   1. `MX_OBFUSCATE_BEGIN/END` markers embedded in the source by the
 *      SDK. When present, every marked region is a candidate and no
 *      other source is consulted.
 *
 *   2. An MSVC `.map` file referenced via `config().map_file_path`.
 *      Parsed by `MapParser`; CRT library functions, export thunks,
 *      and out-of-range sizes are filtered out. Used only when no
 *      markers were emitted.
 *
 *   3. `.pdata` runtime-function table fallback. Every entry strictly
 *      before the entry-point function becomes a candidate, with the
 *      `UNW_FLAG_EHANDLER / UHANDLER / CHAININFO` filter applied so C++
 *      exception unwinding stays intact. Used when neither markers nor
 *      a `.map` file are available.
 *
 * `gather_candidates` is the strategy selector the pipeline calls; the
 * individual `candidates_from_*` helpers are exposed so tests and future
 * callers can drive one strategy directly.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx {
class ProtectionContext;
}

namespace mx::cff {

/**
 * @brief One function that's eligible for flattening.
 *
 * Contains only the information the pipeline needs to locate and size
 * the function; the section lookup happens downstream.
 */
struct FunctionCandidate {
    Rva      rva;
    uint32_t size;
};

/**
 * @brief Collect candidates from `MX_OBFUSCATE_BEGIN/END` markers.
 *
 * Regions smaller than 16 bytes are skipped — too small to be worth a
 * dispatcher. Logs a line per accepted region.
 */
[[nodiscard]] std::vector<FunctionCandidate>
candidates_from_markers(ProtectionContext& ctx);

/**
 * @brief Collect candidates from an MSVC-generated `.map` file.
 *
 * Returns `std::nullopt` when either the configured path is empty or
 * parsing fails — both signal "the `.map` source was not consulted" and
 * let the strategy selector fall through to `.pdata`. A present result
 * (even an empty one) means the parse succeeded and the user's
 * explicit `--map` input is authoritative: the selector trusts it and
 * does not fall back.
 */
[[nodiscard]] std::optional<std::vector<FunctionCandidate>>
candidates_from_map_file(ProtectionContext& ctx);

/**
 * @brief Collect candidates from the PE's `.pdata` runtime-function
 *        table, with CFF-safety filtering.
 *
 * Only entries whose `begin_addr < entry_point_rva` are considered (the
 * heuristic that everything after the entry is application code that
 * CFF already covers through markers / `.map`).
 */
[[nodiscard]] std::vector<FunctionCandidate>
candidates_from_pdata(ProtectionContext& ctx);

/**
 * @brief Select the first-available source and return its candidates.
 *
 * Priority: markers → `.map` → `.pdata`. An empty return means the
 * pipeline has nothing to flatten.
 */
[[nodiscard]] std::vector<FunctionCandidate>
gather_candidates(ProtectionContext& ctx);

} // namespace mx::cff
