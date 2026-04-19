/**
 * @file string_candidate_gather.hpp
 * @brief Phase 1..4 of the StringProtectionPass pipeline — scan,
 *        xref, filter, assign dense IDs.
 *
 * Walks every rodata-like section for printable-ASCII candidates,
 * finds every LEA-xref in every executable section, drops strings
 * hit by base relocations, filters xrefs whose LEA shape or register
 * is unsuitable, enforces the ephemeral-mode length bound, and
 * assigns each surviving string a dense 0-based id.
 *
 * Returns std::nullopt when no xrefs survive (the pipeline logs +
 * skips in that case).
 */

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "mxprotector/protection/string/string_decryptor_codegen.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"
#include "mxprotector/protection/string/string_xref_finder.hpp"

namespace mx {
class ProtectionContext;
} // namespace mx

namespace mx::string_protect {

/// Output of the gather phase. `kept_strings` is indexed 0..N-1 by
/// dense string id; `xref_string_id[i]` is the dense id that
/// trampoline i / call site i targets.
struct GatheredStrings {
    std::vector<FoundString> kept_strings;
    std::vector<StringXref>  usable_xrefs;
    std::vector<uint32_t>    xref_string_id;
    bool                     is_ephemeral_mode = false;
};

/// Scan + discover + filter + assign IDs. Returns std::nullopt when
/// no candidates, no xrefs, or nothing survives filtering — callers
/// log + skip in that case.
[[nodiscard]] std::optional<GatheredStrings>
gather_string_candidates(ProtectionContext& ctx);

} // namespace mx::string_protect
