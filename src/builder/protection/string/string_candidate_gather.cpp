/**
 * @file string_candidate_gather.cpp
 * @brief Implementation of `gather_string_candidates` — see header.
 */

#include "mxprotector/protection/string/string_candidate_gather.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <unordered_set>

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::string_protect {

namespace {

/// Minimum printable-run length the scanner accepts. Matches the
/// historical default and pins the tradeoff (smaller = more
/// candidates, more false positives).
constexpr uint32_t kScannerMinLength = 6;

/// Candidate data-section characteristics: contains initialized
/// data, NOT executable, NOT writable. Matches MSVC `.rdata`. We
/// deliberately exclude sections the loader marks read-write (those
/// are `.data` which holds mutable globals, not C string constants).
[[nodiscard]] bool is_rodata_section(const pe::SectionInfo& sec) noexcept {
    const bool is_init =
        (sec.characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
    return is_init && !sec.is_executable() && !sec.is_writable();
}

/// Any executable section qualifies for xref discovery. Picks up
/// not only `.text` but any CFF trampoline / VM blob section added
/// by an earlier pass — string references inside relocated code
/// are still candidates for the rewriter.
[[nodiscard]] bool is_code_section(const pe::SectionInfo& sec) noexcept {
    return sec.is_executable() && !sec.data.empty();
}

/// Translate a Zydis register enum value back into the 0..15 AMD64
/// GPR index the codegen module consumes. Returns 16 for 8-bit /
/// 32-bit aliases so the caller can reject the xref.
[[nodiscard]] constexpr GprIndex zydis_reg_to_gpr(uint32_t zydis_reg) noexcept {
    const auto lo = static_cast<uint32_t>(ZYDIS_REGISTER_RAX);
    const auto hi = static_cast<uint32_t>(ZYDIS_REGISTER_R15);
    if (zydis_reg < lo || zydis_reg > hi) return 16;
    return static_cast<GprIndex>(zydis_reg - lo);
}

/// Flat set of every RVA targeted by a base relocation entry. Any
/// string whose byte range intersects this set is held back from
/// protection — overwriting the plaintext bytes would break the
/// non-code consumer pointing at them.
[[nodiscard]] std::unordered_set<Rva>
collect_relocation_targets(const PeImage& image) {
    std::unordered_set<Rva> targets;
    for (const auto& block : image.relocations()) {
        for (const auto& entry : block.entries) {
            if (entry.type == pe::IMAGE_REL_BASED_ABSOLUTE) continue;
            targets.insert(entry.rva);
        }
    }
    return targets;
}

/// True iff any byte in `[str.rva_start, str.rva_start + str.length)`
/// is targeted by a base relocation. We extend the window by 8 bytes
/// BEFORE `rva_start` since we don't know whether each reloc was
/// DIR64 (8 bytes) or HIGHLOW (4) — the conservative widening
/// matches the pre-refactor behaviour byte-for-byte.
[[nodiscard]] bool is_reloc_overlapping(
    const FoundString&                str,
    const std::unordered_set<Rva>&    reloc_targets)
{
    const Rva start = (str.rva_start > 8) ? str.rva_start - 8 : 0;
    const Rva end   = str.rva_start + str.length;
    for (Rva r = start; r < end; ++r) {
        if (reloc_targets.contains(r)) return true;
    }
    return false;
}

} // anonymous namespace

std::optional<GatheredStrings>
gather_string_candidates(ProtectionContext& ctx)
{
    auto& image = ctx.pe_image();

    // (1) Candidate scan — one pass over every rodata-like section.
    StringScanner scanner(ScannerConfig{
        .min_length              = kScannerMinLength,
        .max_length              = 4096,
        .require_null_terminator = true,
    });

    std::vector<FoundString> candidates;
    for (const auto& sec : image.sections()) {
        if (!is_rodata_section(sec)) continue;
        if (sec.data.empty())        continue;
        auto found = scanner.scan(
            ByteView{sec.data.data(), sec.data.size()},
            static_cast<Rva>(sec.virtual_address));
        candidates.insert(candidates.end(),
                          std::make_move_iterator(found.begin()),
                          std::make_move_iterator(found.end()));
    }

    if (candidates.empty()) {
        ctx.log("StringProtectionPass: кандидатов не найдено, пропуск");
        return std::nullopt;
    }

    // Scanner emits per-section in RVA order, multi-section merge
    // may break that — re-sort so xref finder's binary search is
    // valid.
    std::sort(candidates.begin(), candidates.end(),
        [](const FoundString& a, const FoundString& b) noexcept {
            return a.rva_start < b.rva_start;
        });

    ctx.log_fmt("StringProtectionPass: найдено {} кандидатов строк",
        candidates.size());

    // (2) Xref discovery across every executable section.
    StringXrefFinder xref_finder;
    std::vector<StringXref> all_xrefs;
    for (const auto& sec : image.sections()) {
        if (!is_code_section(sec)) continue;
        auto xrefs = xref_finder.find(
            ByteView{sec.data.data(), sec.data.size()},
            static_cast<Rva>(sec.virtual_address),
            candidates);
        all_xrefs.insert(all_xrefs.end(),
                         std::make_move_iterator(xrefs.begin()),
                         std::make_move_iterator(xrefs.end()));
    }

    if (all_xrefs.empty()) {
        ctx.log("StringProtectionPass: xref'ов не найдено, пропуск");
        return std::nullopt;
    }

    // (3) Relocation-overlap filter + ephemeral-mode length bound.
    const auto reloc_targets = collect_relocation_targets(image);

    std::vector<uint8_t> keep_string(candidates.size(), 0);
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (!is_reloc_overlapping(candidates[i], reloc_targets)) {
            keep_string[i] = 1;
        }
    }

    // S3 additional filter: the ephemeral decryptor has a fixed
    // scratch-slot size, so any string whose plaintext wouldn't fit
    // (leaving room for a trailing NUL) is dropped from protection.
    // Applying the bound here instead of at encrypt time keeps the
    // rng draw order identical between --strings=stub and
    // --strings=ephemeral builds.
    GatheredStrings out;
    out.is_ephemeral_mode =
        ctx.config().string_protection == StringProtectionMode::ephemeral;
    if (out.is_ephemeral_mode) {
        for (size_t i = 0; i < candidates.size(); ++i) {
            if (candidates[i].length > kEphemeralMaxStringLength) {
                keep_string[i] = 0;
            }
        }
    }

    // Filter xrefs: drop those whose LEA is not a clean 7-byte
    // form, whose register is not a plain 64-bit GPR 0..15 except
    // rsp, or whose target string was filtered out.
    std::vector<StringXref> usable_xrefs;
    usable_xrefs.reserve(all_xrefs.size());
    for (const auto& x : all_xrefs) {
        if (x.insn_length < 7)                      continue;
        if (!keep_string[x.string_index])           continue;
        const GprIndex gpr = zydis_reg_to_gpr(x.dest_reg);
        if (gpr >= 16 || gpr == kGprRsp)            continue;
        usable_xrefs.push_back(x);
    }

    if (usable_xrefs.empty()) {
        ctx.log("StringProtectionPass: после фильтрации ни одной "
                "применимой xref, пропуск");
        return std::nullopt;
    }

    // (4) Assign dense string IDs only for strings we actually use.
    //     Map the old `string_index` (into `candidates`) → dense id
    //     that downstream emission uses as the mx_str_get argument.
    std::vector<uint32_t> id_for_candidate(candidates.size(),
                                            static_cast<uint32_t>(-1));
    std::vector<size_t>   kept_candidate_indices;
    kept_candidate_indices.reserve(candidates.size());
    for (const auto& x : usable_xrefs) {
        if (id_for_candidate[x.string_index] == static_cast<uint32_t>(-1)) {
            id_for_candidate[x.string_index] =
                static_cast<uint32_t>(kept_candidate_indices.size());
            kept_candidate_indices.push_back(x.string_index);
        }
    }

    out.kept_strings.reserve(kept_candidate_indices.size());
    for (size_t orig : kept_candidate_indices) {
        out.kept_strings.push_back(candidates[orig]);
    }

    out.usable_xrefs   = std::move(usable_xrefs);
    out.xref_string_id.reserve(out.usable_xrefs.size());
    for (const auto& x : out.usable_xrefs) {
        out.xref_string_id.push_back(id_for_candidate[x.string_index]);
    }

    return out;
}

} // namespace mx::string_protect
