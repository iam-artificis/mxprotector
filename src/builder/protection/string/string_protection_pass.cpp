/**
 * @file string_protection_pass.cpp
 * @brief [BUILDER] StringProtectionPass — S2 orchestrator implementation.
 *
 * Pipeline walk-through:
 *
 *   1. For every non-executable initialized-data section (typically
 *      `.rdata`), run the scanner to collect printable-ASCII candidates.
 *   2. For every executable section (`.text`, CFF trampoline, VM blob,
 *      etc.), run the xref finder against the combined candidate list.
 *      All xrefs are pooled together. A candidate with zero xrefs is
 *      dropped — nothing in the binary would be decrypted anyway.
 *   3. Build the "relocation-reachable RVA" set so strings whose bytes
 *      are the target of a base-relocation entry (data pointer, vtable,
 *      static init array) are excluded. Overwriting such a string with
 *      ciphertext would break the non-code consumer at runtime.
 *   4. Encrypt the surviving strings with a per-string XOR key.
 *   5. Emit the shared `mx_str_get` decryptor and one trampoline per
 *      surviving xref. Compose the `.mxstr` section:
 *         [mx_str_get][trampolines...][descriptor table][data pool]
 *   6. Add the new section through `SectionManager`, which assigns its
 *      final RVA. Patch the two disp32 slots inside `mx_str_get` (to the
 *      descriptor table and data pool) and each trampoline's `call rel32`
 *      (to `mx_str_get`).
 *   7. Overwrite every LEA site in place with `call rel32 <trampoline>`
 *      plus NOP padding so the original instruction length is preserved.
 *      Finally, wipe the plaintext bytes in the source data section so
 *      `strings` output on the packed binary reveals nothing.
 */

#include "mxprotector/protection/string/string_protection_pass.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/string/string_decryptor_codegen.hpp"
#include "mxprotector/protection/string/string_encryptor.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"
#include "mxprotector/protection/string/string_xref_finder.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_set>
#include <vector>

namespace mx {

namespace {

using string_protect::EmittedDecryptor;
using string_protect::EmittedTrampoline;
using string_protect::EncryptedString;
using string_protect::FoundString;
using string_protect::GprIndex;
using string_protect::StringDescriptor;
using string_protect::StringXref;

/// Minimum printable-run length the scanner accepts. Six matches the
/// scanner default; we pin it here for clarity and to document the
/// tradeoff (smaller = more candidates, more false positives).
constexpr uint32_t kScannerMinLength = 6;

/// Candidate data-section characteristics: contains initialized data,
/// NOT executable, NOT writable. Matches MSVC `.rdata`. We deliberately
/// exclude sections the loader marks read-write (those are `.data`
/// which holds mutable globals, not C string constants).
[[nodiscard]] bool is_rodata_section(const pe::SectionInfo& sec) noexcept {
    const bool is_init =
        (sec.characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
    return is_init && !sec.is_executable() && !sec.is_writable();
}

/// All sections we scan for LEA xrefs. Any executable section qualifies.
/// This picks up not only `.text` but also any CFF trampoline / VM blob
/// section added by an earlier pass — string references inside code that
/// a previous pass relocated are still candidates for the rewriter.
[[nodiscard]] bool is_code_section(const pe::SectionInfo& sec) noexcept {
    return sec.is_executable() && !sec.data.empty();
}

/// Zydis RAX..R15 is a contiguous 16-value range starting at
/// `ZYDIS_REGISTER_RAX`. The xref finder stores the raw Zydis enum
/// value; we translate it back to the 0..15 AMD64 index the codegen
/// module consumes. Out-of-range (8-bit / 32-bit aliases) returns 16
/// so the caller can reject the xref.
[[nodiscard]] constexpr GprIndex zydis_reg_to_gpr(uint32_t zydis_reg) noexcept {
    const auto lo = static_cast<uint32_t>(ZYDIS_REGISTER_RAX);
    const auto hi = static_cast<uint32_t>(ZYDIS_REGISTER_R15);
    if (zydis_reg < lo || zydis_reg > hi) return 16;
    return static_cast<GprIndex>(zydis_reg - lo);
}

/// Build a flat set of every RVA that a base relocation entry targets.
/// Any string whose [rva_start, rva_start+length) range intersects this
/// set is held back from protection — doing so guarantees that overwriting
/// the plaintext bytes cannot break a non-code consumer pointing at them.
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
/// is targeted by a base relocation (approximation: we check a window
/// of length 8 around each reloc target since DIR64 consumes 8 bytes,
/// but since we're using a set lookup per byte this is O(len) per
/// string, which is fine given string lengths are bounded).
[[nodiscard]] bool is_reloc_overlapping(
    const FoundString& str,
    const std::unordered_set<Rva>& reloc_targets)
{
    // Check every byte the reloc could legally target. A DIR64 reloc
    // covers 8 bytes starting at entry.rva; HIGHLOW covers 4. We don't
    // know which type each entry was, so conservatively extend the
    // guard window by 8 bytes BEFORE rva_start as well.
    const Rva start = (str.rva_start > 8) ? str.rva_start - 8 : 0;
    const Rva end   = str.rva_start + str.length;
    for (Rva r = start; r < end; ++r) {
        if (reloc_targets.contains(r)) return true;
    }
    return false;
}

/// Write `value` little-endian into `buf[offset..offset+4]`. No-op if
/// the offset would exceed the buffer size — callers should enforce
/// bounds, this is a last-resort guard.
void write_i32_le(std::vector<uint8_t>& buf, size_t offset, int32_t value) noexcept {
    if (offset + 4 > buf.size()) return;
    buf[offset + 0] = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8)  & 0xFF);
    buf[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buf[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

/// Result of flattening the candidate/xref/encrypt inputs into the
/// dense per-string tables the `.mxstr` section is assembled from.
struct StringTable {
    std::vector<EncryptedString> strings;   ///< One entry per protected string
    std::vector<StringXref>      xrefs;     ///< One entry per rewritable LEA site
};

/// Rewrite a LEA site in place with `call rel32 <trampoline>` plus NOP
/// padding up to the original instruction length. Operates on the
/// SectionInfo holding the LEA — discovered by RVA lookup.
void rewrite_lea_as_call(
    PeImage& image,
    Rva      lea_rva,
    uint8_t  lea_length,
    Rva      trampoline_rva) noexcept
{
    auto* sec = const_cast<pe::SectionInfo*>(image.section_by_rva(lea_rva));
    if (sec == nullptr) return;
    const uint32_t off = lea_rva - sec->virtual_address;
    if (off + lea_length > sec->data.size()) return;
    if (lea_length < 5) return;  // call rel32 needs 5 bytes minimum

    // call rel32 = E8 <rel32>, rel32 = target - (lea_rva + 5)
    const int32_t rel = static_cast<int32_t>(
        static_cast<int64_t>(trampoline_rva) -
        (static_cast<int64_t>(lea_rva) + 5));

    sec->data[off + 0] = 0xE8;
    sec->data[off + 1] = static_cast<uint8_t>(rel        & 0xFF);
    sec->data[off + 2] = static_cast<uint8_t>((rel >> 8)  & 0xFF);
    sec->data[off + 3] = static_cast<uint8_t>((rel >> 16) & 0xFF);
    sec->data[off + 4] = static_cast<uint8_t>((rel >> 24) & 0xFF);

    // NOP pad the remainder. A single 0x90 per byte is uglier than a
    // multi-byte NOP but correctness-identical; the tail is at most 2
    // bytes for a standard 7-byte LEA.
    for (uint8_t i = 5; i < lea_length; ++i) {
        sec->data[off + i] = 0x90;
    }
}

/// Zero the plaintext bytes of `str` in its owning source section.
/// Called after the string has been successfully protected (xref
/// rewritten to a trampoline, ciphertext already copied into the data
/// pool). The original `.rdata` slot is therefore wiped so the final
/// binary has no plaintext copy of the string to feed `strings`.
void wipe_plaintext(PeImage& image, Rva start, uint32_t length) noexcept {
    auto* sec = const_cast<pe::SectionInfo*>(image.section_by_rva(start));
    if (sec == nullptr) return;
    const uint32_t off = start - sec->virtual_address;
    if (off + length > sec->data.size()) return;
    std::fill(sec->data.begin() + off,
              sec->data.begin() + off + length,
              static_cast<uint8_t>(0));
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Applicability
// ---------------------------------------------------------------------------

bool StringProtectionPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    // Only runs when the user asked for string protection.
    if (ctx.config().string_protection == StringProtectionMode::disabled) {
        return false;
    }
    // x64 PE only: the codegen emits AMD64 bytes and the layout
    // assumes 64-bit RIP-relative LEA encoding.
    if (!ctx.target().is_windows_pe_x64()) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

MxStatus StringProtectionPass::execute(ProtectionContext& ctx) {
    ctx.log("StringProtectionPass: старт S2 (scan → xref → encrypt → emit → patch)");

    auto& image = ctx.pe_image();

    // (1) Candidate scan — one pass over every rodata-like section.
    //     FoundString.bytes aliases the section data buffer; we must
    //     keep `candidate_sources` alive for the lifetime of `candidates`.
    string_protect::StringScanner scanner(string_protect::ScannerConfig{
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
        return {};
    }

    // Scanner emits in RVA order per section; multi-section merge may
    // break that invariant. Re-sort so xref finder's binary search is
    // valid.
    std::sort(candidates.begin(), candidates.end(),
        [](const FoundString& a, const FoundString& b) noexcept {
            return a.rva_start < b.rva_start;
        });

    ctx.log_fmt("StringProtectionPass: найдено {} кандидатов строк",
        candidates.size());

    // (2) Xref discovery — every executable section.
    string_protect::StringXrefFinder xref_finder;
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
        return {};
    }

    // (3) Relocation overlap filter + LEA size / register sanity.
    //     We only accept xrefs whose LEA is the canonical 7-byte
    //     form with a destination register that maps cleanly to a
    //     0..15 AMD64 GPR (excluding rsp).
    const auto reloc_targets = collect_relocation_targets(image);

    // Mark strings whose xrefs should be kept; skip strings hit by a
    // base relocation. A single "keep" bitmap indexed by string_index
    // avoids re-checking per xref.
    std::vector<uint8_t> keep_string(candidates.size(), 0);
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (!is_reloc_overlapping(candidates[i], reloc_targets)) {
            keep_string[i] = 1;
        }
    }

    // Filter xrefs: drop those whose LEA is not a clean 7-byte form,
    // whose register is not a plain 64-bit GPR 0..15 excluding rsp,
    // or whose target string was filtered out by the reloc check.
    std::vector<StringXref> usable_xrefs;
    usable_xrefs.reserve(all_xrefs.size());
    for (const auto& x : all_xrefs) {
        if (x.insn_length < 7)                   continue;
        if (!keep_string[x.string_index])        continue;
        const GprIndex gpr = zydis_reg_to_gpr(x.dest_reg);
        if (gpr >= 16 || gpr == string_protect::kGprRsp) continue;
        usable_xrefs.push_back(x);
    }

    if (usable_xrefs.empty()) {
        ctx.log("StringProtectionPass: после фильтрации ни одной применимой xref, пропуск");
        return {};
    }

    // (4) Assign dense string IDs only for strings we actually use.
    //     Map old `string_index` (into `candidates`) → new dense id.
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

    // Build the subset list we actually protect, preserving RVA order
    // is not required but keeps logs readable.
    std::vector<FoundString> kept_strings;
    kept_strings.reserve(kept_candidate_indices.size());
    for (size_t orig : kept_candidate_indices) {
        kept_strings.push_back(candidates[orig]);
    }

    // (5) Per-string XOR encryption.
    Randomizer rng;
    auto encrypted = string_protect::encrypt_all(kept_strings, rng);

    // (6) Emit mx_str_get + per-xref trampolines.
    auto emitted_decryptor = string_protect::emit_mx_str_get();

    std::vector<EmittedTrampoline> trampolines;
    trampolines.reserve(usable_xrefs.size());
    for (const auto& x : usable_xrefs) {
        const GprIndex gpr = zydis_reg_to_gpr(x.dest_reg);
        string_protect::TrampolineRequest req{
            .string_id  = id_for_candidate[x.string_index],
            .target_reg = gpr,
        };
        trampolines.push_back(string_protect::emit_trampoline(req));
    }

    // (7) Compose the section buffer. Offsets are tracked as we go
    //     so patch sites can be translated from stub-local to
    //     section-local once the section has an assigned RVA.
    std::vector<uint8_t> section_buf;
    section_buf.reserve(
        emitted_decryptor.code.size() +
        trampolines.size() * string_protect::kTrampolineSizeVolatile +
        encrypted.size() * string_protect::kDescriptorSize +
        /* worst-case data pool: */ encrypted.size() * 4096);

    const size_t decryptor_offset = section_buf.size();
    section_buf.insert(section_buf.end(),
                       emitted_decryptor.code.begin(),
                       emitted_decryptor.code.end());

    // Trampoline offsets are remembered so we can patch their call
    // rel32 AFTER the section RVA is known, and so we can compute
    // the LEA rewrite target.
    std::vector<size_t> trampoline_offsets;
    trampoline_offsets.reserve(trampolines.size());
    for (const auto& tr : trampolines) {
        trampoline_offsets.push_back(section_buf.size());
        section_buf.insert(section_buf.end(),
                           tr.code.begin(),
                           tr.code.end());
    }

    // Descriptor table: one packed 8-byte record per protected string.
    // Data offsets are measured from the start of the data pool (not
    // the section), matching what `mx_str_get` computes:
    //     rax = desc.data_offset + data_base
    const size_t desc_table_offset = section_buf.size();
    size_t       data_pool_cursor  = 0;

    std::vector<StringDescriptor> descriptors;
    descriptors.reserve(encrypted.size());
    for (const auto& enc : encrypted) {
        StringDescriptor d{};
        d.data_offset = static_cast<uint32_t>(data_pool_cursor);
        d.length      = static_cast<uint16_t>(enc.length);
        d.key         = enc.key;
        d.flags       = 0;
        descriptors.push_back(d);
        data_pool_cursor += enc.length;
    }
    for (const auto& d : descriptors) {
        const auto packed = string_protect::pack_descriptor(d);
        section_buf.insert(section_buf.end(), packed.begin(), packed.end());
    }

    // Data pool — append ciphertexts back-to-back.
    const size_t data_pool_offset = section_buf.size();
    for (const auto& enc : encrypted) {
        section_buf.insert(section_buf.end(),
                           enc.ciphertext.begin(),
                           enc.ciphertext.end());
    }

    // (8) Add the section. SectionManager assigns the final RVA.
    //
    // The section holds both code (mx_str_get + trampolines) and data
    // (descriptor table + ciphertext pool). It must be WRITABLE because
    // the decryptor does an in-place XOR over the data pool on the first
    // call to each string, and it must also flip the sticky flag inside
    // the descriptor. MEM_EXECUTE lets the trampolines and mx_str_get
    // run. MEM_READ is included for clarity even though MEM_EXECUTE
    // implies it on x64.
    constexpr uint32_t str_section_characteristics =
        pe::IMAGE_SCN_CNT_CODE     |
        pe::IMAGE_SCN_MEM_EXECUTE  |
        pe::IMAGE_SCN_MEM_READ     |
        pe::IMAGE_SCN_MEM_WRITE;

    const std::string& str_section_name = ctx.section_names().str;
    SectionManager sec_mgr(image);
    auto add_res = sec_mgr.add_section(
        str_section_name,
        ByteView{section_buf.data(), section_buf.size()},
        str_section_characteristics);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const uint32_t added_idx  = *add_res;
    auto&          added_sec  = image.sections()[added_idx];
    const Rva      section_rva = added_sec.virtual_address;

    // (9) Patch the two rip+disp32 slots inside `mx_str_get`.
    //
    // mx_str_get is at section_rva + decryptor_offset. The disp32
    // offsets reported by the codegen are relative to the decryptor's
    // own first byte, so the absolute in-section offset is:
    //
    //     disp32_abs = decryptor_offset + disp32_offset_in_code
    //
    // The LEA's rel32 is computed from the END of the instruction,
    // which is the disp32 slot + 4:
    //
    //     lea_end_rva = section_rva + disp32_abs + 4
    //     rel32       = target_rva - lea_end_rva
    {
        const Rva desc_table_target_rva = section_rva + static_cast<Rva>(desc_table_offset);
        const Rva data_pool_target_rva  = section_rva + static_cast<Rva>(data_pool_offset);

        const size_t disp_desc_abs = decryptor_offset +
            emitted_decryptor.desc_table_disp32_offset;
        const size_t disp_data_abs = decryptor_offset +
            emitted_decryptor.data_base_disp32_offset;

        const Rva lea_end_rva_desc = section_rva + static_cast<Rva>(disp_desc_abs) + 4;
        const Rva lea_end_rva_data = section_rva + static_cast<Rva>(disp_data_abs) + 4;

        const int32_t rel_desc = static_cast<int32_t>(
            static_cast<int64_t>(desc_table_target_rva) -
            static_cast<int64_t>(lea_end_rva_desc));
        const int32_t rel_data = static_cast<int32_t>(
            static_cast<int64_t>(data_pool_target_rva) -
            static_cast<int64_t>(lea_end_rva_data));

        write_i32_le(added_sec.data, disp_desc_abs, rel_desc);
        write_i32_le(added_sec.data, disp_data_abs, rel_data);
    }

    // (10) Patch each trampoline's call rel32 → mx_str_get.
    {
        const Rva decryptor_target_rva = section_rva + static_cast<Rva>(decryptor_offset);
        for (size_t i = 0; i < trampolines.size(); ++i) {
            const size_t tr_off      = trampoline_offsets[i];
            const size_t call_rel_abs = tr_off + trampolines[i].call_rel32_offset;
            const Rva    call_end_rva = section_rva + static_cast<Rva>(call_rel_abs) + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(decryptor_target_rva) -
                static_cast<int64_t>(call_end_rva));
            write_i32_le(added_sec.data, call_rel_abs, rel);
        }
    }

    // (11) Rewrite each source LEA in place with `call trampoline_i`,
    //      pad with NOPs, then wipe the plaintext bytes.
    for (size_t i = 0; i < usable_xrefs.size(); ++i) {
        const auto& x           = usable_xrefs[i];
        const Rva   tramp_rva   = section_rva + static_cast<Rva>(trampoline_offsets[i]);
        rewrite_lea_as_call(image, x.xref_rva, x.insn_length, tramp_rva);
    }

    // (12) Wipe plaintext of every kept string. One wipe per string
    //      (not per xref) — the bytes are the same regardless of how
    //      many places reference them.
    for (const auto& ks : kept_strings) {
        wipe_plaintext(image, ks.rva_start, ks.length);
    }

    ctx.log_fmt(
        "StringProtectionPass: защищено {} строк, переписано {} LEA xref'ов, "
        "секция '{}' RVA=0x{:08X} размер={} байт",
        encrypted.size(),
        usable_xrefs.size(),
        str_section_name,
        section_rva,
        static_cast<uint32_t>(added_sec.data.size()));

    return {};
}

} // namespace mx
