/**
 * @file obfuscated_jt_scanner.cpp
 * @brief Implementation — see header.
 *
 * Phase split (kept identical to the legacy logic; only the file
 * boundary moved during R10):
 *   1. `find_dispatchers` (in `obfuscated_jt_dispatcher_matcher.cpp`)
 *      walks every code section, decodes with Zydis, and returns
 *      one `DispatcherSite` per match of the 7-instruction
 *      dispatcher pattern.
 *   2. This file walks the 4-byte slots starting at each
 *      `jt_base_rva`, decrypts each entry with `KEY`, sign-extends
 *      the result, and emits one reference per entry whose decoded
 *      target lands inside a code section.
 */

#include "mxprotector/pe/refmap/obfuscated_jt_scanner.hpp"

#include "obfuscated_jt_dispatcher_matcher.hpp"

#include <cstdint>
#include <cstring>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx::pe::refmap {

namespace {

/// Defensive cap on entries per single jump table.
constexpr std::uint32_t kMaxEntriesPerTable = 1024;

/// True when `target_rva` lands inside any code (executable) section.
[[nodiscard]] bool is_code_rva(
    const PeImage& image, Rva target_rva) noexcept
{
    for (const auto& s : image.sections()) {
        if (!s.is_code()) continue;
        if (target_rva >= s.virtual_address &&
            target_rva <  s.virtual_address + s.virtual_size)
        {
            return true;
        }
    }
    return false;
}

/// Read four little-endian bytes at `rva`.
[[nodiscard]] bool read_u32(
    const PeImage& image, Rva rva, std::uint32_t& out) noexcept
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return false;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint32_t) > sec->data.size()) return false;
    std::memcpy(&out, sec->data.data() + off, sizeof(out));
    return true;
}

/// Walk `kMaxEntriesPerTable` JT slots forward from `site.jt_base_rva`.
/// Stops at the first slot whose decoded target is not a valid code
/// RVA, or at `next_jt_rva` (when set).
void walk_jumptable_entries(
    const PeImage&         image,
    const DispatcherSite&  site,
    Rva                    next_jt_rva,
    ReferenceTable&        table)
{
    for (std::uint32_t i = 0; i < kMaxEntriesPerTable; ++i) {
        const Rva slot_rva = static_cast<Rva>(site.jt_base_rva + i * 4);
        if (next_jt_rva != 0 && slot_rva >= next_jt_rva) return;

        std::uint32_t encrypted = 0;
        if (!read_u32(image, slot_rva, encrypted)) return;

        const std::int32_t delta = static_cast<std::int32_t>(
            encrypted ^ site.key);
        const std::int64_t target_signed =
            static_cast<std::int64_t>(site.jt_base_rva) + delta;
        if (target_signed < 0) return;
        const auto target_rva = static_cast<Rva>(target_signed);
        if (!is_code_rva(image, target_rva)) return;

        Reference ref{
            .location_rva = slot_rva,
            .target_rva   = target_rva,
            .width        = ReferenceWidth::byte4,
            .encoding     = ReferenceEncoding::xor_encoded_signed_delta_imm32,
            .origin       = ReferenceOrigin::obfuscated_jt_entry,
        };
        ref.aux = Reference::pack_xor_aux(site.jt_base_rva, site.key);
        table.add(ref);
    }
}

} // anonymous namespace

void ObfuscatedJtScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto sites = find_dispatchers(image);
    for (std::size_t i = 0; i < sites.size(); ++i) {
        const Rva next = (i + 1 < sites.size())
            ? sites[i + 1].jt_base_rva
            : 0;
        walk_jumptable_entries(image, sites[i], next, table);
    }
}

} // namespace mx::pe::refmap
