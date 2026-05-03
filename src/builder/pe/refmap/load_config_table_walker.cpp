/**
 * @file load_config_table_walker.cpp
 * @brief Implementation — see header.
 */

#include "load_config_table_walker.hpp"

#include <algorithm>
#include <cstring>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

constexpr std::uint32_t kRvaSlotSize = sizeof(std::uint32_t);

/// Append a `byte4`/`rva`/`load_config_table_entry` ref. Zero target
/// is treated as a "no entry" hole and skipped.
void emit_entry_ref(
    Rva             slot_rva,
    std::uint32_t   target_rva,
    ReferenceTable& table)
{
    if (target_rva == 0) return;
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::load_config_table_entry,
    });
}

} // anonymous namespace

void walk_rva_function_table(
    const PeImage&  image,
    Rva             table_rva,
    std::uint64_t   count,
    std::uint32_t   stride,
    ReferenceTable& table)
{
    if (table_rva == 0 || count == 0 || stride < kRvaSlotSize) return;

    const auto* sec = image.section_by_rva(table_rva);
    if (sec == nullptr) return;

    const auto off       = table_rva - sec->virtual_address;
    const auto available = (sec->data.size() > off)
        ? sec->data.size() - off
        : 0;
    const std::uint64_t bounded = available / stride;
    const std::uint64_t walk    = std::min<std::uint64_t>(count, bounded);

    for (std::uint64_t i = 0; i < walk; ++i) {
        std::uint32_t entry_rva = 0;
        std::memcpy(&entry_rva,
                    sec->data.data() + off + i * stride,
                    kRvaSlotSize);
        emit_entry_ref(
            static_cast<Rva>(table_rva + i * stride),
            entry_rva, table);
    }
}

} // namespace mx::pe::refmap
