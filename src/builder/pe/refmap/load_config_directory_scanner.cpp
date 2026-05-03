/**
 * @file load_config_directory_scanner.cpp
 * @brief Implementation — see header.
 *
 * The CFG / IAT-taken / longjmp / EH-continuation / SEH function
 * tables are all walked the same way (4-byte RVA per record + an
 * optional metadata tail per `GuardFlags`), so the table walking is
 * factored into `load_config_table_walker.hpp`.
 */

#include "mxprotector/pe/refmap/load_config_directory_scanner.hpp"

#include <array>
#include <cstring>
#include <optional>
#include <variant>

#include "load_config_field_offsets.hpp"
#include "load_config_table_walker.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

constexpr std::uint32_t kVaSlotSize = sizeof(std::uint64_t);

/// Catalogue of every absolute-VA pointer slot in
/// IMAGE_LOAD_CONFIG_DIRECTORY64 we know how to scan.
struct VaSlot {
    std::uint32_t offset;
};

constexpr std::array<VaSlot, 21> kVaSlots = {{
    {40},  // LockPrefixTable
    {80},  // EditList
    {88},  // SecurityCookie
    {96},  // SEHandlerTable (32-bit only — usually 0 in 64-bit)
    {112}, // GuardCFCheckFunctionPointer
    {120}, // GuardCFDispatchFunctionPointer
    {128}, // GuardCFFunctionTable
    {160}, // GuardAddressTakenIatEntryTable
    {176}, // GuardLongJumpTargetTable
    {192}, // DynamicValueRelocTable
    {208}, // GuardRFFailureRoutine
    {216}, // GuardRFFailureRoutineFunctionPointer
    {232}, // GuardRFVerifyStackPointerFunctionPointer
    {248}, // EnclaveConfigurationPointer
    {256}, // VolatileMetadataPointer
    {264}, // GuardEHContinuationTable
    {280}, // GuardXFGCheckFunctionPointer
    {288}, // GuardXFGDispatchFunctionPointer
    {296}, // GuardXFGTableDispatchFunctionPointer
    {304}, // CastGuardOsDeterminedFailureMode
    {312}, // GuardMemcpyFunctionPointer
}};

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_load_config_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] std::optional<std::uint32_t> read_u32_at(
    const PeImage& image, Rva rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint32_t) > sec->data.size()) return std::nullopt;
    std::uint32_t v = 0;
    std::memcpy(&v, sec->data.data() + off, sizeof(v));
    return v;
}

[[nodiscard]] std::optional<std::uint64_t> read_u64_at(
    const PeImage& image, Rva rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint64_t) > sec->data.size()) return std::nullopt;
    std::uint64_t v = 0;
    std::memcpy(&v, sec->data.data() + off, sizeof(v));
    return v;
}

[[nodiscard]] std::optional<Rva> va_to_rva(
    std::uint64_t va, std::uint64_t image_base) noexcept
{
    if (va == 0)         return std::nullopt;
    if (va < image_base) return std::nullopt;
    return static_cast<Rva>(va - image_base);
}

void emit_directory_va(
    Rva slot_rva, Rva target_rva, ReferenceTable& table)
{
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte8,
        .encoding     = ReferenceEncoding::absolute_va,
        .origin       = ReferenceOrigin::load_config_directory,
    });
}

void scan_va_slots(
    const PeImage&  image,
    Rva             dir_rva,
    std::uint32_t   effective_size,
    ReferenceTable& table)
{
    const std::uint64_t image_base = image.image_base();
    for (const auto& slot : kVaSlots) {
        if (slot.offset + kVaSlotSize > effective_size) continue;
        const Rva slot_rva = static_cast<Rva>(dir_rva + slot.offset);
        const auto va = read_u64_at(image, slot_rva);
        if (!va) continue;
        const auto target = va_to_rva(*va, image_base);
        if (!target) continue;
        emit_directory_va(slot_rva, *target, table);
    }
}

[[nodiscard]] std::uint32_t compute_cfg_stride(
    const PeImage& image,
    Rva            dir_rva,
    std::uint32_t  effective_size)
{
    constexpr std::uint32_t kRvaSlotSize = sizeof(std::uint32_t);
    if (lcfg::kOffGuardFlags + kRvaSlotSize > effective_size) {
        return kRvaSlotSize;
    }
    const auto flags = read_u32_at(image,
        static_cast<Rva>(dir_rva + lcfg::kOffGuardFlags));
    if (!flags) return kRvaSlotSize;
    // `IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000`. The
    // stored value (bits 28..31) is the count of trailing metadata
    // bytes per entry beyond the 4-byte RVA.
    const std::uint32_t extra = (*flags >> 28) & 0xFu;
    return kRvaSlotSize + extra;
}

[[nodiscard]] std::optional<Rva> read_table_base(
    const PeImage& image,
    Rva            dir_rva,
    std::uint32_t  offset_in_dir,
    std::uint32_t  effective_size)
{
    if (offset_in_dir + kVaSlotSize > effective_size) return std::nullopt;
    const auto va = read_u64_at(image,
        static_cast<Rva>(dir_rva + offset_in_dir));
    if (!va) return std::nullopt;
    return va_to_rva(*va, image.image_base());
}

[[nodiscard]] std::optional<std::uint64_t> read_table_count(
    const PeImage& image,
    Rva            dir_rva,
    std::uint32_t  offset_in_dir,
    std::uint32_t  effective_size)
{
    if (offset_in_dir + kVaSlotSize > effective_size) return std::nullopt;
    return read_u64_at(image, static_cast<Rva>(dir_rva + offset_in_dir));
}

void scan_one_function_table(
    const PeImage&  image,
    Rva             dir_rva,
    std::uint32_t   effective_size,
    std::uint32_t   off_table,
    std::uint32_t   off_count,
    std::uint32_t   stride,
    ReferenceTable& table)
{
    const auto base  = read_table_base (image, dir_rva,
        off_table, effective_size);
    const auto count = read_table_count(image, dir_rva,
        off_count, effective_size);
    if (!base || !count) return;
    walk_rva_function_table(image, *base, *count, stride, table);
}

} // anonymous namespace

void LoadConfigDirectoryScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_load_config_directory(image);
    if (loc.rva == 0) return;

    // The LOAD_CONFIG block's *internal* `Size` (first 4 bytes) is
    // authoritative; the directory `Size` may report the same or a
    // larger reservation. Use the smaller of the two so we never
    // read past the linker's intended bounds.
    const auto inner_size = read_u32_at(image,
        static_cast<Rva>(loc.rva + lcfg::kOffSize));
    if (!inner_size) return;
    const std::uint32_t effective =
        loc.size > 0 ? std::min(loc.size, *inner_size) : *inner_size;

    scan_va_slots(image, loc.rva, effective, table);

    const std::uint32_t cfg_stride =
        compute_cfg_stride(image, loc.rva, effective);
    constexpr std::uint32_t kPlainRvaStride = sizeof(std::uint32_t);

    // CFG fids — stride = 4 + GuardFlags metadata.
    scan_one_function_table(image, loc.rva, effective,
        lcfg::kOffGuardCFFunctionTable,
        lcfg::kOffGuardCFFunctionCount,
        cfg_stride, table);

    // Address-taken IAT entries — same stride as CFG.
    scan_one_function_table(image, loc.rva, effective,
        lcfg::kOffGuardAddressTakenIatEntryTable,
        lcfg::kOffGuardAddressTakenIatEntryCount,
        cfg_stride, table);

    // Long-jump targets — same stride as CFG.
    scan_one_function_table(image, loc.rva, effective,
        lcfg::kOffGuardLongJumpTargetTable,
        lcfg::kOffGuardLongJumpTargetCount,
        cfg_stride, table);

    // EH continuation — pure 4-byte RVA per entry.
    scan_one_function_table(image, loc.rva, effective,
        lcfg::kOffGuardEHContinuationTable,
        lcfg::kOffGuardEHContinuationCount,
        kPlainRvaStride, table);

    // SE handler — 32-bit only, but harmless to walk on x64.
    scan_one_function_table(image, loc.rva, effective,
        lcfg::kOffSEHandlerTable,
        lcfg::kOffSEHandlerCount,
        kPlainRvaStride, table);
}

} // namespace mx::pe::refmap
