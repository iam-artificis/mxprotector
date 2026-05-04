/**
 * @file structure_reference_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/structure_reference_scanner.hpp"

#include <cstddef>
#include <cstring>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// One `RUNTIME_FUNCTION` entry occupies twelve bytes — three
/// 32-bit RVAs (`BeginAddress`, `EndAddress`, `UnwindInfoAddress`).
constexpr std::uint32_t kRuntimeFunctionSize = 12;

/// Append one rva-style reference for a header-located slot.
void emit_header_rva_ref(
    Rva               location_rva,
    Rva               target_rva,
    ReferenceOrigin   origin,
    ReferenceTable&   table)
{
    table.add(Reference{
        .location_rva = location_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = origin,
    });
}

/// Locate `.pdata` bytes in the image, parse `RUNTIME_FUNCTION`
/// entries, and emit one reference per non-zero RVA field.
void scan_pdata(
    const PeImage&  image,
    Rva             pdata_rva,
    std::uint32_t   pdata_size,
    ReferenceTable& table)
{
    if (pdata_rva == 0 || pdata_size == 0) return;

    const auto* sec = image.section_by_rva(pdata_rva);
    if (sec == nullptr) return;

    const std::uint32_t off_in_section =
        pdata_rva - sec->virtual_address;
    if (off_in_section + pdata_size > sec->data.size()) {
        // Truncated `.pdata` — refuse to scan past the section's
        // physical bytes. Better to miss entries than to read OOB.
        return;
    }

    const std::uint32_t entry_count = pdata_size / kRuntimeFunctionSize;

    for (std::uint32_t i = 0; i < entry_count; ++i) {
        const Rva           entry_rva = static_cast<Rva>(
            pdata_rva + i * kRuntimeFunctionSize);
        const std::uint32_t entry_off = off_in_section
            + i * kRuntimeFunctionSize;

        std::uint32_t begin  = 0;
        std::uint32_t end    = 0;
        std::uint32_t unwind = 0;
        std::memcpy(&begin,  sec->data.data() + entry_off + 0, 4);
        std::memcpy(&end,    sec->data.data() + entry_off + 4, 4);
        std::memcpy(&unwind, sec->data.data() + entry_off + 8, 4);

        // Each non-zero field is a separate reference. The patcher
        // remaps the target through the chunk planner; if the
        // target's RVA didn't move, the remapper returns the input
        // unchanged.
        //
        // `EndAddress` uses `rva_end_exclusive` because its target
        // is the BYTE AFTER the function — for a function split
        // into sub-block atoms (B.4.23.1), that byte falls inside
        // the NEXT sub-block's chunk and a plain `rva` remap would
        // return the wrong value. The encoding remaps `target - 1`
        // (the last byte of the owning chunk) and adds 1, yielding
        // the correct end-exclusive RVA. For contiguous functions
        // whose `FunctionAtomSource` chunk absorbs trailing INT3
        // padding past `EndAddress`, the encoding's result equals
        // plain `rva` — `target - 1` and `target` map to the same
        // delta within the chunk.
        if (begin != 0) {
            emit_header_rva_ref(
                entry_rva + 0, begin,
                ReferenceOrigin::pdata_runtime_function, table);
        }
        if (end != 0) {
            table.add(Reference{
                .location_rva = static_cast<Rva>(entry_rva + 4),
                .target_rva   = static_cast<Rva>(end),
                .width        = ReferenceWidth::byte4,
                .encoding     = ReferenceEncoding::rva_end_exclusive,
                .origin       = ReferenceOrigin::pdata_runtime_function,
            });
        }
        if (unwind != 0) {
            emit_header_rva_ref(
                entry_rva + 8, unwind,
                ReferenceOrigin::pdata_runtime_function, table);
        }
    }
}

/// Walk the PE32+ NT headers and emit references for the entry
/// point and every non-empty `DataDirectory` entry; recurse into
/// `.pdata` if the EXCEPTION directory is populated.
void scan_pe32plus(
    const PeImage&                    image,
    const pe::IMAGE_NT_HEADERS64&     nt,
    Rva                               e_lfanew,
    ReferenceTable&                   table)
{
    const Rva opt_hdr_rva = static_cast<Rva>(
        e_lfanew + offsetof(pe::IMAGE_NT_HEADERS64, OptionalHeader));

    // 1. AddressOfEntryPoint.
    if (nt.OptionalHeader.AddressOfEntryPoint != 0) {
        emit_header_rva_ref(
            static_cast<Rva>(opt_hdr_rva +
                offsetof(pe::IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint)),
            nt.OptionalHeader.AddressOfEntryPoint,
            ReferenceOrigin::entry_point,
            table);
    }

    // 2. DataDirectory entries.
    const Rva data_dir_rva = static_cast<Rva>(opt_hdr_rva +
        offsetof(pe::IMAGE_OPTIONAL_HEADER64, DataDirectory));
    const std::uint32_t entry_limit = std::min(
        nt.OptionalHeader.NumberOfRvaAndSizes,
        pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    for (std::uint32_t i = 0; i < entry_limit; ++i) {
        const auto& dir = nt.OptionalHeader.DataDirectory[i];
        if (dir.VirtualAddress == 0) continue;
        emit_header_rva_ref(
            static_cast<Rva>(data_dir_rva +
                i * sizeof(pe::IMAGE_DATA_DIRECTORY)),
            dir.VirtualAddress,
            ReferenceOrigin::data_directory_entry,
            table);
    }

    // 3. `.pdata` RUNTIME_FUNCTION entries.
    if (pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION < entry_limit) {
        const auto& exc = nt.OptionalHeader.DataDirectory[
            pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        scan_pdata(image, exc.VirtualAddress, exc.Size, table);
    }
}

} // anonymous namespace

void StructureReferenceScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const Rva e_lfanew = static_cast<Rva>(image.dos_header().e_lfanew);

    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            scan_pe32plus(image, nt, e_lfanew, table);
        }
    }, image.nt_headers());
}

} // namespace mx::pe::refmap
