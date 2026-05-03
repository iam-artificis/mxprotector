/**
 * @file import_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/import_atom_source.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kDescriptorSize =
    sizeof(pe::IMAGE_IMPORT_DESCRIPTOR);
constexpr std::uint32_t kThunkSize = sizeof(std::uint64_t);

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_import_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_IMPORT <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_IMPORT];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] std::optional<pe::IMAGE_IMPORT_DESCRIPTOR> read_descriptor(
    const PeImage& image, Rva desc_rva)
{
    const auto* sec = image.section_by_rva(desc_rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = desc_rva - sec->virtual_address;
    if (off + kDescriptorSize > sec->data.size()) return std::nullopt;
    pe::IMAGE_IMPORT_DESCRIPTOR d{};
    std::memcpy(&d, sec->data.data() + off, kDescriptorSize);
    return d;
}

[[nodiscard]] std::optional<std::uint64_t> read_thunk(
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

[[nodiscard]] bool descriptor_is_terminator(
    const pe::IMAGE_IMPORT_DESCRIPTOR& d) noexcept
{
    return d.OriginalFirstThunk == 0 &&
           d.TimeDateStamp      == 0 &&
           d.ForwarderChain     == 0 &&
           d.Name               == 0 &&
           d.FirstThunk         == 0;
}

/// Walk the thunk array starting at `array_rva` (null-terminated)
/// and emit:
///   * ONE atom covering the whole array (header through terminator
///     inclusive). The loader walks INT/IAT linearly, so the array
///     bytes must stay contiguous post-shuffle.
///   * One atom per non-ordinal entry's `IMAGE_IMPORT_BY_NAME`
///     record (these are pointed-to by RVA — they may travel
///     independently as long as the pointer is patched).
void scan_thunk_array(
    const PeImage&  image,
    Rva             array_rva,
    AtomTable&      out)
{
    if (array_rva == 0) return;

    Rva           cursor       = array_rva;
    std::uint32_t entry_count  = 0;
    const std::uint32_t kMaxThunks = 4096;
    for (std::uint32_t i = 0; i < kMaxThunks; ++i) {
        const auto thunk = read_thunk(image, cursor);
        if (!thunk) break;
        ++entry_count;
        if (*thunk == 0) break;          // terminator counted in size

        if ((*thunk & pe::IMAGE_ORDINAL_FLAG64) == 0) {
            const auto by_name_rva = static_cast<std::uint32_t>(
                *thunk & 0xFFFFFFFFu);
            if (by_name_rva != 0) {
                const auto* sec = image.section_by_rva(by_name_rva);
                if (sec != nullptr) {
                    const auto base_off =
                        by_name_rva - sec->virtual_address;
                    if (base_off + 2 < sec->data.size()) {
                        std::size_t name_off = base_off + 2;
                        while (name_off < sec->data.size() &&
                               sec->data[name_off] != 0)
                        {
                            ++name_off;
                        }
                        if (name_off < sec->data.size()) {
                            const std::uint32_t total =
                                static_cast<std::uint32_t>(
                                    name_off - base_off + 1);
                            out.add(Atom{
                                .start_rva = by_name_rva,
                                .size      = total,
                                .origin    = AtomOrigin::import_by_name,
                            });
                        }
                    }
                }
            }
        }

        cursor = static_cast<Rva>(cursor + kThunkSize);
    }

    if (entry_count > 0) {
        out.add(Atom{
            .start_rva = array_rva,
            .size      = entry_count * kThunkSize,
            .origin    = AtomOrigin::import_thunk,
        });
    }
}

} // anonymous namespace

void ImportAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_import_directory(image);
    if (loc.rva == 0) return;

    // Walk the descriptor array twice: once to count entries (so
    // we can emit the correct full-array atom size), once to
    // enumerate thunk arrays.
    const std::uint32_t max_entries = loc.size > 0
        ? loc.size / kDescriptorSize + 1
        : 1024;

    Rva           cursor      = loc.rva;
    std::uint32_t desc_count  = 0;
    for (std::uint32_t i = 0; i < max_entries; ++i) {
        const auto desc = read_descriptor(image, cursor);
        if (!desc) break;
        ++desc_count;
        if (descriptor_is_terminator(*desc)) break;
        scan_thunk_array(image, desc->OriginalFirstThunk, out);
        scan_thunk_array(image, desc->FirstThunk,         out);
        cursor = static_cast<Rva>(cursor + kDescriptorSize);
    }

    if (desc_count > 0) {
        // ONE atom covering the entire descriptor array — including
        // the all-zero terminator. The PE loader walks descriptors
        // linearly until it finds the terminator, so we must keep
        // the array contiguous.
        out.add(Atom{
            .start_rva = loc.rva,
            .size      = desc_count * kDescriptorSize,
            .origin    = AtomOrigin::import_descriptor,
        });
    }
}

} // namespace mx::pe::chaos
