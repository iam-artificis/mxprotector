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

/// Emit a 20-byte atom for the descriptor at `desc_rva`.
void emit_descriptor_atom(Rva desc_rva, AtomTable& out) {
    out.add(Atom{
        .start_rva = desc_rva,
        .size      = kDescriptorSize,
        .origin    = AtomOrigin::import_descriptor,
    });
}

/// Walk the thunk array starting at `array_rva` (null-terminated)
/// and emit one 8-byte atom per slot, including the terminator.
/// For non-ordinal entries, also emit an atom for the
/// `IMAGE_IMPORT_BY_NAME` record they point at.
void scan_thunk_array(
    const PeImage&  image,
    Rva             array_rva,
    AtomTable&      out)
{
    if (array_rva == 0) return;

    Rva cursor = array_rva;
    for (std::uint32_t i = 0; i < 4096; ++i) {
        const auto thunk = read_thunk(image, cursor);
        if (!thunk) break;

        out.add(Atom{
            .start_rva = cursor,
            .size      = kThunkSize,
            .origin    = AtomOrigin::import_thunk,
        });

        if (*thunk == 0) break;  // null-terminator, stop walking

        if ((*thunk & pe::IMAGE_ORDINAL_FLAG64) == 0) {
            const auto by_name_rva = static_cast<std::uint32_t>(
                *thunk & 0xFFFFFFFFu);
            if (by_name_rva != 0) {
                // IMAGE_IMPORT_BY_NAME = Hint(2) + ASCIIZ Name +
                // optional 1-byte alignment padding. Walk to find
                // the terminator.
                const auto* sec = image.section_by_rva(by_name_rva);
                if (sec != nullptr) {
                    const auto base_off =
                        by_name_rva - sec->virtual_address;
                    if (base_off + 2 < sec->data.size()) {
                        // Find NUL after the Hint.
                        std::size_t name_off = base_off + 2;
                        while (name_off < sec->data.size() &&
                               sec->data[name_off] != 0)
                        {
                            ++name_off;
                        }
                        if (name_off < sec->data.size()) {
                            // Include hint + name + NUL.
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
}

void scan_one_descriptor(
    const PeImage&                     image,
    Rva                                desc_rva,
    const pe::IMAGE_IMPORT_DESCRIPTOR& d,
    AtomTable&                         out)
{
    emit_descriptor_atom(desc_rva, out);
    scan_thunk_array(image, d.OriginalFirstThunk, out);
    scan_thunk_array(image, d.FirstThunk,         out);
}

} // anonymous namespace

void ImportAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_import_directory(image);
    if (loc.rva == 0) return;

    const std::uint32_t max_entries = loc.size > 0
        ? loc.size / kDescriptorSize + 1
        : 1024;

    Rva cursor = loc.rva;
    for (std::uint32_t i = 0; i < max_entries; ++i) {
        const auto desc = read_descriptor(image, cursor);
        if (!desc) break;
        // Emit the descriptor atom regardless (the terminator must
        // also be pinned so the loader still finds the array end).
        emit_descriptor_atom(cursor, out);
        if (descriptor_is_terminator(*desc)) break;
        scan_thunk_array(image, desc->OriginalFirstThunk, out);
        scan_thunk_array(image, desc->FirstThunk,         out);
        cursor = static_cast<Rva>(cursor + kDescriptorSize);
    }
}

} // namespace mx::pe::chaos
