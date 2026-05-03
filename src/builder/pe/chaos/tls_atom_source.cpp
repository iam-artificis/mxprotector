/**
 * @file tls_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/tls_atom_source.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kTlsDirectorySize =
    sizeof(pe::IMAGE_TLS_DIRECTORY64);
constexpr std::uint32_t kCallbackEntrySize = sizeof(std::uint64_t);
constexpr std::uint32_t kOffAddressOfCallBacks = 24;

[[nodiscard]] Rva find_tls_directory_rva(const PeImage& image) noexcept {
    Rva result = 0;
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_TLS <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                result = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] std::optional<std::uint64_t> read_u64(
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

/// Compute the byte size of a null-terminated callback VA array
/// starting at `array_rva`. Returns 0 when the array is empty or
/// out-of-section.
[[nodiscard]] std::uint32_t callback_array_size(
    const PeImage& image, Rva array_rva)
{
    if (array_rva == 0) return 0;
    Rva cursor = array_rva;
    std::uint32_t entries = 0;
    for (std::uint32_t i = 0; i < 4096; ++i) {
        const auto v = read_u64(image, cursor);
        if (!v) return 0;
        ++entries;                  // count the entry itself
        if (*v == 0) break;          // null terminator counted as entry
        cursor = static_cast<Rva>(cursor + kCallbackEntrySize);
    }
    return entries * kCallbackEntrySize;
}

} // anonymous namespace

void TlsAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const Rva dir_rva = find_tls_directory_rva(image);
    if (dir_rva == 0) return;

    const auto* sec = image.section_by_rva(dir_rva);
    if (sec == nullptr) return;
    const auto off = dir_rva - sec->virtual_address;
    if (off + kTlsDirectorySize > sec->data.size()) return;

    // 1. Atom for the directory itself.
    out.add(Atom{
        .start_rva = dir_rva,
        .size      = kTlsDirectorySize,
        .origin    = AtomOrigin::tls_directory,
    });

    // 2. Atom for the callback array (when AddressOfCallBacks
    //    points inside the image).
    const auto callbacks_va = read_u64(image,
        static_cast<Rva>(dir_rva + kOffAddressOfCallBacks));
    if (!callbacks_va || *callbacks_va == 0) return;
    const auto image_base = image.image_base();
    if (*callbacks_va < image_base) return;

    const Rva array_rva = static_cast<Rva>(*callbacks_va - image_base);
    const std::uint32_t array_size = callback_array_size(image, array_rva);
    if (array_size == 0) return;

    out.add(Atom{
        .start_rva = array_rva,
        .size      = array_size,
        .origin    = AtomOrigin::tls_callback_array,
    });
}

} // namespace mx::pe::chaos
