/**
 * @file reference_patcher.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/reference_patcher.hpp"

#include <array>
#include <cstring>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// `width_bytes` for a `ReferenceWidth`.
[[nodiscard]] constexpr std::uint8_t width_bytes(ReferenceWidth w) noexcept {
    return static_cast<std::uint8_t>(w);
}

/// Encode the new target into a max-8-byte little-endian buffer.
/// The buffer's leading `width` bytes are the on-disk slot value.
[[nodiscard]] std::array<std::uint8_t, 8> encode_value(
    const Reference&      ref,
    Rva                   new_location,
    Rva                   new_target,
    std::uint64_t         image_base) noexcept
{
    std::array<std::uint8_t, 8> out{};
    const std::uint8_t            w = width_bytes(ref.width);

    switch (ref.encoding) {
        case ReferenceEncoding::rel: {
            const std::int64_t disp =
                static_cast<std::int64_t>(new_target) -
                static_cast<std::int64_t>(new_location + w);
            if (w == 1) {
                const auto v = static_cast<std::int8_t>(disp);
                std::memcpy(out.data(), &v, 1);
            } else if (w == 4) {
                const auto v = static_cast<std::int32_t>(disp);
                std::memcpy(out.data(), &v, 4);
            }
            // (rel8 / rel32 only — rel16 not encoded by any scanner.)
            break;
        }
        case ReferenceEncoding::rva: {
            const auto v = static_cast<std::uint32_t>(new_target);
            std::memcpy(out.data(), &v, 4);
            break;
        }
        case ReferenceEncoding::absolute_va: {
            const std::uint64_t v = image_base + new_target;
            std::memcpy(out.data(), &v, 8);
            break;
        }
        case ReferenceEncoding::rel32_call_pop_anchored: {
            // Anchor sits 4 bytes BEFORE the slot, not after — the
            // slot lives inside `add qword [rsp], imm32` whose `add`
            // RVA equals `slot_rva - 4`. That `add_rva` also equals
            // the byte right after the preceding `call $+5`, which
            // is the value the call pushed and the value the loader
            // sees as the rel anchor.
            const std::int64_t disp =
                static_cast<std::int64_t>(new_target) -
                (static_cast<std::int64_t>(new_location) - 4);
            const auto v = static_cast<std::int32_t>(disp);
            std::memcpy(out.data(), &v, 4);
            break;
        }
        case ReferenceEncoding::rel32_with_imm_offset: {
            // Encoded LEA disp32 inside an indirect-call stub: the
            // chain of operations following the LEA collapses to a
            // single algebraic add of `K` (signed int32, low 32 of
            // `aux`). To keep the chain resolving to the moved
            // target, the disp32 must subtract `K` from the
            // standard rel32 displacement.
            const auto k = static_cast<std::int32_t>(
                ref.aux & 0xFFFFFFFFu);
            const std::int64_t disp =
                static_cast<std::int64_t>(new_target) -
                static_cast<std::int64_t>(new_location + 4) -
                static_cast<std::int64_t>(k);
            const auto v = static_cast<std::int32_t>(disp);
            std::memcpy(out.data(), &v, 4);
            break;
        }
        case ReferenceEncoding::xor_encoded_signed_delta_imm32: {
            // Slot stores `(target_rva - jt_base_rva) XOR KEY` in 32
            // bits. Both `jt_base_rva` and `KEY` ride along in the
            // reference's `aux` field — the JT base is in `.rdata`
            // and stays put across the shuffle, so we recompute the
            // delta from the new target alone and re-encrypt.
            const auto jt_base = Reference::unpack_xor_jt_base(ref.aux);
            const auto key     = Reference::unpack_xor_key(ref.aux);
            const std::int32_t delta =
                static_cast<std::int32_t>(new_target) -
                static_cast<std::int32_t>(jt_base);
            const std::uint32_t encoded =
                static_cast<std::uint32_t>(delta) ^ key;
            std::memcpy(out.data(), &encoded, 4);
            break;
        }
    }
    return out;
}

/// Determine whether `rva` falls inside the PE header range
/// `[0, SizeOfHeaders)`.
[[nodiscard]] bool is_header_rva(
    const PeImage& image, Rva rva) noexcept
{
    std::uint32_t size_of_headers = 0;
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64> ||
                      std::is_same_v<NT, pe::IMAGE_NT_HEADERS32>)
        {
            size_of_headers = nt.OptionalHeader.SizeOfHeaders;
        }
    }, image.nt_headers());
    return rva < size_of_headers;
}

/// Write `count` bytes of `data` at `location_rva` inside the PE
/// header range. Implementation casts the NT-headers struct to a
/// byte buffer; both PE32 and PE32+ NT header types are PODs so the
/// memcpy is well-defined.
[[nodiscard]] bool write_to_headers(
    PeImage&             image,
    Rva                  location_rva,
    const std::uint8_t*  data,
    std::uint8_t         count) noexcept
{
    const Rva e_lfanew = static_cast<Rva>(image.dos_header().e_lfanew);
    if (location_rva < e_lfanew) return false;
    const std::uint32_t off_in_nt = location_rva - e_lfanew;

    bool wrote = false;
    std::visit([&](auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64> ||
                      std::is_same_v<NT, pe::IMAGE_NT_HEADERS32>)
        {
            if (off_in_nt + count <= sizeof(NT)) {
                std::memcpy(
                    reinterpret_cast<std::uint8_t*>(&nt) + off_in_nt,
                    data, count);
                wrote = true;
            }
        }
    }, image.nt_headers());
    return wrote;
}

/// Write `count` bytes into the section that contains `location_rva`.
[[nodiscard]] bool write_to_section(
    PeImage&             image,
    Rva                  location_rva,
    const std::uint8_t*  data,
    std::uint8_t         count) noexcept
{
    for (auto& sec : image.sections()) {
        const Rva sec_end = sec.virtual_address + sec.virtual_size;
        if (location_rva < sec.virtual_address || location_rva >= sec_end) {
            continue;
        }
        const std::uint32_t off = location_rva - sec.virtual_address;
        if (off + count > sec.data.size()) return false;
        std::memcpy(sec.data.data() + off, data, count);
        return true;
    }
    return false;
}

} // anonymous namespace

PatchStats ReferencePatcher::apply(
    PeImage&              image,
    const ReferenceTable& table,
    const RvaRemapper&    remapper) const
{
    PatchStats stats{};
    const std::uint64_t image_base = image.image_base();

    for (const auto& ref : table.slots()) {
        ++stats.total;

        const Rva new_location = remapper.remap(ref.location_rva);
        const Rva new_target   = remapper.remap(ref.target_rva);

        const auto value = encode_value(
            ref, new_location, new_target, image_base);
        const std::uint8_t w = width_bytes(ref.width);

        const bool wrote = is_header_rva(image, new_location)
            ? write_to_headers(image, new_location, value.data(), w)
            : write_to_section(image, new_location, value.data(), w);

        if (wrote) {
            ++stats.patched;
            if (is_header_rva(image, new_location)) {
                ++stats.header_writes;
            } else {
                ++stats.section_writes;
            }
        } else {
            ++stats.skipped;
        }
    }

    return stats;
}

} // namespace mx::pe::refmap
