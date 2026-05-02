/**
 * @file extend_in_place_sink.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/protection/mutation/overflow/extend_in_place_sink.hpp"

#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/protection/mutation/overflow/jmp_emit.hpp"

namespace mx::mutation::overflow {

namespace {

/// Default intent for the mutation overflow section: executable code
/// with read+execute access. Mutation engine never writes to it at
/// runtime — reads instructions, executes them, jumps back.
constexpr pe::SectionIntent kOverflowIntent{
    pe::SectionContentType::code,
    pe::SectionPermissions::rx,
};

/// Build `expanded_bytes` followed by a 5-byte placeholder for the
/// JMP-back. We patch the placeholder once the actual base RVA of the
/// allocated overflow section is known.
[[nodiscard]] ByteBuffer build_payload_with_placeholder(
    ByteView expanded_bytes)
{
    ByteBuffer payload;
    payload.reserve(expanded_bytes.size() + kJmpRel32Size);
    payload.assign(expanded_bytes.begin(), expanded_bytes.end());
    payload.resize(payload.size() + kJmpRel32Size, 0xCC);
    return payload;
}

/// Patch the trailing 5 bytes of `section_data` to encode a JMP from
/// `tail_rva` to `return_rva`. Pre-condition: `section_data` was just
/// extended by `kJmpRel32Size` bytes of placeholder.
void patch_jmp_back(
    ByteBuffer& section_data,
    Rva         tail_rva,
    Rva         return_rva)
{
    const auto jmp = encode_jmp_rel32(tail_rva, return_rva);
    const std::size_t off = section_data.size() - kJmpRel32Size;
    std::memcpy(section_data.data() + off, jmp.data(), jmp.size());
}

} // anonymous namespace

ExtendInPlaceSink::ExtendInPlaceSink(
    pe::SectionEmitter& emitter,
    std::string         section_name) noexcept
    : emitter_(emitter)
    , section_name_(std::move(section_name))
{}

MxResult<ExpansionPlan> ExtendInPlaceSink::plant(
    const ExpansionRequest& request)
{
    if (request.expanded_bytes.empty()) {
        return std::unexpected(error::pe(
            mx::PeErrorCode::section_alignment_violation,
            "ExtendInPlaceSink: пустой expanded_bytes"));
    }

    const Rva return_rva = static_cast<Rva>(
        request.site_rva + request.site_size);

    auto payload = build_payload_with_placeholder(request.expanded_bytes);

    if (!base_rva_.has_value()) {
        // Lazy first-call: allocate the overflow section. The bytes
        // are committed before we know the section's base RVA, so we
        // patch the JMP-back placeholder in-place after the allocation.
        auto add = emitter_.append_section(
            section_name_,
            ByteView{payload.data(), payload.size()},
            kOverflowIntent);
        if (!add) return std::unexpected(add.error());

        auto& sec = emitter_.image().sections()[*add];
        const Rva planted_rva = sec.virtual_address;
        const Rva tail_rva    = static_cast<Rva>(
            planted_rva + request.expanded_bytes.size());

        patch_jmp_back(sec.data, tail_rva, return_rva);
        base_rva_ = planted_rva;

        return ExpansionPlan{
            .overflow_rva  = planted_rva,
            .overflow_size = static_cast<std::uint32_t>(payload.size()),
        };
    }

    // Subsequent calls: append to the cached section. The new bytes
    // begin at offset = pre-grow size; the offset is returned by
    // `append_to_section`. We append the full payload (expanded +
    // placeholder JMP) and then patch the placeholder in place.
    auto offset_res = emitter_.append_to_section(
        section_name_,
        ByteView{payload.data(), payload.size()});
    if (!offset_res) return std::unexpected(offset_res.error());

    const auto& sections = emitter_.image().sections();
    const auto it = std::ranges::find_if(sections, [&](const auto& s) {
        return s.name == section_name_;
    });
    if (it == sections.end()) {
        return std::unexpected(error::pe_fmt(
            mx::PeErrorCode::section_not_found,
            "ExtendInPlaceSink: секция '{}' исчезла после append",
            section_name_));
    }

    const std::size_t offset = *offset_res;
    const Rva planted_rva = static_cast<Rva>(*base_rva_ + offset);
    const Rva tail_rva    = static_cast<Rva>(
        planted_rva + request.expanded_bytes.size());

    auto& mut_sec = emitter_.image().sections()[
        static_cast<std::size_t>(it - sections.begin())];
    patch_jmp_back(mut_sec.data, tail_rva, return_rva);

    return ExpansionPlan{
        .overflow_rva  = planted_rva,
        .overflow_size = static_cast<std::uint32_t>(payload.size()),
    };
}

std::string_view ExtendInPlaceSink::name() const noexcept {
    return "extend-in-place";
}

} // namespace mx::mutation::overflow
