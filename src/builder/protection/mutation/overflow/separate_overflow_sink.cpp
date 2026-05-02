/**
 * @file separate_overflow_sink.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/protection/mutation/overflow/separate_overflow_sink.hpp"

#include <cstring>
#include <format>
#include <utility>

#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/protection/mutation/overflow/jmp_emit.hpp"

namespace mx::mutation::overflow {

namespace {

/// Default intent for an overflow section — RX code. Same rationale
/// as `ExtendInPlaceSink`: the engine reads + jumps, never writes.
constexpr pe::SectionIntent kOverflowIntent{
    pe::SectionContentType::code,
    pe::SectionPermissions::rx,
};

/// PE on-wire section name limit (`IMAGE_SIZEOF_SHORT_NAME`).
constexpr std::size_t kPeSectionNameMax = 8;

/// Build `expanded_bytes` followed by 5 placeholder bytes for the
/// JMP-back. The placeholder is patched once the section's base RVA
/// is known.
[[nodiscard]] ByteBuffer build_payload_with_placeholder(
    ByteView expanded_bytes)
{
    ByteBuffer payload;
    payload.reserve(expanded_bytes.size() + kJmpRel32Size);
    payload.assign(expanded_bytes.begin(), expanded_bytes.end());
    payload.resize(payload.size() + kJmpRel32Size, 0xCC);
    return payload;
}

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

SeparateOverflowSink::SeparateOverflowSink(
    pe::SectionEmitter& emitter,
    std::string         base_name) noexcept
    : emitter_(emitter)
    , base_name_(std::move(base_name))
{}

std::string SeparateOverflowSink::next_section_name() const {
    // Two-digit lowercase hex keeps every name ≤ 8 bytes given the
    // ≤ 6-byte base_name guarantee enforced at plant() time.
    return std::format("{}{:02x}", base_name_, next_index_);
}

MxResult<ExpansionPlan> SeparateOverflowSink::plant(
    const ExpansionRequest& request)
{
    if (request.expanded_bytes.empty()) {
        return std::unexpected(error::pe(
            mx::PeErrorCode::section_alignment_violation,
            "SeparateOverflowSink: пустой expanded_bytes"));
    }
    if (next_index_ >= kMaxSpillCount) {
        return std::unexpected(error::pe_fmt(
            mx::PeErrorCode::section_out_of_bounds,
            "SeparateOverflowSink: исчерпан лимит spill-секций ({})",
            kMaxSpillCount));
    }

    const auto sec_name = next_section_name();
    if (sec_name.size() > kPeSectionNameMax) {
        return std::unexpected(error::pe_fmt(
            mx::PeErrorCode::section_alignment_violation,
            "SeparateOverflowSink: имя секции '{}' длиннее {} байт",
            sec_name, kPeSectionNameMax));
    }

    const Rva return_rva = static_cast<Rva>(
        request.site_rva + request.site_size);

    auto payload = build_payload_with_placeholder(request.expanded_bytes);

    auto add = emitter_.append_section(
        sec_name,
        ByteView{payload.data(), payload.size()},
        kOverflowIntent);
    if (!add) return std::unexpected(add.error());

    auto& sec = emitter_.image().sections()[*add];
    const Rva planted_rva = sec.virtual_address;
    const Rva tail_rva    = static_cast<Rva>(
        planted_rva + request.expanded_bytes.size());

    patch_jmp_back(sec.data, tail_rva, return_rva);
    ++next_index_;

    return ExpansionPlan{
        .overflow_rva  = planted_rva,
        .overflow_size = static_cast<std::uint32_t>(payload.size()),
    };
}

std::string_view SeparateOverflowSink::name() const noexcept {
    return "separate-overflow";
}

} // namespace mx::mutation::overflow
