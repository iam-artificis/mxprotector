/**
 * @file grow_source_section_sink.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/protection/mutation/overflow/grow_source_section_sink.hpp"

#include <cstring>
#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/protection/mutation/overflow/jmp_emit.hpp"

namespace mx::mutation::overflow {

namespace {

/// Locate the section that contains `rva` (RVA falls within
/// `[sec.va, sec.va + sec.virtual_size)`). Returns nullopt when no
/// section matches — a programmer error in the caller (mutation pass
/// should never feed a site outside any section).
[[nodiscard]] const mx::pe::SectionInfo* find_section_for_rva(
    const PeImage& image, Rva rva) noexcept
{
    for (const auto& sec : image.sections()) {
        if (rva >= sec.virtual_address &&
            rva <  sec.virtual_address + sec.virtual_size)
        {
            return &sec;
        }
    }
    return nullptr;
}

/// Compute the available section-alignment slack at the section's
/// tail. `align_up(virtual_size, sa) - virtual_size`. Zero when the
/// section's `virtual_size` is already aligned.
[[nodiscard]] std::uint32_t compute_slack(
    const mx::pe::SectionInfo& sec,
    std::uint32_t              section_alignment) noexcept
{
    const std::uint32_t aligned = static_cast<std::uint32_t>(
        align_up(sec.virtual_size, section_alignment));
    return aligned - sec.virtual_size;
}

/// Build `expanded_bytes` followed by a `JMP rel32` from
/// `tail_rva` to `return_rva`. Pre-encoded so we can `append_to_section`
/// in one shot without a second post-write patch step.
[[nodiscard]] ByteBuffer build_payload(
    ByteView expanded_bytes,
    Rva      tail_rva,
    Rva      return_rva)
{
    ByteBuffer payload;
    payload.reserve(expanded_bytes.size() + kJmpRel32Size);
    payload.assign(expanded_bytes.begin(), expanded_bytes.end());
    const auto jmp = encode_jmp_rel32(tail_rva, return_rva);
    payload.insert(payload.end(), jmp.begin(), jmp.end());
    return payload;
}

} // anonymous namespace

GrowSourceSectionSink::GrowSourceSectionSink(
    pe::SectionEmitter& emitter) noexcept
    : emitter_(emitter)
{}

MxResult<ExpansionPlan> GrowSourceSectionSink::plant(
    const ExpansionRequest& request)
{
    if (request.expanded_bytes.empty()) {
        return std::unexpected(error::pe(
            mx::PeErrorCode::section_alignment_violation,
            "GrowSourceSectionSink: пустой expanded_bytes"));
    }

    const auto& image = emitter_.image();
    const auto* sec_const = find_section_for_rva(image, request.site_rva);
    if (sec_const == nullptr) {
        return std::unexpected(error::pe_fmt(
            mx::PeErrorCode::invalid_rva,
            "GrowSourceSectionSink: site RVA 0x{:08X} не принадлежит ни одной секции",
            request.site_rva));
    }

    const std::uint32_t payload_size = static_cast<std::uint32_t>(
        request.expanded_bytes.size() + kJmpRel32Size);

    const std::uint32_t slack = compute_slack(
        *sec_const, image.section_alignment());

    if (payload_size > slack) {
        // Slack-exhausted is a soft failure: the caller dispatches the
        // spill to a fallback sink (overflow / separate). Use the
        // dedicated error code so `FallbackSink` can discriminate it
        // from a genuine PE-format failure.
        return std::unexpected(error::pe_fmt(
            mx::PeErrorCode::section_slack_exhausted,
            "GrowSourceSectionSink: payload {} байт превышает slack {} в секции '{}'",
            payload_size, slack, sec_const->name));
    }

    // Pre-compute the planted RVA so the JMP-back can be encoded
    // before the bytes are written. The section's virtual_address
    // does not move during `append_to_section`, only its virtual_size,
    // so the planted RVA is fixed at the call site.
    const Rva planted_rva = static_cast<Rva>(
        sec_const->virtual_address + sec_const->data.size());
    const Rva tail_rva = static_cast<Rva>(
        planted_rva + request.expanded_bytes.size());
    const Rva return_rva = static_cast<Rva>(
        request.site_rva + request.site_size);

    auto payload = build_payload(
        request.expanded_bytes, tail_rva, return_rva);

    auto offset_res = emitter_.append_to_section(
        sec_const->name,
        ByteView{payload.data(), payload.size()});
    if (!offset_res) return std::unexpected(offset_res.error());

    return ExpansionPlan{
        .overflow_rva  = planted_rva,
        .overflow_size = static_cast<std::uint32_t>(payload.size()),
    };
}

std::string_view GrowSourceSectionSink::name() const noexcept {
    return "grow-source-section";
}

} // namespace mx::mutation::overflow
