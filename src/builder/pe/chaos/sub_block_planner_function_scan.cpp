/**
 * @file sub_block_planner_function_scan.cpp
 * @brief Implementation of the input-gathering side of sub-block
 *        planning — see sub_block_planner_function_scan.hpp.
 *
 * Two responsibilities, both read-only against the input image:
 *   1. `.pdata` directory walk → vector of valid `RuntimeFunction`s.
 *   2. Per-function decode → split candidates and rel displacement
 *      spans.
 *
 * The byte-level decoding rules (which categories count as
 * unconditional terminators, which immediates qualify as rel
 * spans) match `basic_block_atom_source.cpp` byte-for-byte so
 * both consumers see the same splits.
 */

#include "sub_block_planner_function_scan.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <variant>

#include <Zydis/Zydis.h>

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kRuntimeFunctionSize = 12;
constexpr std::uint32_t kMaxFunctionBytes    = 1u << 20;

// ---------------------------------------------------------------------------
// `.pdata` reading
// ---------------------------------------------------------------------------

struct PdataLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] PdataLocation find_pdata_directory(
    const PeImage& image) noexcept
{
    PdataLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] RuntimeFunction read_one(
    const std::uint8_t* data, std::size_t offset) noexcept
{
    RuntimeFunction rf{};
    std::memcpy(&rf, data + offset, sizeof(rf));
    return rf;
}

[[nodiscard]] bool entry_is_valid(
    const RuntimeFunction& rf, std::uint32_t image_size_hint) noexcept
{
    if (rf.begin_address == 0 && rf.end_address == 0)         return false;
    if (rf.end_address <= rf.begin_address)                   return false;
    if (rf.end_address - rf.begin_address > kMaxFunctionBytes) return false;
    if (image_size_hint != 0 && rf.end_address > image_size_hint) {
        return false;
    }
    return true;
}

[[nodiscard]] std::uint32_t compute_image_size_hint(
    const PeImage& image) noexcept
{
    std::uint32_t end = 0;
    for (const auto& s : image.sections()) {
        end = std::max(end, s.virtual_address + s.virtual_size);
    }
    return end;
}

// ---------------------------------------------------------------------------
// Function decoding
// ---------------------------------------------------------------------------

/// `true` when the decoded instruction transfers control
/// unconditionally — see `basic_block_atom_source.cpp` for the
/// rationale (kept identical so the two consumers stay in sync).
[[nodiscard]] bool is_unconditional_terminator(
    ZydisInstructionCategory cat) noexcept
{
    switch (cat) {
        case ZYDIS_CATEGORY_RET:
        case ZYDIS_CATEGORY_UNCOND_BR:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] const std::uint8_t* code_window(
    const PeImage& image, Rva rva, std::uint32_t size) noexcept
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return nullptr;
    const auto off = rva - sec->virtual_address;
    if (static_cast<std::size_t>(off) + size > sec->data.size()) {
        return nullptr;
    }
    return sec->data.data() + off;
}

} // namespace

std::vector<RuntimeFunction> collect_pdata_entries(const PeImage& image) {
    std::vector<RuntimeFunction> out;
    if (!image.is_64bit()) return out;

    const auto loc = find_pdata_directory(image);
    if (loc.rva == 0 || loc.size < kRuntimeFunctionSize) return out;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return out;

    const auto off_in_section = loc.rva - sec->virtual_address;
    if (off_in_section + loc.size > sec->data.size()) return out;

    const std::uint8_t* dir       = sec->data.data() + off_in_section;
    const std::uint32_t entry_cnt = loc.size / kRuntimeFunctionSize;
    const auto          hint      = compute_image_size_hint(image);

    out.reserve(entry_cnt);
    for (std::uint32_t i = 0; i < entry_cnt; ++i) {
        const auto rf = read_one(dir, i * kRuntimeFunctionSize);
        if (entry_is_valid(rf, hint)) out.push_back(rf);
    }
    std::sort(out.begin(), out.end(),
              [](const RuntimeFunction& a, const RuntimeFunction& b) {
                  return a.begin_address < b.begin_address;
              });
    return out;
}

FunctionScan scan_function(const PeImage& image, const RuntimeFunction& rf) {
    FunctionScan out;
    const std::uint32_t size = rf.end_address - rf.begin_address;
    const auto* code = code_window(image,
                                   static_cast<Rva>(rf.begin_address), size);
    if (code == nullptr) return out;

    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder,
                     ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    std::uint32_t off = 0;
    while (off < size) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code + off, size - off, &insn, ops))) {
            break;
        }
        const std::uint32_t after = off + insn.length;

        // Harvest `rel` operand spans from this instruction. We
        // examine every operand for `IMM` types whose width is 8
        // or 32 bits and whose source was a relative immediate
        // (Zydis sets `imm.is_relative` for those).
        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const auto& op = ops[i];
            if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
            if (!op.imm.is_relative) continue;

            const auto& raw = insn.raw.imm[i];
            if (raw.size != 8 && raw.size != 32) continue;
            const Rva slot_rva = static_cast<Rva>(
                rf.begin_address + off + raw.offset);
            const std::int64_t disp = op.imm.value.s;
            const Rva target_rva = static_cast<Rva>(
                static_cast<std::int64_t>(rf.begin_address + after) + disp);
            if (target_rva < rf.begin_address ||
                target_rva > rf.end_address)
            {
                // Cross-function ref — split policy doesn't care:
                // the slot is inside the function, target outside,
                // any split inside the function leaves the slot
                // and target on opposite sides regardless. Skip.
                continue;
            }
            // The span is `[min(slot, target), max(slot, target)]`
            // — the slot and target byte positions. A split point
            // `S` breaks this span when `min < S <= max`, putting
            // the slot in one chunk and the target in another.
            out.rel_spans.push_back(RelRefSpan{
                .lo    = std::min(slot_rva, target_rva),
                .hi    = std::max(slot_rva, target_rva),
                .width = static_cast<std::uint8_t>(raw.size / 8),
            });
        }

        if (is_unconditional_terminator(insn.meta.category) &&
            after < size)
        {
            out.split_candidates.push_back(
                static_cast<Rva>(rf.begin_address + after));
        }
        off = after;
    }
    return out;
}

} // namespace mx::pe::chaos
