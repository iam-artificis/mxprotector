/**
 * @file sub_block_planner.cpp
 * @brief Implementation — see header.
 *
 * Two-pass walker per function (kept identical to the legacy logic
 * in `basic_block_atom_source.cpp` so both consumers see the same
 * splits):
 *
 *   1. Decode every instruction in `[BeginAddress, EndAddress)`.
 *      Record the byte offset immediately after each unconditional
 *      terminator (`RET` / `JMP`).
 *   2. Walk those candidate split points; keep only the ones that
 *      are `kSubBlockSplitAlignment`-aligned RVAs and emit one
 *      sub-block per surviving span.
 *
 * The trailing sub-block extends across the function's INT3 tail
 * padding up to the next 8-aligned RVA, capped by the next
 * function's start. The leading sub-block extends BACK over INT3
 * padding down to the previous 8-aligned RVA, capped by the
 * previous function's end. This is the same head/tail absorption
 * `FunctionAtomSource` performs.
 */

#include "mxprotector/pe/chaos/sub_block_planner.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <variant>

#include <Zydis/Zydis.h>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kRuntimeFunctionSize = 12;
constexpr std::uint8_t  kInt3                = 0xCC;
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

struct RuntimeFunction {
    std::uint32_t begin_address;
    std::uint32_t end_address;
    std::uint32_t unwind_data;
};

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

[[nodiscard]] std::vector<RuntimeFunction> collect_pdata_entries(
    const PeImage& image)
{
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

// ---------------------------------------------------------------------------
// Zydis wrapper
// ---------------------------------------------------------------------------

class ZydisX64Decoder {
public:
    ZydisX64Decoder() noexcept {
        ZydisDecoderInit(&decoder_,
                         ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64);
    }

    struct Decoded {
        std::uint8_t            length;
        ZydisInstructionCategory category;
    };

    [[nodiscard]] Decoded decode_one(
        const std::uint8_t* data, std::size_t remaining) noexcept
    {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        const auto status = ZydisDecoderDecodeFull(
            &decoder_, data, remaining, &insn, ops);
        if (!ZYAN_SUCCESS(status)) return {0, ZYDIS_CATEGORY_INVALID};
        return {insn.length, insn.meta.category};
    }

private:
    ZydisDecoder decoder_;
};

// ---------------------------------------------------------------------------
// Terminator classification
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

[[nodiscard]] std::vector<Rva> harvest_split_points(
    const PeImage& image, const RuntimeFunction& rf)
{
    std::vector<Rva> splits;
    const std::uint32_t size = rf.end_address - rf.begin_address;
    const auto* code = code_window(image,
                                   static_cast<Rva>(rf.begin_address), size);
    if (code == nullptr) return splits;

    ZydisX64Decoder decoder;
    std::uint32_t   off = 0;
    while (off < size) {
        const auto d = decoder.decode_one(code + off, size - off);
        if (d.length == 0) break;
        const std::uint32_t after = off + d.length;
        if (is_unconditional_terminator(d.category) && after < size) {
            splits.push_back(static_cast<Rva>(rf.begin_address + after));
        }
        off = after;
    }
    return splits;
}

// ---------------------------------------------------------------------------
// Tail / head INT3 absorption
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr std::uint32_t align_up_u32(
    std::uint32_t v, std::uint32_t a) noexcept
{
    return (v + a - 1u) & ~(a - 1u);
}

[[nodiscard]] constexpr std::uint32_t align_down_u32(
    std::uint32_t v, std::uint32_t a) noexcept
{
    return v & ~(a - 1u);
}

[[nodiscard]] bool all_int3(
    const PeImage& image, Rva rva, std::uint32_t count) noexcept
{
    if (count == 0) return true;
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return false;
    const auto off = rva - sec->virtual_address;
    if (static_cast<std::size_t>(off) + count > sec->data.size()) {
        return false;
    }
    const auto* p = sec->data.data() + off;
    for (std::uint32_t k = 0; k < count; ++k) {
        if (p[k] != kInt3) return false;
    }
    return true;
}

[[nodiscard]] std::uint32_t extend_tail(
    const PeImage& image, const RuntimeFunction& rf,
    std::uint32_t next_function_start)
{
    const std::uint32_t target_end = align_up_u32(
        rf.end_address, kSubBlockFunctionEndAlignment);
    const std::uint32_t cap = next_function_start == 0
        ? target_end
        : std::min(target_end, next_function_start);
    if (cap <= rf.end_address) return rf.end_address;
    if (!all_int3(image, static_cast<Rva>(rf.end_address),
                  cap - rf.end_address))
    {
        return rf.end_address;
    }
    return cap;
}

[[nodiscard]] std::uint32_t extend_head(
    const PeImage& image, const RuntimeFunction& rf,
    std::uint32_t prev_function_end)
{
    const std::uint32_t target_start = align_down_u32(
        rf.begin_address, kSubBlockFunctionEndAlignment);
    const std::uint32_t floor = std::max(target_start, prev_function_end);
    if (floor >= rf.begin_address) return rf.begin_address;
    if (!all_int3(image, static_cast<Rva>(floor),
                  rf.begin_address - floor))
    {
        return rf.begin_address;
    }
    return floor;
}

// ---------------------------------------------------------------------------
// Sub-block emission per function
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr bool is_split_aligned(Rva rva) noexcept {
    return (rva % kSubBlockSplitAlignment) == 0;
}

void emit_sub_blocks_for_function(
    const PeImage&         image,
    const RuntimeFunction& rf,
    std::uint32_t          function_index,
    std::uint32_t          prev_function_end,
    std::uint32_t          next_function_start,
    std::span<const Rva>   raw_splits,
    std::vector<SubBlock>& out)
{
    const Rva fn_start_with_head = static_cast<Rva>(
        extend_head(image, rf, prev_function_end));
    const Rva fn_end_with_tail = static_cast<Rva>(
        extend_tail(image, rf, next_function_start));

    const std::size_t first_emit = out.size();
    Rva run_start = fn_start_with_head;
    for (const Rva split : raw_splits) {
        if (split <= run_start)        continue;
        if (split >= fn_end_with_tail) break;
        if (!is_split_aligned(split))  continue;
        if (!is_split_aligned(run_start)) continue;
        out.push_back(SubBlock{
            .function_index = function_index,
            .start_rva      = run_start,
            .size           = static_cast<std::uint32_t>(split - run_start),
            .is_first       = false,
            .is_last        = false,
        });
        run_start = split;
    }
    out.push_back(SubBlock{
        .function_index = function_index,
        .start_rva      = run_start,
        .size           = static_cast<std::uint32_t>(
            fn_end_with_tail - run_start),
        .is_first       = false,
        .is_last        = false,
    });

    // Mark the first/last sub-block of this function — convenient
    // for downstream consumers that need to know which sub-block
    // owns the parent function's `BeginAddress` / `EndAddress`.
    if (first_emit < out.size()) {
        out[first_emit].is_first = true;
        out.back().is_last       = true;
    }
}

} // anonymous namespace

std::vector<SubBlock> plan_sub_blocks(const PeImage& image) {
    std::vector<SubBlock> out;
    const auto entries = collect_pdata_entries(image);
    if (entries.empty()) return out;

    out.reserve(entries.size() * 2);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& rf = entries[i];
        const std::uint32_t prev_end =
            (i > 0) ? entries[i - 1].end_address : 0;
        const std::uint32_t next_start =
            (i + 1 < entries.size()) ? entries[i + 1].begin_address : 0;
        const auto splits = harvest_split_points(image, rf);
        emit_sub_blocks_for_function(
            image, rf, static_cast<std::uint32_t>(i),
            prev_end, next_start,
            std::span<const Rva>{splits.data(), splits.size()},
            out);
    }
    return out;
}

} // namespace mx::pe::chaos
