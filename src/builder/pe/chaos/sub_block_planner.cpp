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

/// One rel8 / rel32 reference observed inside a function — paired
/// `slot_rva` (the disp byte) and `target_rva` (where the jump
/// lands). Sub-block split points that fall STRICTLY BETWEEN
/// `min(slot, target)` and `max(slot, target)` would put the slot
/// in one chunk and the target in another; chaos relocates them
/// independently and the rel8 displacement overflows int8 range
/// (or even rel32 range though that is far rarer). The planner
/// drops such split points so the rel reference stays intra-chunk
/// and its disp value survives the shuffle byte-for-byte.
struct RelRefSpan {
    Rva           lo; ///< min(slot+1, target). slot+1 = byte AFTER disp.
    Rva           hi; ///< max(slot+1, target).
    std::uint8_t  width; ///< 1 or 4 — diagnostic only.
};

/// Decode the entire function and harvest:
///   * Candidate split points (one per unconditional terminator).
///   * `RelRefSpan`s for every `rel8` / `rel32` branch slot — these
///     span the slot-byte and target-byte and constrain where the
///     planner can split.
struct FunctionScan {
    std::vector<Rva>        split_candidates;
    std::vector<RelRefSpan> rel_spans;
};

[[nodiscard]] FunctionScan scan_function(
    const PeImage& image, const RuntimeFunction& rf)
{
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

[[nodiscard]] std::vector<Rva> harvest_split_points(
    const PeImage& image, const RuntimeFunction& rf)
{
    return scan_function(image, rf).split_candidates;
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

/// `true` when splitting the function at `split` would put a rel
/// slot in one sub-block and its target in another. Such a split
/// would force the chaos refmap to write a new disp into the slot,
/// and for `rel8` slots a cross-chunk distance overflows the int8
/// range — the patcher truncates and the jump lands on a wrong
/// byte (most often mid-instruction → illegal-instruction crash).
/// We refuse the split rather than break the jump.
[[nodiscard]] bool split_breaks_any_rel(
    Rva                          split,
    std::span<const RelRefSpan>  rel_spans) noexcept
{
    // Reject splits that would put the slot in one chunk and the
    // target in another. A split at `S` breaks the rel reference
    // when `lo < S <= hi` — the half-open boundary on the high
    // side is what lets us split RIGHT AT the rel's source byte
    // (slot strictly precedes the split) without breaking it.
    for (const auto& s : rel_spans) {
        if (s.lo < split && split <= s.hi) return true;
    }
    return false;
}

void emit_sub_blocks_for_function(
    const PeImage&              image,
    const RuntimeFunction&      rf,
    std::uint32_t               function_index,
    std::uint32_t               prev_function_end,
    std::uint32_t               next_function_start,
    std::span<const Rva>        raw_splits,
    std::span<const RelRefSpan> rel_spans,
    std::vector<SubBlock>&      out)
{
    const Rva fn_start_with_head = static_cast<Rva>(
        extend_head(image, rf, prev_function_end));
    const Rva fn_end_with_tail = static_cast<Rva>(
        extend_tail(image, rf, next_function_start));

    const std::size_t first_emit = out.size();
    Rva run_start = fn_start_with_head;
    for (const Rva split : raw_splits) {
        if (split <= run_start)         continue;
        if (split >= fn_end_with_tail)  break;
        if (!is_split_aligned(split))   continue;
        if (!is_split_aligned(run_start)) continue;
        if (split_breaks_any_rel(split, rel_spans)) continue;
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
        const auto scan = scan_function(image, rf);
        emit_sub_blocks_for_function(
            image, rf, static_cast<std::uint32_t>(i),
            prev_end, next_start,
            std::span<const Rva>{scan.split_candidates.data(),
                                 scan.split_candidates.size()},
            std::span<const RelRefSpan>{scan.rel_spans.data(),
                                        scan.rel_spans.size()},
            out);
    }
    return out;
}

} // namespace mx::pe::chaos
