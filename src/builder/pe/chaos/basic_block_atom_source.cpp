/**
 * @file basic_block_atom_source.cpp
 * @brief Implementation — see header.
 *
 * Two-pass walker per function:
 *
 *   1. Decode every instruction in `[BeginAddress, EndAddress)`.
 *      Record the byte offset immediately after each unconditional
 *      terminator (`RET`/`JMP`/`UD2`/`HLT`/`INT 1/3`/`IRET*`).
 *   2. Walk those candidate split points. Keep only the ones that
 *      are `kSplitAlignment`-aligned RVAs — the planner pins
 *      anything else as a "movable atom with un-aligned boundary".
 *      Emit one atom per surviving span; tail-extend the **last**
 *      sub-block over trailing `0xCC` (`INT 3`) padding the same
 *      way `FunctionAtomSource` does — so the function's tail run
 *      ends on an 8-aligned RVA.
 *
 * Functions that yield zero usable splits collapse to one atom
 * covering the whole `[BeginAddress, EndAddress)` plus tail
 * padding, identical to the function-source output. That is the
 * `LSP` fallback: callers that swap in this source pay no
 * granularity cost on functions where the algorithm finds nothing
 * to split.
 *
 * The Zydis category check (`ZYDIS_CATEGORY_RET` / `_UNCOND_BR` /
 * `_INTERRUPT`) gives the unconditional-terminator predicate
 * directly. We do **not** treat `CALL` as a terminator — `CALL`
 * does not transfer control unconditionally (the callee returns).
 */

#include "mxprotector/pe/chaos/basic_block_atom_source.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <variant>
#include <vector>

#include <Zydis/Zydis.h>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `RUNTIME_FUNCTION` slot is three RVAs = 12 bytes on x64.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

/// `INT 3` byte — the link-time padding compilers emit between
/// functions and after `RET` to fill out a 16-byte cache line.
constexpr std::uint8_t kInt3 = 0xCC;

/// Defensive cap for absurdly large `RUNTIME_FUNCTION` entries.
constexpr std::uint32_t kMaxFunctionBytes = 1u << 20;

// ---------------------------------------------------------------------------
// `.pdata` reading — duplicated locally (small, two-page helpers)
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
    const std::uint8_t* data,
    std::size_t         offset) noexcept
{
    RuntimeFunction rf{};
    std::memcpy(&rf, data + offset, sizeof(rf));
    return rf;
}

[[nodiscard]] bool entry_is_valid(
    const RuntimeFunction& rf,
    std::uint32_t          image_size_hint) noexcept
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

/// Stateless x64 long-mode decoder — matches the pattern used by
/// every other Zydis client in the chaos package.
class ZydisX64Decoder {
public:
    ZydisX64Decoder() noexcept {
        ZydisDecoderInit(&decoder_,
                         ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64);
    }

    /// Decode one instruction. Returns `(length, category)`.
    /// `length == 0` signals decode failure.
    struct Decoded {
        std::uint8_t            length;
        ZydisInstructionCategory category;
    };

    [[nodiscard]] Decoded decode_one(
        const std::uint8_t* data,
        std::size_t         remaining) noexcept
    {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        const auto status = ZydisDecoderDecodeFull(
            &decoder_, data, remaining, &insn, ops);
        if (!ZYAN_SUCCESS(status)) {
            return {0, ZYDIS_CATEGORY_INVALID};
        }
        return {insn.length, insn.meta.category};
    }

private:
    ZydisDecoder decoder_;
};

// ---------------------------------------------------------------------------
// Terminator classification
// ---------------------------------------------------------------------------

/// `true` when the decoded instruction transfers control
/// unconditionally — i.e. the bytes immediately AFTER it are not
/// reachable via implicit fall-through. Splitting a sub-block on
/// such a boundary needs no `JMP rel32` slack-after fixup.
///
/// The categories used here:
///   * `RET`         — `ret`, `retn imm16`, `retf`, `retf imm16`.
///   * `UNCOND_BR`   — `jmp <rel/r/m>` (NOT `jcc`).
///   * `INTERRUPT`   — `int 1`, `int 3`, `int imm8`, `into`, `iret*`.
///
/// `JCC` falls under `COND_BR` and is **excluded** — its fall-
/// through path needs slack. `CALL`/`SYSCALL` similarly fall through
/// (callee returns) and are excluded.
[[nodiscard]] bool is_unconditional_terminator(
    ZydisInstructionCategory cat) noexcept
{
    // Conservative split policy: only `RET` and `UNCOND_BR` (`JMP`).
    //
    // `INTERRUPT` (`INT 3` = `__debugbreak()`, `INT n`, `INTO`) is
    // EXCLUDED — `INT 3` raises a structured exception user code may
    // catch with SEH and resume past the breakpoint. Treating it as
    // a terminator would put unreachable bytes between the resume
    // target's `BeginAddress` patch and the actual resume RIP after
    // shuffle.
    //
    // `JCC` falls under `COND_BR` and is excluded — its fall-through
    // path needs explicit slack-after fixup, which is the
    // `FallThroughJmpFiller` story (B.4.18).
    //
    // **Important caveat (B.4.23.1 follow-up).** Even with this
    // conservative split set, the post-shuffle `.pdata`
    // `RUNTIME_FUNCTION` entry still describes one CONTIGUOUS
    // `[BeginAddress, EndAddress)` range. After chaos relocates
    // sub-blocks independently, that range no longer matches the
    // scattered bytes — the SEH unwinder fails to dispatch for any
    // RIP outside `BeginAddress`'s sub-block. Activating sub-
    // function splits requires emitting one extra `RUNTIME_FUNCTION`
    // per sub-block (with `UNW_FLAG_CHAININFO` linking back to the
    // parent unwind data). Until that machinery lands the source
    // remains built but UN-registered in `chaos_layout.cpp`.
    switch (cat) {
        case ZYDIS_CATEGORY_RET:
        case ZYDIS_CATEGORY_UNCOND_BR:
            return true;
        default:
            return false;
    }
}

// ---------------------------------------------------------------------------
// Function decoding + split-point harvesting
// ---------------------------------------------------------------------------

/// Locate the section containing `rva` and return a pointer to its
/// in-memory bytes for `[rva, rva + size)`. Returns `nullptr` on
/// any miss (no covering section, range past `data.size()`).
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

/// Collect post-terminator offsets within a single function. Each
/// emitted offset is the RVA OF THE FIRST BYTE AFTER the terminator
/// — i.e. a candidate split-point. Decode failures abort the walk
/// for that function (the conservative thing — a desync past a
/// failed decode produces meaningless category data).
[[nodiscard]] std::vector<Rva> harvest_split_points(
    const PeImage&         image,
    const RuntimeFunction& rf)
{
    std::vector<Rva> splits;
    const std::uint32_t size = rf.end_address - rf.begin_address;
    const auto* code = code_window(image,
                                   static_cast<Rva>(rf.begin_address),
                                   size);
    if (code == nullptr) return splits;

    ZydisX64Decoder decoder;
    std::uint32_t   off = 0;
    while (off < size) {
        const auto d = decoder.decode_one(code + off, size - off);
        if (d.length == 0) {
            // Decode failure — stop harvesting splits but keep the
            // surviving prefix. The caller's emit step will fall
            // back to "one atom for the whole function" if `splits`
            // ends up empty.
            break;
        }
        const std::uint32_t after = off + d.length;
        if (is_unconditional_terminator(d.category)) {
            // Final instruction — split point would equal the
            // function's `end_address`; that is not a useful "split"
            // because there is no sub-block after it. Skip.
            if (after < size) {
                splits.push_back(
                    static_cast<Rva>(rf.begin_address + after));
            }
        }
        off = after;
    }
    return splits;
}

// ---------------------------------------------------------------------------
// Tail-padding adjustment (last sub-block only)
// ---------------------------------------------------------------------------

/// Round `value` up to the next multiple of `alignment`.
[[nodiscard]] constexpr std::uint32_t align_up_u32(
    std::uint32_t value, std::uint32_t alignment) noexcept
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

/// Round `value` down to the nearest multiple of `alignment`.
[[nodiscard]] constexpr std::uint32_t align_down_u32(
    std::uint32_t value, std::uint32_t alignment) noexcept
{
    return value & ~(alignment - 1u);
}

/// `true` when every byte at `[rva, rva + count)` is `0xCC` and the
/// read does not cross a section boundary. Bytes past the section's
/// in-memory extent are NOT treated as `0xCC` — uninitialised
/// virtual-size tail is loader-zeroed, not INT3.
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

/// Extend the trailing sub-block end forward over `0xCC` padding
/// until the next 8-aligned RVA, capped by the next function's
/// start. Mirrors `FunctionAtomSource::all_int3` end-rounding so
/// last-sub-block alignment matches the function-source output.
[[nodiscard]] std::uint32_t extend_tail_with_int3(
    const PeImage&         image,
    const RuntimeFunction& rf,
    std::uint32_t          next_function_start)
{
    const std::uint32_t target_end = align_up_u32(
        rf.end_address, BasicBlockAtomSource::kFunctionEndAlignment);
    const std::uint32_t cap = next_function_start == 0
        ? target_end
        : std::min(target_end, next_function_start);
    if (cap <= rf.end_address) return rf.end_address;
    if (!all_int3(image,
                  static_cast<Rva>(rf.end_address),
                  cap - rf.end_address))
    {
        return rf.end_address;
    }
    return cap;
}

/// Extend the leading sub-block start backward over `0xCC` padding
/// down to the previous 8-aligned RVA, capped by the previous
/// function's end. Mirrors `FunctionAtomSource`'s start-rounding so
/// the first sub-block keeps the same boundary semantics as a
/// function atom would have produced.
[[nodiscard]] std::uint32_t extend_head_with_int3(
    const PeImage&         image,
    const RuntimeFunction& rf,
    std::uint32_t          prev_function_end)
{
    const std::uint32_t target_start = align_down_u32(
        rf.begin_address, BasicBlockAtomSource::kFunctionEndAlignment);
    const std::uint32_t floor =
        std::max(target_start, prev_function_end);
    if (floor >= rf.begin_address) return rf.begin_address;
    if (!all_int3(image,
                  static_cast<Rva>(floor),
                  rf.begin_address - floor))
    {
        return rf.begin_address;
    }
    return floor;
}

// ---------------------------------------------------------------------------
// Atom emission — one function at a time
// ---------------------------------------------------------------------------

/// `true` when `rva % kSplitAlignment == 0`.
[[nodiscard]] constexpr bool is_split_aligned(Rva rva) noexcept {
    return (rva % BasicBlockAtomSource::kSplitAlignment) == 0;
}

/// Emit one atom for a sub-block that starts at `start` and ends at
/// `end`. The atom's origin is `instruction` (movable, alignment 1).
void emit_run(Rva start, Rva end, AtomTable& out) {
    if (end <= start) return;
    out.add(Atom{
        .start_rva = start,
        .size      = static_cast<std::uint32_t>(end - start),
        .origin    = AtomOrigin::instruction,
    });
}

/// Walk the harvested split list for one function and emit atoms.
/// Splits whose RVA is NOT `kSplitAlignment`-aligned are dropped
/// because the planner would pin them.
///
/// The trailing sub-block extends across the function's INT3 tail
/// padding — same rounding behaviour as `FunctionAtomSource`.
void emit_function_atoms(
    const PeImage&         image,
    const RuntimeFunction& rf,
    std::uint32_t          prev_function_end,
    std::uint32_t          next_function_start,
    std::span<const Rva>   raw_splits,
    AtomTable&             out)
{
    const Rva fn_start_with_head = static_cast<Rva>(
        extend_head_with_int3(image, rf, prev_function_end));
    const Rva fn_end_with_tail = static_cast<Rva>(
        extend_tail_with_int3(image, rf, next_function_start));

    Rva run_start = fn_start_with_head;
    for (const Rva split : raw_splits) {
        if (split <= run_start)         continue;
        if (split >= fn_end_with_tail)  break;
        if (!is_split_aligned(split))   continue;
        if (!is_split_aligned(run_start)) {
            // The run's start itself is not aligned (function entry
            // not 4-aligned, very rare). The planner would pin the
            // resulting atom for boundary mismatch — fast-skip the
            // split and let the trailing emit cover the function as
            // one atom.
            continue;
        }
        emit_run(run_start, split, out);
        run_start = split;
    }
    emit_run(run_start, fn_end_with_tail, out);
}

} // anonymous namespace

void BasicBlockAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    const auto entries = collect_pdata_entries(image);
    if (entries.empty()) return;

    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& rf = entries[i];
        const std::uint32_t prev_end =
            (i > 0) ? entries[i - 1].end_address : 0;
        const std::uint32_t next_start =
            (i + 1 < entries.size()) ? entries[i + 1].begin_address : 0;
        const auto splits = harvest_split_points(image, rf);
        emit_function_atoms(image, rf, prev_end, next_start,
                            std::span<const Rva>{splits.data(), splits.size()},
                            out);
    }
}

} // namespace mx::pe::chaos
