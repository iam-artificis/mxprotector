/**
 * @file code_gap_pin_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/code_gap_pin_atom_source.hpp"

#include <algorithm>
#include <cstring>
#include <variant>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// One `RUNTIME_FUNCTION` triple is 3 × 4 bytes.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

struct FuncRange {
    Rva start;
    Rva end;  // exclusive
};

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

/// Read one `RUNTIME_FUNCTION` entry. Returns the (begin, end)
/// range; both `0` when the entry is the zero terminator some
/// linkers emit.
[[nodiscard]] FuncRange read_function_range(
    const std::uint8_t* dir, std::size_t entry_index) noexcept
{
    std::uint32_t begin = 0;
    std::uint32_t end   = 0;
    std::memcpy(&begin,
                dir + entry_index * kRuntimeFunctionSize + 0, 4);
    std::memcpy(&end,
                dir + entry_index * kRuntimeFunctionSize + 4, 4);
    return {static_cast<Rva>(begin), static_cast<Rva>(end)};
}

/// Walk the `.pdata` directory and return every valid function
/// `[begin, end)` range, sorted by start.
[[nodiscard]] std::vector<FuncRange> collect_function_ranges(
    const PeImage& image)
{
    std::vector<FuncRange> ranges;
    const auto loc = find_pdata_directory(image);
    if (loc.rva == 0 || loc.size < kRuntimeFunctionSize) return ranges;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return ranges;
    const auto off = loc.rva - sec->virtual_address;
    if (off + loc.size > sec->data.size()) return ranges;

    const std::uint8_t* dir = sec->data.data() + off;
    const std::uint32_t count = loc.size / kRuntimeFunctionSize;
    ranges.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto rf = read_function_range(dir, i);
        if (rf.start == 0 || rf.end <= rf.start) continue;
        ranges.push_back(rf);
    }
    std::sort(ranges.begin(), ranges.end(),
              [](const FuncRange& a, const FuncRange& b) noexcept {
                  return a.start < b.start;
              });
    return ranges;
}

/// Emit one pinned atom for the byte range `[start, end)`. Origin
/// `load_config_directory` carries the alignment-8 floor in the
/// policy table, which is what we want for "pinned, never moved".
void emit_pin(Rva start, Rva end, AtomTable& out) {
    if (end <= start) return;
    out.add(Atom{
        .start_rva = start,
        .size      = static_cast<std::uint32_t>(end - start),
        .origin    = AtomOrigin::load_config_directory,
    });
}

/// Returns `true` when the byte at section-offset `byte_offset`
/// (relative to `sec.virtual_address`) is inside any
/// `pe::DataRegion` registered on the section. Such bytes are
/// **structured data** (VM bytecode, jump tables, descriptor
/// tables) — even when they happen to be `0xCC` they must remain
/// pinned, because a movable chunk landing on top of them silently
/// corrupts the structure.
[[nodiscard]] bool byte_is_data_region(
    const pe::SectionInfo& sec, Rva byte_rva) noexcept
{
    for (const auto& dr : sec.data_regions) {
        if (byte_rva >= dr.begin_rva &&
            byte_rva <  dr.begin_rva + dr.size)
        {
            return true;
        }
    }
    return false;
}

/// Returns `true` when the byte falls inside any
/// `SectionInfo::movable_block`. Such bytes are *already* claimed
/// by `SectionMovableBlockAtomSource` as movable atoms; pinning
/// them here would let the strictest-alignment merge in
/// `AtomTable::normalize` upgrade them to pinned and cancel the
/// movability the emitting pass declared.
[[nodiscard]] bool byte_is_movable_block(
    const pe::SectionInfo& sec, Rva byte_rva) noexcept
{
    for (const auto& mb : sec.movable_blocks) {
        if (byte_rva >= mb.begin_rva &&
            byte_rva <  mb.begin_rva + mb.size)
        {
            return true;
        }
    }
    return false;
}

/// Walk `[start, end)` byte-by-byte and emit a pin atom for every
/// maximal sub-run of bytes that must remain at their original
/// RVA. A byte qualifies when:
///
///   * it is non-`0xCC` (real instruction or data), OR
///   * it falls inside a registered `pe::DataRegion` — even pure
///     `0xCC` bytes inside structured data must be pinned because
///     they are *not* INT 3 padding, they're a co-incidence in the
///     XOR-encrypted bytecode / handler table.
///
/// Outside the structured ranges, pure-`INT 3` runs are left
/// unpinned so they become passthrough — a chunk can land on top
/// of them without breaking anything (`INT 3` is unreachable code
/// by definition).
///
/// Splitting the gap byte-by-byte (instead of pinning the whole
/// gap whenever any byte is non-`0xCC`) is what lets the planner's
/// free ranges actually span multiple functions: a single 5-byte
/// `JMP rel32` thunk between two functions used to anchor a 256-
/// byte gap as one giant pin, which fragmented `.text` into 92
/// tiny free ranges with one chunk each — no permutation possible.
void pin_non_int3_subranges(
    const pe::SectionInfo& sec,
    Rva                    start,
    Rva                    end,
    AtomTable&             out)
{
    if (end <= start) return;
    if (start < sec.virtual_address) return;
    const auto off = start - sec.virtual_address;
    const auto count = static_cast<std::size_t>(end - start);
    if (off + count > sec.data.size()) return;

    const std::uint8_t* p = sec.data.data() + off;
    Rva cursor = start;
    Rva run_start = cursor;
    bool in_run = false;
    for (std::size_t k = 0; k < count; ++k, ++cursor) {
        // Bytes claimed by `SectionInfo::movable_blocks` are
        // already movable atoms — never pin them, otherwise the
        // strictest-alignment merge would silently upgrade them.
        if (byte_is_movable_block(sec, cursor)) {
            if (in_run) {
                emit_pin(run_start, cursor, out);
                in_run = false;
            }
            continue;
        }
        const bool keep = (p[k] != 0xCC)
                       || byte_is_data_region(sec, cursor);
        if (keep) {
            if (!in_run) { run_start = cursor; in_run = true; }
        } else {
            if (in_run) {
                emit_pin(run_start, cursor, out);
                in_run = false;
            }
        }
    }
    if (in_run) {
        emit_pin(run_start, cursor, out);
    }
}

/// For one code section, emit pinned atoms covering every byte
/// that does NOT fall inside any `.pdata`-listed function range
/// AND that contains real (non-`0xCC`) content. `INT 3` filler is
/// always left unpinned — `FunctionAtomSource` absorbs the bytes
/// adjacent to a function up to the next 4-aligned boundary, and
/// the rest become harmless passthrough that any movable chunk
/// can overlay without affecting executable behaviour.
void pin_gaps_in_code_section(
    const pe::SectionInfo&        sec,
    const std::vector<FuncRange>& funcs,
    AtomTable&                    out)
{
    const Rva sec_start = sec.virtual_address;
    const Rva sec_end   = static_cast<Rva>(sec.virtual_address +
                                           sec.virtual_size);

    Rva cursor = sec_start;
    for (const auto& f : funcs) {
        if (f.end <= sec_start) continue;
        if (f.start >= sec_end) break;

        const Rva fn_start = std::max(f.start, sec_start);
        const Rva fn_end   = std::min(f.end,   sec_end);
        if (cursor < fn_start) {
            pin_non_int3_subranges(sec, cursor, fn_start, out);
        }
        if (fn_end > cursor) cursor = fn_end;
    }
    if (cursor < sec_end) {
        pin_non_int3_subranges(sec, cursor, sec_end, out);
    }
}

} // anonymous namespace

void CodeGapPinAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto funcs = collect_function_ranges(image);
    for (const auto& sec : image.sections()) {
        if (!sec.is_code()) continue;
        if (sec.virtual_size == 0) continue;
        pin_gaps_in_code_section(sec, funcs, out);
    }
}

} // namespace mx::pe::chaos
