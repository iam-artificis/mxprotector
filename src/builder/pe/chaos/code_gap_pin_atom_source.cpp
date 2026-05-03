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

/// True when every byte at `[start, end)` reads as `0xCC` (`INT 3`)
/// inside `sec.data`. Used to identify pure-padding gaps that
/// `FunctionAtomSource` will absorb into the adjacent function
/// atom; we skip pinning them so the function atom stays movable.
[[nodiscard]] bool is_int3_only(
    const pe::SectionInfo& sec,
    Rva                    start,
    Rva                    end) noexcept
{
    if (end <= start) return true;
    if (start < sec.virtual_address) return false;
    const auto off = start - sec.virtual_address;
    const auto count = static_cast<std::size_t>(end - start);
    if (off + count > sec.data.size()) return false;
    const std::uint8_t* p = sec.data.data() + off;
    for (std::size_t k = 0; k < count; ++k) {
        if (p[k] != 0xCC) return false;
    }
    return true;
}

/// For one code section, emit pinned atoms covering every byte
/// that does NOT fall inside any `.pdata`-listed function range
/// AND that contains real (non-`0xCC`) content. Pure-`INT 3`
/// padding is left unpinned: `FunctionAtomSource` extends the
/// adjacent function's atom over that padding so the function
/// becomes 8-aligned at the boundary and can participate in the
/// shuffle as a movable chunk.
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
            if (!is_int3_only(sec, cursor, fn_start)) {
                emit_pin(cursor, fn_start, out);
            }
        }
        if (fn_end > cursor) cursor = fn_end;
    }
    if (cursor < sec_end) {
        if (!is_int3_only(sec, cursor, sec_end)) {
            emit_pin(cursor, sec_end, out);
        }
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
