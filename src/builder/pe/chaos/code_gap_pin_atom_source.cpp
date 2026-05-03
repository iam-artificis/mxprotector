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

/// For one code section, emit pinned atoms covering every byte
/// that does NOT fall inside any `.pdata`-listed function range.
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
            emit_pin(cursor, fn_start, out);
        }
        if (fn_end > cursor) cursor = fn_end;
    }
    if (cursor < sec_end) {
        emit_pin(cursor, sec_end, out);
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
