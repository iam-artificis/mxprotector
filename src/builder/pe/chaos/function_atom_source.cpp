/**
 * @file function_atom_source.cpp
 * @brief Implementation — see header.
 *
 * The `.pdata` directory is a packed array of `RUNTIME_FUNCTION`
 * records (3 DWORDs = 12 bytes per entry). We walk the array
 * end-to-end (size is in the data directory header), filter out
 * entries that fall outside the image (sentinel/terminator), and
 * emit one atom per surviving entry with the start/end alignment
 * adjustments described in the header.
 */

#include "mxprotector/pe/chaos/function_atom_source.hpp"

#include <algorithm>
#include <cstring>
#include <variant>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// One `RUNTIME_FUNCTION` slot is three RVAs = 12 bytes on x64.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

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

/// Read one `RUNTIME_FUNCTION` triple from `data` at `offset`.
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

/// Sanity-check a single entry. Linkers emit a zeroed terminator
/// at the end of the table; misaligned junk past the terminator
/// is also possible. Reject anything we cannot meaningfully
/// turn into an atom.
[[nodiscard]] bool entry_is_valid(
    const RuntimeFunction& rf,
    std::uint32_t          image_size_hint) noexcept
{
    if (rf.begin_address == 0 && rf.end_address == 0) return false;
    if (rf.end_address <= rf.begin_address)           return false;
    // RUNTIME_FUNCTION sizes top out around tens of KB even for
    // very large functions; anything larger is almost certainly a
    // malformed entry. Use a defensive 1 MiB cap.
    constexpr std::uint32_t kMaxFunctionBytes = 1u << 20;
    if (rf.end_address - rf.begin_address > kMaxFunctionBytes) return false;
    if (image_size_hint != 0 && rf.end_address > image_size_hint) return false;
    return true;
}

/// Round `value` DOWN to the nearest multiple of `alignment`.
[[nodiscard]] constexpr std::uint32_t align_down_u32(
    std::uint32_t value, std::uint32_t alignment) noexcept
{
    return value & ~(alignment - 1u);
}

/// Round `value` UP to the nearest multiple of `alignment`.
[[nodiscard]] constexpr std::uint32_t align_up_u32(
    std::uint32_t value, std::uint32_t alignment) noexcept
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

/// Compute a defensive image-size hint by summing every section's
/// `virtual_address + virtual_size` and taking the maximum. Used
/// only to reject `.pdata` entries that point past the image.
[[nodiscard]] std::uint32_t compute_image_size_hint(
    const PeImage& image) noexcept
{
    std::uint32_t end = 0;
    for (const auto& s : image.sections()) {
        end = std::max(end, s.virtual_address + s.virtual_size);
    }
    return end;
}

} // anonymous namespace

void FunctionAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_pdata_directory(image);
    if (loc.rva == 0 || loc.size < kRuntimeFunctionSize) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const auto off_in_section = loc.rva - sec->virtual_address;
    if (off_in_section + loc.size > sec->data.size()) return;

    const std::uint8_t* dir = sec->data.data() + off_in_section;
    const std::uint32_t entry_count = loc.size / kRuntimeFunctionSize;
    const auto image_size_hint = compute_image_size_hint(image);

    // Pass 1 — collect every valid `RUNTIME_FUNCTION` triple.
    std::vector<RuntimeFunction> entries;
    entries.reserve(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        const auto rf = read_one(dir, i * kRuntimeFunctionSize);
        if (!entry_is_valid(rf, image_size_hint)) continue;
        entries.push_back(rf);
    }
    if (entries.empty()) return;

    // Sort by start so adjacent entries cover adjacent address
    // ranges. The linker usually emits them sorted, but the spec
    // does not require it.
    std::sort(entries.begin(), entries.end(),
              [](const RuntimeFunction& a, const RuntimeFunction& b) {
                  return a.begin_address < b.begin_address;
              });

    // Pass 2 — emit one atom per function. The atom covers the
    // exact `.pdata` range PLUS any trailing `0xCC` (`INT 3`)
    // padding bytes up to the next 8-byte boundary, capped by the
    // start of the next function. Absorbing INT3 padding lets the
    // chunk planner treat the function as 8-aligned (movable) on
    // both ends — without it, the planner pins the function
    // because non-aligned movable atoms would split adjacent
    // 64-bit values across chunks. Real inter-function content
    // (link-time `JMP rel32` thunks, hot-patch pads) is never
    // `0xCC`, so the heuristic stops at the first non-`0xCC` byte
    // and leaves the rest to `CodeGapPinAtomSource`.
    //
    // We additionally try to round the start DOWN to an 8-aligned
    // RVA when the bytes immediately before the function start
    // are also `0xCC` filler (and not part of any preceding
    // function), so both ends become 8-aligned.
    constexpr std::uint8_t  kInt3        = 0xCC;
    constexpr std::uint32_t kAlignment   = 8;
    auto round_up = [&](std::uint32_t v) {
        return (v + kAlignment - 1u) & ~(kAlignment - 1u);
    };
    auto round_down = [&](std::uint32_t v) {
        return v & ~(kAlignment - 1u);
    };

    /// True when every byte at `[rva, rva + count)` reads as
    /// `0xCC` and the read does not cross a section boundary.
    auto all_int3 = [&](Rva rva, std::uint32_t count) -> bool {
        if (count == 0) return true;
        const auto* s = image.section_by_rva(rva);
        if (s == nullptr) return false;
        const auto off = rva - s->virtual_address;
        if (off + count > s->data.size()) return false;
        const std::uint8_t* p = s->data.data() + off;
        for (std::uint32_t k = 0; k < count; ++k) {
            if (p[k] != kInt3) return false;
        }
        return true;
    };

    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& rf = entries[i];
        const std::uint32_t size = rf.end_address - rf.begin_address;
        if (size == 0) continue;

        // Extend the END forward up to the next 8-aligned RVA, but
        // not past the start of the next function.
        const std::uint32_t target_end = round_up(rf.end_address);
        std::uint32_t end_cap = target_end;
        if (i + 1 < entries.size()) {
            end_cap = std::min(end_cap, entries[i + 1].begin_address);
        }
        std::uint32_t new_end = rf.end_address;
        if (end_cap > rf.end_address &&
            all_int3(static_cast<Rva>(rf.end_address),
                     end_cap - rf.end_address))
        {
            new_end = end_cap;
        }

        // Extend the START backward down to the previous 8-aligned
        // RVA, but not before the end of the previous function.
        const std::uint32_t target_start = round_down(rf.begin_address);
        std::uint32_t start_floor = target_start;
        if (i > 0) {
            start_floor = std::max(start_floor, entries[i - 1].end_address);
        }
        std::uint32_t new_start = rf.begin_address;
        if (start_floor < rf.begin_address &&
            all_int3(static_cast<Rva>(start_floor),
                     rf.begin_address - start_floor))
        {
            new_start = start_floor;
        }

        out.add(Atom{
            .start_rva = static_cast<Rva>(new_start),
            .size      = static_cast<std::uint32_t>(new_end - new_start),
            .origin    = AtomOrigin::instruction,
        });
    }
}

} // namespace mx::pe::chaos
