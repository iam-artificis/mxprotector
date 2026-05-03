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

    // Pass 2 — emit one atom per function covering its EXACT
    // `.pdata` range. Critically, we do NOT pad start/end to a
    // larger alignment: doing so absorbs bytes adjacent to the
    // function (inter-function thunks, hot-patch pads, link-time
    // jump pads) into the atom. Those bytes are still real
    // instructions whose other half lives outside the atom,
    // and the shuffle would split them across non-contiguous
    // chunks. Aligning to function boundaries == aligning to
    // instruction boundaries, which is the strictest guarantee
    // the chaos shuffle can offer for code without rewriting
    // control flow.
    //
    // The atomic planner skips atoms whose boundaries are not
    // 8-aligned (passthrough), so functions whose entry isn't
    // 8-aligned simply don't shuffle. That's a strictly safe
    // choice — those functions execute from their original RVA.
    for (const auto& rf : entries) {
        const std::uint32_t size = rf.end_address - rf.begin_address;
        if (size == 0) continue;

        out.add(Atom{
            .start_rva = static_cast<Rva>(rf.begin_address),
            .size      = size,
            .origin    = AtomOrigin::instruction,
        });
    }
}

} // namespace mx::pe::chaos
