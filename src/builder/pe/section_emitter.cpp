/**
 * @file section_emitter.cpp
 * @brief Implementation of `SectionEmitter` — see header for rationale.
 */

#include "mxprotector/pe/section_emitter.hpp"

#include <algorithm>

#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe {

namespace {

/// Locate a section by exact name match. Returns the index or an
/// `MxError` so the caller can propagate via `MxResult`.
[[nodiscard]] MxResult<std::uint32_t> find_section_index(
    const PeImage&   image,
    std::string_view name)
{
    const auto& sections = image.sections();
    for (std::size_t i = 0; i < sections.size(); ++i) {
        if (sections[i].name == name) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return std::unexpected(mx::error::pe_fmt(
        mx::PeErrorCode::section_not_found,
        "section '{}' not found in image", name));
}

} // anonymous namespace

std::uint32_t SectionEmitter::characteristics_for(
    std::string_view name,
    SectionIntent    intent) const noexcept
{
    const SectionIntent resolved = policy_.resolve(name, intent);
    return make_section_characteristics(resolved);
}

MxResult<std::uint32_t> SectionEmitter::append_section(
    std::string_view name,
    ByteView         bytes,
    SectionIntent    intent)
{
    return mgr_.add_section(name, bytes, characteristics_for(name, intent));
}

MxResult<std::size_t> SectionEmitter::append_to_section(
    std::string_view name,
    ByteView         bytes)
{
    auto idx_res = find_section_index(mgr_.image(), name);
    if (!idx_res) return std::unexpected(idx_res.error());

    auto& section = mgr_.image().sections()[*idx_res];
    const std::size_t insertion_offset = section.data.size();

    // Growing the section requires updating both the in-memory
    // virtual_size and any sections that follow (their RVA / raw
    // offset must be recomputed). `SectionManager::resize_section`
    // owns that bookkeeping, so we use it instead of mutating
    // `section.data` directly — even when the caller asked for an
    // empty append (skip resize_section's work in that case so we
    // do not pointlessly recompute the layout).
    if (!bytes.empty()) {
        const std::uint32_t new_size = static_cast<std::uint32_t>(
            section.data.size() + bytes.size());
        auto status = mgr_.resize_section(*idx_res, new_size);
        if (!status) return std::unexpected(status.error());

        // Refresh the reference — `resize_section` may have moved
        // the underlying buffer.
        auto& grown = mgr_.image().sections()[*idx_res];
        std::copy(bytes.begin(), bytes.end(),
                  grown.data.begin() + static_cast<std::ptrdiff_t>(insertion_offset));
    }

    return insertion_offset;
}

MxResult<OverflowAllocation> SectionEmitter::allocate_overflow_section(
    std::string_view name,
    ByteView         bytes,
    SectionIntent    intent)
{
    auto add_res = append_section(name, bytes, intent);
    if (!add_res) return std::unexpected(add_res.error());

    const std::uint32_t idx = *add_res;
    const Rva base_rva = mgr_.image().sections()[idx].virtual_address;
    return OverflowAllocation{.section_index = idx, .base_rva = base_rva};
}

} // namespace mx::pe
