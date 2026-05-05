/**
 * @file pe_image_binary_adapter.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/pe_image_binary_adapter.hpp"

#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe {

namespace {

/// PE `IMAGE_SCN_MEM_*` characteristics → `target::SectionFlags`.
[[nodiscard]] target::SectionFlags
to_section_flags(std::uint32_t characteristics) noexcept
{
    target::SectionFlags flags = target::SectionFlags::none;
    if (characteristics & IMAGE_SCN_MEM_READ)    flags = flags | target::SectionFlags::read;
    if (characteristics & IMAGE_SCN_MEM_WRITE)   flags = flags | target::SectionFlags::write;
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) flags = flags | target::SectionFlags::execute;
    if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        flags = flags | target::SectionFlags::zero_fill;
    return flags;
}

/// `target::SectionFlags` → PE `IMAGE_SCN_MEM_*` characteristics.
[[nodiscard]] std::uint32_t
to_pe_characteristics(target::SectionFlags flags) noexcept
{
    std::uint32_t out = 0;
    if (target::has_flag(flags, target::SectionFlags::read))      out |= IMAGE_SCN_MEM_READ;
    if (target::has_flag(flags, target::SectionFlags::write))     out |= IMAGE_SCN_MEM_WRITE;
    if (target::has_flag(flags, target::SectionFlags::execute))   out |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    if (target::has_flag(flags, target::SectionFlags::zero_fill)) out |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    if (out == 0) out = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    return out;
}

[[nodiscard]] target::SectionView
to_section_view(const SectionInfo& src)
{
    target::SectionView v;
    v.name         = src.name;
    v.segment.clear();  // PE has no per-section segment name.
    v.rva          = src.virtual_address;
    v.virtual_size = src.virtual_size;
    v.raw_size     = src.raw_size;
    v.flags        = to_section_flags(src.characteristics);
    v.data         = ByteView{src.data.data(), src.data.size()};
    return v;
}

} // namespace

std::vector<target::SectionView> PeImageBinaryAdapter::sections() const {
    const auto& src = image_.sections();
    std::vector<target::SectionView> out;
    out.reserve(src.size());
    for (const auto& s : src) {
        out.push_back(to_section_view(s));
    }
    return out;
}

MxResult<target::SectionView>
PeImageBinaryAdapter::find_section(std::string_view name) const {
    const auto* sec = image_.section_by_name(name);
    if (sec == nullptr) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_not_found,
            "Section '{}' not found", name));
    }
    return to_section_view(*sec);
}

MxResult<uint32_t>
PeImageBinaryAdapter::add_section(std::string_view name, ByteView data,
                                  target::SectionFlags flags)
{
    SectionInfo info;
    info.name            = std::string{name};
    info.data.assign(data.begin(), data.end());
    info.virtual_size    = static_cast<std::uint32_t>(data.size());
    info.characteristics = to_pe_characteristics(flags);
    return image_.add_section(std::move(info));
}

MxStatus PeImageBinaryAdapter::patch_section_bytes(
    uint32_t section_index, uint32_t offset, ByteView data)
{
    auto& sections = image_.sections();
    if (section_index >= sections.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Section index {} out of range (have {} sections)",
            section_index, sections.size()));
    }
    auto& sec = sections[section_index];
    if (offset + data.size() > sec.data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Patch [{}, {}) overflows section '{}' raw size {}",
            offset, offset + data.size(), sec.name, sec.data.size()));
    }
    std::copy(data.begin(), data.end(), sec.data.begin() + offset);
    return {};
}

} // namespace mx::pe
