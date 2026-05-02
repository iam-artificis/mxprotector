/**
 * @file chaos_layout.cpp
 * @brief Implementation of `ChaosLayout` — see header.
 */

#include "mxprotector/pe/layout/chaos_layout.hpp"

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_intent.hpp"

namespace mx::pe {

namespace {

/// Canonical chaos intent — every section claims to hold both code
/// and data and demands RWX runtime permissions.
constexpr SectionIntent kChaosIntent{
    SectionContentType::mixed_code_data,
    SectionPermissions::rwx,
};

/// The bit-mask that `make_section_characteristics` produces for
/// `kChaosIntent`. Computed as a `constexpr` constant so the
/// `finalize()` sweep does not redo the lookup per section.
constexpr std::uint32_t kChaosCharacteristics =
    make_section_characteristics(kChaosIntent);

} // anonymous namespace

SectionIntent ChaosLayout::resolve(
    std::string_view /*section_name*/,
    SectionIntent    /*requested*/) const noexcept
{
    return kChaosIntent;
}

MxStatus ChaosLayout::finalize(PeImage& image) const {
    for (auto& sec : image.sections()) {
        // OR the chaos bits in rather than overwriting wholesale —
        // some PE-format-level bits (e.g. discardable, shared)
        // belong to the build-time intent of the section and chaos
        // does not have an opinion on them. The intent we *do* care
        // about (CNT_CODE / CNT_DATA / MEM_READ / MEM_WRITE /
        // MEM_EXECUTE) gets unconditionally stamped.
        sec.characteristics |= kChaosCharacteristics;
    }
    return {};
}

std::string_view ChaosLayout::name() const noexcept {
    return "chaos";
}

} // namespace mx::pe
