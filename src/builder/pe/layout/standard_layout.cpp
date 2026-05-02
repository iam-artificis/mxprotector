/**
 * @file standard_layout.cpp
 * @brief Implementation of the default `ILayoutPolicy` — see header.
 *
 * The class is intentionally tiny: every method is a one-liner.
 * Keeping it in its own translation unit (rather than inlining in
 * the header) gives the linker a single anchor for the vtable, which
 * matters once the policy is held by `unique_ptr<ILayoutPolicy>` in
 * `ProtectionContext` — the standard library otherwise emits the
 * vtable in every TU that constructs the type.
 */

#include "mxprotector/pe/layout/standard_layout.hpp"

namespace mx::pe {

SectionIntent StandardLayout::resolve(
    std::string_view /*section_name*/,
    SectionIntent    requested) const noexcept
{
    return requested;
}

MxStatus StandardLayout::finalize(PeImage& /*image*/) const {
    return {};
}

std::string_view StandardLayout::name() const noexcept {
    return "standard";
}

} // namespace mx::pe
