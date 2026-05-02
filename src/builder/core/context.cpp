/**
 * @file context.cpp
 * @brief Out-of-line definitions for `ProtectionContext`.
 *
 * The class is otherwise header-defined; this TU exists so the
 * constructor can default-construct a concrete `pe::StandardLayout`
 * without forcing every translation unit that includes `context.hpp`
 * to also pull in the `StandardLayout` definition. R2.2 introduced
 * the `layout_policy_` field — initialising it here keeps the header
 * free of `<memory>` for `std::make_unique<StandardLayout>` and
 * gives a single anchor for the (small) standard-layout vtable.
 */

#include "mxprotector/core/context.hpp"

#include "mxprotector/pe/layout/standard_layout.hpp"

namespace mx {

ProtectionContext::ProtectionContext(
    std::unique_ptr<PeImage>                 image,
    ProtectionConfig                         config,
    std::shared_ptr<analysis::IDisassembler> disasm)
    : image_(std::move(image))
    , config_(std::move(config))
    , disasm_(std::move(disasm))
    , layout_policy_(std::make_unique<pe::StandardLayout>())
{}

} // namespace mx
