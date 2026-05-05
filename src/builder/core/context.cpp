/**
 * @file context.cpp
 * @brief Out-of-line definitions for `ProtectionContext`.
 *
 * @details The class is otherwise header-defined; this TU exists so
 *          the constructor can default-construct concrete classes
 *          (`pe::StandardLayout`, `pe::PeImageBinaryAdapter`) without
 *          forcing every translation unit that includes `context.hpp`
 *          to pull in their definitions. Keeping these out-of-line
 *          also gives a single anchor for the (small) vtables.
 */

#include "mxprotector/core/context.hpp"

#include "mxprotector/pe/layout/standard_layout.hpp"
#include "mxprotector/pe/pe_image_binary_adapter.hpp"

namespace mx {

ProtectionContext::ProtectionContext(
    std::unique_ptr<PeImage>                 image,
    ProtectionConfig                         config,
    std::shared_ptr<analysis::IDisassembler> disasm)
    : image_(std::move(image))
    , config_(std::move(config))
    , disasm_(std::move(disasm))
    , layout_policy_(std::make_unique<pe::StandardLayout>())
    , binary_adapter_(std::make_unique<pe::PeImageBinaryAdapter>(*image_, target_))
{}

ProtectionContext::~ProtectionContext() = default;

void ProtectionContext::set_target(target::TargetInfo info) noexcept {
    target_ = info;
    if (binary_adapter_) {
        binary_adapter_->set_target(info);
    }
}

target::IBinaryImage& ProtectionContext::binary_image() noexcept {
    return *binary_adapter_;
}

const target::IBinaryImage& ProtectionContext::binary_image() const noexcept {
    return *binary_adapter_;
}

} // namespace mx
