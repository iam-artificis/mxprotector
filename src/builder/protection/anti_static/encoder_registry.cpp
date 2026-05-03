/**
 * @file encoder_registry.cpp
 * @brief Implementation — see header.
 *
 * The default-registry seed lives here so adding a new encoder is
 * exactly two lines: `#include` its header and one
 * `r.register_encoder(...)` call. No central enum to extend, no
 * factory switch.
 */

#include "mxprotector/protection/anti_static/encoder_registry.hpp"

#include <utility>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/anti_static/encoders/add_offset_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/xor_chain_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/sub_neg_encoder.hpp"

namespace mx::protection::anti_static {

void EncoderRegistry::register_encoder(
    std::unique_ptr<IIndirectCallEncoder> encoder)
{
    if (encoder == nullptr) return;
    encoders_.push_back(std::move(encoder));
}

const IIndirectCallEncoder* EncoderRegistry::pick(Randomizer& rng) const {
    if (encoders_.empty()) return nullptr;
    const auto idx = rng.next_range(
        0, static_cast<std::uint32_t>(encoders_.size()) - 1);
    return encoders_[idx].get();
}

const IIndirectCallEncoder* EncoderRegistry::find(
    std::string_view name) const noexcept
{
    for (const auto& e : encoders_) {
        if (e && e->name() == name) return e.get();
    }
    return nullptr;
}

EncoderRegistry make_default_registry() {
    EncoderRegistry r;
    r.register_encoder(std::make_unique<AddOffsetEncoder>());
    r.register_encoder(std::make_unique<XorChainEncoder>());
    r.register_encoder(std::make_unique<SubNegEncoder>());
    return r;
}

} // namespace mx::protection::anti_static
