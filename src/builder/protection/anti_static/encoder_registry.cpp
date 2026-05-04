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
#include "mxprotector/protection/anti_static/encoders/add_chain4_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/add_offset_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/add_offset_unbalanced_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/interleaved_add_sub_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/sub_neg_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/xor_chain4_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/xor_chain_encoder.hpp"

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
    // Foundation set — visible cancel mirrors. Kept for diversity:
    // a registry that mixes mirrored and non-mirrored encoders is
    // strictly harder to fingerprint than one with only one shape.
    r.register_encoder(std::make_unique<AddOffsetEncoder>());
    r.register_encoder(std::make_unique<XorChainEncoder>());
    r.register_encoder(std::make_unique<SubNegEncoder>());

    // Phase C — non-mirrored chains. Each constant is independently
    // random; a pattern matcher can't see the cancel structure
    // without a full constant-fold. Adding new encoders here is the
    // SOLID extension point — no edit to the pass, the registry, or
    // any downstream consumer.
    r.register_encoder(std::make_unique<AddChain4Encoder>());
    r.register_encoder(std::make_unique<XorChain4Encoder>());
    r.register_encoder(std::make_unique<InterleavedAddSubEncoder>());

    // Phase B.4.22 — fully **non-balanced** encoder. The LEA's
    // `disp32` does not decode to the target on its own; the chain
    // folds in a non-zero `K`. Its `constant_offset != 0` triggers
    // the `IndirectCallEncoderPass` `pre_scanned_refs` path so the
    // chaos refmap patches with the
    // `rel32_with_imm_offset` encoding. A static analyser must
    // constant-fold across two instructions to recover the target —
    // pure byte-pattern signatures fail.
    r.register_encoder(std::make_unique<AddOffsetUnbalancedEncoder>());
    return r;
}

} // namespace mx::protection::anti_static
