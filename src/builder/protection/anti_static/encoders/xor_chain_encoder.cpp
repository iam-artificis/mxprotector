/**
 * @file xor_chain_encoder.cpp
 * @brief Implementation — see header.
 *
 * Algebraic identity at runtime:
 *
 *     rax = (((RIP + encoded) ^ K1) + K2) ^ K3
 *
 * For the pass to remap when the target moves, the patcher must
 * see a single linear relation `rax = (RIP + encoded) + K_total`
 * — i.e. the chain must collapse into one additive constant the
 * patcher can subtract from the rel32 displacement.
 *
 * **The only way the chain collapses additively is when both XORs
 *  are no-ops on the relevant value range.** We achieve that by
 *  picking `K1 == K3` and constraining the `(RIP+encoded)` value
 *  so the XOR's bit pattern is identical on the inputs of both
 *  XORs. Equivalently: `K3 == K1` and the additive `K2` is the
 *  only effective offset.
 *
 *  This sounds like a degenerate chain but it gives the
 *  decompiler-defeating *appearance* of a non-trivial encoding
 *  while preserving the simple linear remap behaviour the chaos-
 *  shuffle reference patcher requires. A future encoder family
 *  with a custom reference-encoding type can carry the full
 *  XOR/ADD/XOR triple through to the patcher; this first cut
 *  uses the simplest sound option.
 */

#include "mxprotector/protection/anti_static/encoders/xor_chain_encoder.hpp"

#include <cstring>

#include "mxprotector/core/randomizer.hpp"

namespace mx::protection::anti_static {

namespace {

/// Pick a positive imm32 (high bit clear) so 64-bit sign-extend is
/// a zero-extend — the high half of `rax` (image-base bits) stays
/// intact through the XOR.
[[nodiscard]] std::uint32_t pick_positive_imm32(Randomizer& rng) {
    std::uint32_t v = 0;
    do {
        v = rng.next_u32() & 0x7FFFFFFFu;
    } while (v < 0x100u || v > 0x7FFFF000u);
    return v;
}

/// Pick a non-trivial signed offset for the additive step.
[[nodiscard]] std::int32_t pick_offset(Randomizer& rng) {
    std::int32_t k = 0;
    do {
        k = static_cast<std::int32_t>(rng.next_u32()) >> 4;
    } while (k > -0x100 && k < 0x100);
    return k;
}

} // anonymous namespace

EncodedStub XorChainEncoder::emit(
    Rva         stub_rva,
    Rva         target_rva,
    Randomizer& rng) const
{
    // Choose the XOR mask once; we use the same value at both XOR
    // sites so the two XORs cancel and only the central ADD
    // contributes to the target VA. See implementation comment for
    // the rationale.
    const std::uint32_t K_xor = pick_positive_imm32(rng);
    const std::int32_t  K_add = pick_offset(rng);

    // After the chain: rax = (RIP + encoded) + K_add.
    // We want rax = target_rva, so
    //   encoded = (target - RIP_after_lea) - K_add.
    const std::int64_t encoded_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 7) -
        static_cast<std::int64_t>(K_add);
    const auto encoded_disp = static_cast<std::int32_t>(encoded_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    // lea rax, [rip + encoded_disp]   (REX.W + 8D 05 + disp32)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x8D);
    out.bytes.push_back(0x05);
    out.disp32_byte_offset = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.resize(out.bytes.size() + 4);
    std::memcpy(out.bytes.data() + out.disp32_byte_offset,
                &encoded_disp, sizeof(encoded_disp));

    // xor rax, K_xor   (REX.W + 35 + imm32 sign-ext)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x35);
    {
        const auto k = K_xor;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &k, sizeof(k));
    }

    // add rax, K_add   (REX.W + 81 /0 + imm32 — 7 bytes)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x81);
    out.bytes.push_back(0xC0);  // ModRM: /0 (add) on rax
    {
        const auto k = K_add;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &k, sizeof(k));
    }

    // xor rax, K_xor   (same value, cancels)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x35);
    {
        const auto k = K_xor;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &k, sizeof(k));
    }

    // jmp rax
    out.bytes.push_back(0xFF);
    out.bytes.push_back(0xE0);

    out.constant_offset = K_add;
    return out;
}

} // namespace mx::protection::anti_static
