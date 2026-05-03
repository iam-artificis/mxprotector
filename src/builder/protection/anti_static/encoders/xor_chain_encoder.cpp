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
    // The LEA sits 1 byte into the stub (after the leading
    // `push rax`), so its RIP-anchor is `stub_rva + 1 + 7`.
    const std::uint32_t K_xor = pick_positive_imm32(rng);
    const std::int32_t  K_add = pick_offset(rng);

    const std::int64_t standard_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 8);
    const auto encoded_disp = static_cast<std::int32_t>(standard_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    auto emit_xor_rax_imm = [&](std::uint32_t k) {
        out.bytes.push_back(0x48);
        out.bytes.push_back(0x35);
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &k, sizeof(k));
    };

    auto emit_addsub_rax_imm = [&](std::uint8_t modrm,
                                   std::int32_t k) {
        out.bytes.push_back(0x48);
        out.bytes.push_back(0x81);
        out.bytes.push_back(modrm);
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &k, sizeof(k));
    };

    // push rax — preserve caller's rax across the dispatch
    out.bytes.push_back(0x50);

    // lea rax, [rip + std_disp]
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x8D);
    out.bytes.push_back(0x05);
    out.disp32_byte_offset = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.resize(out.bytes.size() + 4);
    std::memcpy(out.bytes.data() + out.disp32_byte_offset,
                &encoded_disp, sizeof(encoded_disp));

    emit_xor_rax_imm(K_xor);                  // ^= K_xor
    emit_addsub_rax_imm(0xC0, K_add);         // += K_add (modrm /0)
    emit_addsub_rax_imm(0xE8, K_add);         // -= K_add (cancels)
    emit_xor_rax_imm(K_xor);                  // ^= K_xor (cancels)

    // xchg rax, [rsp]; ret — restore caller's rax, jump to target
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x87);
    out.bytes.push_back(0x04);
    out.bytes.push_back(0x24);
    out.bytes.push_back(0xC3);

    out.constant_offset = 0;
    return out;
}

} // namespace mx::protection::anti_static
