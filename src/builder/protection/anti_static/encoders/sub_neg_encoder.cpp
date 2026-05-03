/**
 * @file sub_neg_encoder.cpp
 * @brief Implementation — see header.
 *
 * Algebraic chain (after the `neg`/`neg` identity collapses):
 *
 *     rax = (RIP + encoded) - K
 *  ⇒  encoded = (target - RIP_after_lea) + K
 */

#include "mxprotector/protection/anti_static/encoders/sub_neg_encoder.hpp"

#include <cstring>

#include "mxprotector/core/randomizer.hpp"

namespace mx::protection::anti_static {

namespace {

[[nodiscard]] std::int32_t pick_offset(Randomizer& rng) {
    std::int32_t k = 0;
    do {
        k = static_cast<std::int32_t>(rng.next_u32()) >> 4;
    } while (k > -0x100 && k < 0x100);
    return k;
}

} // anonymous namespace

EncodedStub SubNegEncoder::emit(
    Rva         stub_rva,
    Rva         target_rva,
    Randomizer& rng) const
{
    const std::int32_t K = pick_offset(rng);

    // After chain: rax = (RIP + encoded) - K
    // We want target_rva ⇒ encoded = (target - RIP_after_lea) + K
    const std::int64_t encoded_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 7) +
        static_cast<std::int64_t>(K);
    const auto encoded_disp = static_cast<std::int32_t>(encoded_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    // lea rax, [rip + encoded_disp]
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x8D);
    out.bytes.push_back(0x05);
    out.disp32_byte_offset = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.resize(out.bytes.size() + 4);
    std::memcpy(out.bytes.data() + out.disp32_byte_offset,
                &encoded_disp, sizeof(encoded_disp));

    // neg rax  (REX.W + F7 /3 → ModRM 0xD8)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0xF7);
    out.bytes.push_back(0xD8);

    // neg rax (cancels the previous one — pure obfuscation flavour)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0xF7);
    out.bytes.push_back(0xD8);

    // sub rax, K   (REX.W + 81 /5 + imm32 — 7 bytes)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x81);
    out.bytes.push_back(0xE8);   // ModRM: /5 (sub) on rax
    {
        const auto kk = K;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &kk, sizeof(kk));
    }

    // jmp rax  (FF E0)
    out.bytes.push_back(0xFF);
    out.bytes.push_back(0xE0);

    // The chain reduces to `rax = (RIP + encoded) - K`. The
    // patcher needs an algebraic K such that
    // `disp32 = (target - slot - 4) - K`. For our chain that is
    // `K = -K_subtracted`, since `rax = (RIP + encoded) + (-K)`.
    out.constant_offset = -K;
    return out;
}

} // namespace mx::protection::anti_static
