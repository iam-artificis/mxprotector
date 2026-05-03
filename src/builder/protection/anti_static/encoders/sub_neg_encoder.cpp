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
    // The LEA sits 1 byte into the stub (after `push rax`) so the
    // RIP-anchor is `stub_rva + 1 + 7`.
    const std::int32_t K = pick_offset(rng);

    const std::int64_t standard_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 8);
    const auto encoded_disp = static_cast<std::int32_t>(standard_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    // push rax — preserve caller's rax
    out.bytes.push_back(0x50);

    // lea rax, [rip + std_disp]
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

    // neg rax (cancels)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0xF7);
    out.bytes.push_back(0xD8);

    // sub rax, K   (REX.W + 81 /5 + imm32 — 7 bytes)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x81);
    out.bytes.push_back(0xE8);
    {
        const auto kk = K;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &kk, sizeof(kk));
    }

    // add rax, K   (cancels SUB)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x05);
    {
        const auto kk = K;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &kk, sizeof(kk));
    }

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
