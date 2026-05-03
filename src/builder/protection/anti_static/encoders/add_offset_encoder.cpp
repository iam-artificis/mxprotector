/**
 * @file add_offset_encoder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/protection/anti_static/encoders/add_offset_encoder.hpp"

#include <cstring>

#include "mxprotector/core/randomizer.hpp"

namespace mx::protection::anti_static {

namespace {

/// Pick a signed int32 outside `[-0x10, 0x10]` so the additive
/// transformation is at least visually non-trivial. Range `[+/-
/// 0x10000000]` keeps the resulting `disp32 = target_disp - K`
/// well within int32 even for `target_disp` near the ±2 GiB edge.
[[nodiscard]] std::int32_t pick_nontrivial_offset(Randomizer& rng) {
    std::int32_t k = 0;
    do {
        const auto raw = static_cast<std::int32_t>(rng.next_u32());
        k = raw >> 4; // ~ ±0x0FFF_FFFF
    } while (k > -0x10 && k < 0x10);
    return k;
}

} // anonymous namespace

EncodedStub AddOffsetEncoder::emit(
    Rva         stub_rva,
    Rva         target_rva,
    Randomizer& rng) const
{
    const std::int32_t K = pick_nontrivial_offset(rng);

    // RIP after the 7-byte LEA = stub_rva + 7. We want
    // `target_rva = (stub_rva + 7) + encoded_disp + K`, so
    // `encoded_disp = (target_rva - stub_rva - 7) - K`.
    const std::int64_t encoded_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 7) -
        static_cast<std::int64_t>(K);
    const auto encoded_disp = static_cast<std::int32_t>(encoded_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    // lea rax, [rip + encoded_disp32]
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x8D);
    out.bytes.push_back(0x05);
    out.disp32_byte_offset = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.resize(out.bytes.size() + 4);
    std::memcpy(out.bytes.data() + out.disp32_byte_offset,
                &encoded_disp, sizeof(encoded_disp));

    // add rax, sign_ext(K)   (REX.W + 0x05 + imm32)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x05);
    {
        const auto kk = K;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &kk, sizeof(kk));
    }

    // jmp rax    (FF E0)
    out.bytes.push_back(0xFF);
    out.bytes.push_back(0xE0);

    out.constant_offset = K;
    return out;
}

} // namespace mx::protection::anti_static
