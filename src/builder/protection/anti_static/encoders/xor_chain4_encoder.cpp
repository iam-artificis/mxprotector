/**
 * @file xor_chain4_encoder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/protection/anti_static/encoders/xor_chain4_encoder.hpp"

#include <cstring>

#include "mxprotector/core/randomizer.hpp"

namespace mx::protection::anti_static {

namespace {

[[nodiscard]] std::uint32_t pick_nontrivial(Randomizer& rng) {
    std::uint32_t k = 0;
    do {
        k = rng.next_u32();
    } while (k < 0x100u);  // avoid trivially-small constants
    return k;
}

/// Append the 6-byte short-form `xor rax, imm32` (`48 35 <imm32>`).
void emit_xor_rax_imm32(EncodedStub& out, std::uint32_t imm) {
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x35);
    const std::size_t off = out.bytes.size();
    out.bytes.resize(off + 4);
    std::memcpy(out.bytes.data() + off, &imm, sizeof(imm));
}

} // anonymous namespace

EncodedStub XorChain4Encoder::emit(
    Rva         stub_rva,
    Rva         target_rva,
    Randomizer& rng) const
{
    const std::uint32_t K1 = pick_nontrivial(rng);
    const std::uint32_t K2 = pick_nontrivial(rng);
    const std::uint32_t K3 = pick_nontrivial(rng);
    const std::uint32_t K4 = K1 ^ K2 ^ K3;

    const std::int64_t standard_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 8);
    const auto encoded_disp = static_cast<std::int32_t>(standard_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    out.bytes.push_back(0x50);

    out.bytes.push_back(0x48);
    out.bytes.push_back(0x8D);
    out.bytes.push_back(0x05);
    out.disp32_byte_offset = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.resize(out.bytes.size() + 4);
    std::memcpy(out.bytes.data() + out.disp32_byte_offset,
                &encoded_disp, sizeof(encoded_disp));

    emit_xor_rax_imm32(out, K1);
    emit_xor_rax_imm32(out, K2);
    emit_xor_rax_imm32(out, K3);
    emit_xor_rax_imm32(out, K4);

    out.bytes.push_back(0x48);
    out.bytes.push_back(0x87);
    out.bytes.push_back(0x04);
    out.bytes.push_back(0x24);
    out.bytes.push_back(0xC3);

    out.constant_offset = 0;
    return out;
}

} // namespace mx::protection::anti_static
