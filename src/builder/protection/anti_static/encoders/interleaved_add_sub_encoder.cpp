/**
 * @file interleaved_add_sub_encoder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/protection/anti_static/encoders/interleaved_add_sub_encoder.hpp"

#include <cstring>

#include "mxprotector/core/randomizer.hpp"

namespace mx::protection::anti_static {

namespace {

[[nodiscard]] std::int32_t pick_nontrivial(Randomizer& rng) {
    std::int32_t k = 0;
    do {
        k = static_cast<std::int32_t>(rng.next_u32()) >> 4;
    } while (k > -0x100 && k < 0x100);
    return k;
}

void emit_add_rax_imm32(EncodedStub& out, std::int32_t imm) {
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x05);
    const std::size_t off = out.bytes.size();
    out.bytes.resize(off + 4);
    std::memcpy(out.bytes.data() + off, &imm, sizeof(imm));
}

void emit_sub_rax_imm32(EncodedStub& out, std::int32_t imm) {
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x2D);
    const std::size_t off = out.bytes.size();
    out.bytes.resize(off + 4);
    std::memcpy(out.bytes.data() + off, &imm, sizeof(imm));
}

} // anonymous namespace

EncodedStub InterleavedAddSubEncoder::emit(
    Rva         stub_rva,
    Rva         target_rva,
    Randomizer& rng) const
{
    const std::int32_t K1 = pick_nontrivial(rng);
    const std::int32_t K2 = pick_nontrivial(rng);
    const std::int32_t K3 = pick_nontrivial(rng);
    // Net effect: K1 - K2 + K3 - K4 = 0  ⇒  K4 = K1 - K2 + K3.
    const std::int32_t K4 = static_cast<std::int32_t>(
        static_cast<std::int64_t>(K1) -
        static_cast<std::int64_t>(K2) +
        static_cast<std::int64_t>(K3));

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

    emit_add_rax_imm32(out, K1);
    emit_sub_rax_imm32(out, K2);
    emit_add_rax_imm32(out, K3);
    emit_sub_rax_imm32(out, K4);

    out.bytes.push_back(0x48);
    out.bytes.push_back(0x87);
    out.bytes.push_back(0x04);
    out.bytes.push_back(0x24);
    out.bytes.push_back(0xC3);

    out.constant_offset = 0;
    return out;
}

} // namespace mx::protection::anti_static
