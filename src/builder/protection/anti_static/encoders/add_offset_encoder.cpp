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
    // The LEA disp32 is the LEA's RIP-relative offset to `target`.
    // The LEA sits 1 byte into the stub (after the leading
    // `push rax`), so `RIP_after_lea = stub_rva + 1 + 7 =
    // stub_rva + 8`.
    const std::int32_t K = pick_nontrivial_offset(rng);
    const std::int64_t standard_signed =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(stub_rva + 8);
    const auto encoded_disp = static_cast<std::int32_t>(standard_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    // push rax — save caller's rax so the dispatch is transparent
    // to `__chkstk`-style callers that pre-load rax with the
    // frame size.
    out.bytes.push_back(0x50);

    // lea rax, [rip + encoded_disp32]
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x8D);
    out.bytes.push_back(0x05);
    out.disp32_byte_offset = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.resize(out.bytes.size() + 4);
    std::memcpy(out.bytes.data() + out.disp32_byte_offset,
                &encoded_disp, sizeof(encoded_disp));

    // add rax, sign_ext(K)   (REX.W + 0x05 + imm32 — 6 bytes)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x05);
    {
        const auto kk = K;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &kk, sizeof(kk));
    }

    // sub rax, sign_ext(K)   (REX.W + 0x81 /5 + imm32 — 7 bytes;
    // cancels the add — chain is algebraically identity)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x81);
    out.bytes.push_back(0xE8);
    {
        const auto kk = K;
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &kk, sizeof(kk));
    }

    // xchg rax, [rsp]  (REX.W + 87 + ModRM 04 + SIB 24 — 4 bytes)
    // After this, rax = caller's saved rax, [rsp] = target VA.
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x87);
    out.bytes.push_back(0x04);
    out.bytes.push_back(0x24);

    // ret — pops target into RIP, jumps to the original callee.
    // The caller's RIP-after-call-to-stub now sits one slot
    // deeper on the stack and the eventual callee `ret` returns
    // to it as if we had called directly.
    out.bytes.push_back(0xC3);

    out.constant_offset = 0;
    return out;
}

} // namespace mx::protection::anti_static
