/**
 * @file add_offset_unbalanced_encoder.cpp
 * @brief Implementation — see header.
 *
 * `K` is drawn outside `[-0x10, 0x10]` so the additive
 * transformation is at least visually non-trivial. Range
 * `[+/- 0x0FFF_FFFF]` keeps the resulting `encoded_disp32 =
 * (target - lea_anchor) - K` well within `int32` even for
 * `target_disp` near the `±2 GiB` rel32 edge.
 */

#include "mxprotector/protection/anti_static/encoders/add_offset_unbalanced_encoder.hpp"

#include <cstring>

#include "mxprotector/core/randomizer.hpp"

namespace mx::protection::anti_static {

namespace {

/// Pick a signed int32 outside `[-0x10, 0x10]` so the LEA's
/// `disp32` differs visibly from the standard rel32 by at least
/// 16 bytes. Range is shifted right by 4 bits so the worst-case
/// `encoded_disp32 = standard_disp - K` cannot overflow an int32
/// for any rel32-reachable target.
[[nodiscard]] std::int32_t pick_nontrivial_offset(Randomizer& rng) {
    std::int32_t k = 0;
    do {
        const auto raw = static_cast<std::int32_t>(rng.next_u32());
        k = raw >> 4; // ~ ±0x0FFF_FFFF
    } while (k > -0x10 && k < 0x10);
    return k;
}

} // anonymous namespace

EncodedStub AddOffsetUnbalancedEncoder::emit(
    Rva         stub_rva,
    Rva         target_rva,
    Randomizer& rng) const
{
    const std::int32_t K = pick_nontrivial_offset(rng);

    // The LEA sits 1 byte into the stub (after `push rax`); its
    // disp32 occupies bytes 4..7, so RIP after the LEA is
    // `stub_rva + 8`. We want
    //   `rax_after_lea = (stub_rva + 8) + encoded_disp = target - K`
    // so that the next `add rax, K` makes `rax = target`.
    const std::int64_t lea_anchor = static_cast<std::int64_t>(stub_rva + 8);
    const std::int64_t encoded_signed =
        static_cast<std::int64_t>(target_rva) - lea_anchor -
        static_cast<std::int64_t>(K);
    const auto encoded_disp = static_cast<std::int32_t>(encoded_signed);

    EncodedStub out;
    out.bytes.reserve(stub_size());

    // push rax — save caller's rax so `__chkstk`-style callers
    // that pre-load rax keep their argument live across the dispatch.
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
        const std::size_t off = out.bytes.size();
        out.bytes.resize(off + 4);
        std::memcpy(out.bytes.data() + off, &K, sizeof(K));
    }

    // xchg rax, [rsp]  (REX.W + 0x87 + ModRM 04 + SIB 24 — 4 bytes)
    out.bytes.push_back(0x48);
    out.bytes.push_back(0x87);
    out.bytes.push_back(0x04);
    out.bytes.push_back(0x24);

    // ret — pops target into RIP and dispatches to the callee.
    out.bytes.push_back(0xC3);

    // Surface `K` so the emitting pass can register a
    // `PreScannedRefSlot` for the LEA's disp32 slot. The chaos
    // pipeline reads that slot and patches with the
    // `rel32_with_imm_offset` encoding.
    out.constant_offset = K;
    return out;
}

} // namespace mx::protection::anti_static
