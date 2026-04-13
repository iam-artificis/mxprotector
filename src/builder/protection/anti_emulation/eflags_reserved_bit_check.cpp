/**
 * @file eflags_reserved_bit_check.cpp
 * @brief Anti-emulation probe via EFLAGS bit 1 — reserved, always reads 1.
 *
 * Intel SDM Vol. 1 §3.4.3: "Bit 1 of EFLAGS is reserved and always set
 * to 1." Real silicon enforces this invariant on every pushfq: the bit
 * cannot be cleared by software, and any read returns 1 unconditionally.
 * AMD64 manual mirrors the requirement.
 *
 * Several minimal emulators that synthesise EFLAGS from a "status flags
 * only" model fail this check: they only model CF/PF/AF/ZF/SF/OF and
 * leave every other bit (including the always-1 reserved bit 1) at zero
 * on every pushfq. That includes some custom decoders embedded in
 * unpacker scripts, and several didactic VM implementations.
 *
 *     9C                          pushfq
 *     58                          pop  rax
 *     83 E0 02                    and  eax, 2          ; isolate bit 1
 *     83 F0 02                    xor  eax, 2          ; 0 if bit was 1, 2 if bit was 0
 *     69 C0 <mask32>              imul eax, eax, mask  ; 0 or mask*2
 *     31 44 24 <disp8>            xor  [rsp + disp8], eax
 *
 * Real hardware: bit 1 reads back as 1 → eax = 2 → xor 2 → eax = 0
 * → corruption is 0 → no-op. Emulator that leaves bit 1 at 0:
 * eax = 0 → xor 2 → eax = 2 → imul → 2*mask → key slot poisoned.
 *
 * This check sits in the SAME family as `ac_flag_fidelity` (both
 * use pushfq round-trips to probe reserved bits) but tests a different
 * invariant: "bit 1 must be 1" vs. "bit 18 round-trips faithfully".
 * The CheckRegistry picks 1–2 checks per build at random, so over a
 * population of builds the two checks add real diversity without
 * either binary carrying both at once.
 *
 * Register usage.
 *   Clobbers rax. Caller (entry stub) treats rax as scratch — every
 *   guest GPR is already saved in a VM context slot.
 */

#include "mxprotector/protection/anti_emulation/check.hpp"

namespace mx::anti_emulation {

class EflagsReservedBitCheck final : public ICheck {
public:
    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng) const override
    {
        // Random non-zero corruption mask — different every build.
        const uint32_t corruption = rng.next_u32() | 1;

        // pushfq                       9C
        e.u8(0x9C);
        // pop rax                      58
        e.u8(0x58);
        // and eax, 2                   83 E0 02
        e.u8(0x83); e.u8(0xE0); e.u8(0x02);
        // xor eax, 2                   83 F0 02
        e.u8(0x83); e.u8(0xF0); e.u8(0x02);
        // imul eax, eax, <mask>        69 C0 mask32
        e.u8(0x69); e.u8(0xC0); e.u32(corruption);
        // xor [rsp + disp8], eax       31 44 24 disp8
        e.u8(0x31); e.u8(0x44); e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "eflags_reserved_bit";
    }
};

std::unique_ptr<ICheck> make_eflags_reserved_bit_check() {
    return std::make_unique<EflagsReservedBitCheck>();
}

} // namespace mx::anti_emulation
