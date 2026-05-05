/**
 * @file rdtsc_timing_check.cpp
 * @brief Anti-emulation probe via RDTSC deltas.
 *
 * ### RdtscZeroDeltaCheck — catches Unicorn and most DBI frameworks
 *
 * Reads TSC twice with a short NOP sled in between. On real hardware
 * the delta is at least ~10 cycles (usually 20–80 depending on the
 * CPU family, CPU state, and surrounding instructions). On Unicorn
 * and several symbolic executors TSC is not simulated at all — both
 * reads return the same value and the delta is exactly 0.
 *
 * The check maps `delta == 0` → random non-zero corruption mask,
 * `delta != 0` → 0, and XORs the result into the handler-table key
 * slot. No branch, no visible check.
 *
 *     rdtsc                   ; eax = tsc1_low, edx clobbered
 *     mov ecx, eax
 *     nop; nop; nop; nop; nop; nop ; ~6-cycle delay on real HW
 *     rdtsc
 *     sub eax, ecx            ; eax = delta_low, ZF set if delta == 0
 *     neg eax                 ; CF set iff delta was non-zero
 *     sbb eax, eax            ; eax = 0 if delta == 0, -1 if delta != 0
 *     inc eax                 ; eax = 1 if delta == 0, 0 if delta != 0
 *     imul eax, eax, <mask>   ; eax = 0 or <mask>
 *     xor [rsp + disp], eax   ; no-op on real, corrupt on Unicorn
 *
 * ### RdtscHugeDeltaCheck — catches QEMU/Triton and slow emulators
 *
 * Same TSC bracket, but flags "suspiciously large" deltas instead of
 * zero. On real hardware 6 NOPs take roughly 10–100 cycles — so any
 * delta above ~50,000 means we're running in an emulator that doesn't
 * fast-path NOP. Also catches debugger single-step (each insn an
 * int3 + ptrace round-trip is much slower than the instruction itself).
 *
 *     rdtsc
 *     mov ecx, eax
 *     nop x6
 *     rdtsc
 *     sub eax, ecx            ; eax = delta
 *     cmp eax, 50000
 *     seta al                 ; al = 1 if delta > 50000
 *     movzx eax, al           ; zero-extend
 *     neg eax                 ; 0 or -1
 *     and eax, <mask>         ; 0 or <mask>
 *     xor [rsp + disp], eax
 */

#include "mxprotector/protection/anti_emulation/check.hpp"

#include <memory>

namespace mx::anti_emulation {

namespace {

/// Helper: emit `xor [rsp + disp8], eax`
/// Encoding: 31 44 24 disp8  (opcode=XOR r/m32, r32; ModRM: mod=01, reg=eax=0, rm=100 (SIB); SIB: scale=0 idx=100 base=100=rsp)
void emit_xor_rsp_disp8_eax(RawEmitter& e, int32_t disp) {
    e.u8(0x31);
    e.u8(0x44);
    e.u8(0x24);
    e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
}

} // anonymous namespace

class RdtscZeroDeltaCheck final : public ICheck {
public:
    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng) const override
    {
        // Random non-zero corruption mask — different every build so a
        // reverser can't pattern-match on a fixed immediate.
        const uint32_t corruption = rng.next_u32() | 1;

        //   0F 31                rdtsc
        //   89 C1                mov ecx, eax            ; save tsc1_low
        //   90 90 90 90 90 90    nop × 6                 ; delay
        //   0F 31                rdtsc
        //   29 C8                sub eax, ecx            ; eax = delta
        //   F7 D8                neg eax                 ; CF = (delta != 0)
        //   19 C0                sbb eax, eax            ; -CF
        //   FF C0                inc eax                 ; 1 if delta == 0
        //   69 C0 <mask32>       imul eax, eax, <mask>   ; 0 or mask
        //   31 44 24 <disp8>     xor [rsp + disp8], eax
        e.u8(0x0F); e.u8(0x31);
        e.u8(0x89); e.u8(0xC1);
        for (int i = 0; i < 6; ++i) e.u8(0x90);
        e.u8(0x0F); e.u8(0x31);
        e.u8(0x29); e.u8(0xC8);
        e.u8(0xF7); e.u8(0xD8);
        e.u8(0x19); e.u8(0xC0);
        e.u8(0xFF); e.u8(0xC0);
        e.u8(0x69); e.u8(0xC0); e.u32(corruption);
        emit_xor_rsp_disp8_eax(e, key_slot_disp);
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "rdtsc_zero_delta";
    }
};

class RdtscHugeDeltaCheck final : public ICheck {
public:
    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng) const override
    {
        const uint32_t corruption = rng.next_u32() | 1;

        // Threshold picked so real CPUs essentially never hit it but any
        // single-step or full-emulator backend trivially will. 50k cycles
        // is ~15 µs on a 3 GHz core — way beyond any straight-line NOP
        // sled.
        constexpr uint32_t kThreshold = 50000;

        //   0F 31                       rdtsc
        //   89 C1                       mov ecx, eax
        //   90 × 6                      nop × 6
        //   0F 31                       rdtsc
        //   29 C8                       sub eax, ecx           ; delta
        //   3D <thresh>                 cmp eax, thresh
        //   0F 97 C0                    seta al
        //   0F B6 C0                    movzx eax, al          ; 0 or 1
        //   F7 D8                       neg eax                ; 0 or -1
        //   25 <mask32>                 and eax, mask          ; 0 or mask
        //   31 44 24 <disp8>            xor [rsp + disp8], eax
        e.u8(0x0F); e.u8(0x31);
        e.u8(0x89); e.u8(0xC1);
        for (int i = 0; i < 6; ++i) e.u8(0x90);
        e.u8(0x0F); e.u8(0x31);
        e.u8(0x29); e.u8(0xC8);
        e.u8(0x3D); e.u32(kThreshold);
        e.u8(0x0F); e.u8(0x97); e.u8(0xC0);
        e.u8(0x0F); e.u8(0xB6); e.u8(0xC0);
        e.u8(0xF7); e.u8(0xD8);
        e.u8(0x25); e.u32(corruption);
        emit_xor_rsp_disp8_eax(e, key_slot_disp);
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "rdtsc_huge_delta";
    }
};

// Factory functions consumed by CheckRegistry.
std::unique_ptr<ICheck> make_rdtsc_zero_delta_check() {
    return std::make_unique<RdtscZeroDeltaCheck>();
}
std::unique_ptr<ICheck> make_rdtsc_huge_delta_check() {
    return std::make_unique<RdtscHugeDeltaCheck>();
}

} // namespace mx::anti_emulation
