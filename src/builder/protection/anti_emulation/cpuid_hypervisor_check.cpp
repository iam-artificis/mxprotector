/**
 * @file cpuid_hypervisor_check.cpp
 * @brief Anti-emulation probe via CPUID.1:ECX[31] (hypervisor present bit).
 *
 * Intel reserved bit 31 of ECX in CPUID leaf 1 for the "hypervisor
 * present" indicator. It is 0 on bare metal, 1 whenever the CPU is
 * running under a hypervisor that sets it (all major hypervisors do:
 * KVM, Hyper-V, VMware, VirtualBox, Xen). It is also typically set by
 * user-mode emulators that report synthetic CPUID, including Unicorn's
 * default model and several sandbox products.
 *
 *     B8 01 00 00 00          mov eax, 1
 *     0F A2                   cpuid                    ; clobbers rax/rbx/rcx/rdx
 *     C1 E9 1F                shr ecx, 31              ; ecx = 0 or 1
 *     F7 D9                   neg ecx                  ; 0 or -1
 *     81 E1 <mask32>          and ecx, <mask>          ; 0 or mask
 *     31 4C 24 <disp8>        xor [rsp + disp8], ecx
 *
 * Register usage.
 *   CPUID clobbers rax, rbx, rcx, rdx unconditionally. This is fine in
 *   the entry stub where every GPR is already saved in a VM context
 *   slot — we're between "pushed reg → slot" and "first dispatch", so
 *   no live register values exist outside of rsp and the key slot.
 *
 * False-positive caveat.
 *   Legitimate users running this inside a hypervisor (e.g. a Windows
 *   guest on Hyper-V, WSL2, or a containerized VM) will ALSO trip the
 *   check and the program will crash. That's an accepted trade-off:
 *   the point of MxProtector is to resist reverse engineering, and
 *   "reverse engineering inside a hypervisor" is a very common RE
 *   setup we intentionally want to block. If you need the protected
 *   binary to run inside a legit VM, opt out of this specific check —
 *   a future CLI flag `--no-anti-vm` could disable it.
 */

#include "mxprotector/protection/anti_emulation/check.hpp"

namespace mx::anti_emulation {

class CpuidHypervisorCheck final : public ICheck {
public:
    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng) const override
    {
        const uint32_t corruption = rng.next_u32() | 1;

        // mov eax, 1              B8 01 00 00 00
        e.u8(0xB8); e.u32(1);
        // cpuid                   0F A2
        e.u8(0x0F); e.u8(0xA2);
        // shr ecx, 31             C1 E9 1F
        e.u8(0xC1); e.u8(0xE9); e.u8(0x1F);
        // neg ecx                 F7 D9
        e.u8(0xF7); e.u8(0xD9);
        // and ecx, imm32          81 E1 imm32
        e.u8(0x81); e.u8(0xE1); e.u32(corruption);
        // xor [rsp + disp8], ecx  31 4C 24 disp8
        //   ModRM: mod=01, reg=ecx=1, rm=100 (SIB)
        //   SIB:   scale=00, index=100 (none), base=100 (rsp)
        e.u8(0x31); e.u8(0x4C); e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "cpuid_hypervisor_bit";
    }
};

std::unique_ptr<ICheck> make_cpuid_hypervisor_check() {
    return std::make_unique<CpuidHypervisorCheck>();
}

} // namespace mx::anti_emulation
