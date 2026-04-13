/**
 * @file check.hpp
 * @brief Abstract anti-emulation check emitter.
 *
 * A "check" is a short machine-code sequence that examines some CPU or OS
 * property that a correct real-hardware execution always satisfies, and
 * that known emulators (Unicorn, Triton, angr, QEMU user mode, Frida
 * ...) typically fail to reproduce. Every check follows the same
 * contract:
 *
 *   1. Run the probe.
 *   2. Compute a 32-bit result that is **0** on real hardware and
 *      **non-zero** under emulation.
 *   3. XOR that result directly into the handler-table key slot on the
 *      stack: `xor [rsp + key_slot_disp], <reg>`.
 *
 * The key slot was initialized earlier by the MBA chain. On real
 * hardware every check XORs 0, the slot is unchanged, and VM dispatches
 * decrypt the handler table correctly. Under any emulator that trips a
 * check, the slot is silently corrupted, and every subsequent VM
 * dispatch XORs the opcode table entry with the wrong key → jumps
 * land on garbage → first opcode crashes. There is **no branch** the
 * reverser can NOP out — the check *is* the key derivation.
 *
 * ## Why one file per check
 *
 * Anti-emulation techniques are independent of each other — RDTSC timing
 * tricks, CPUID hypervisor bit, AC-flag fidelity, FPU quirks — and we
 * want to keep adding more without turning `vm_runtime_gen.cpp` into a
 * 3000-line blob. Each technique lives in its own translation unit with
 * its own tiny test surface; the `CheckRegistry` wires them together
 * and hands a randomised selection to the VM pass.
 *
 * ## Register conventions
 *
 * Checks run in the VM entry stub AFTER the handler-table key has
 * already been stored in the slot on the stack. That means:
 *
 *   - The check can clobber ANY GPR it needs (rax through r15) — the
 *     caller's live state for the upcoming VM dispatch is already on
 *     the stack in VM context slots, not in CPU registers.
 *   - The check must NOT touch rsp or the VM context slots (slots 0..15,
 *     rflags, return address). Only the key slot itself is a legitimate
 *     target, and only via the final `xor [rsp + disp], reg` step.
 *   - The check must be flags-independent on exit — the next thing the
 *     entry stub does is emit the first tail-dispatch, which depends on
 *     rflags being... actually, the tail-dispatch doesn't read rflags
 *     until the next handler runs, and the vflags slot is already
 *     populated. So checks can leave flags in any state.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/randomizer.hpp"

namespace mx::anti_emulation {

/**
 * @brief Abstract anti-emulation check. One instance per technique.
 *
 * Implementations live in `src/builder/protection/anti_emulation/*.cpp`
 * and are instantiated into a `CheckRegistry` at build time. The VM
 * pass asks the registry for a random subset and emits them.
 */
class ICheck {
public:
    virtual ~ICheck() = default;

    /**
     * @brief Emit the check's machine code into `e`.
     *
     * @param e              Byte emitter appending to the current stub blob.
     * @param key_slot_disp  Displacement of the handler-table key slot
     *                       relative to `rsp` at the point the check runs.
     *                       The check's final instruction must be
     *                       `xor [rsp + key_slot_disp], <corruption_reg>`.
     * @param rng            Per-build randomizer. Checks use it to pick
     *                       random corruption masks, random scratch regs,
     *                       etc. so that two builds of the same input
     *                       produce different check bodies.
     */
    virtual void emit(RawEmitter& e,
                      int32_t key_slot_disp,
                      Randomizer& rng) const = 0;

    /// Short human-readable name, for logs and diagnostics.
    [[nodiscard]] virtual const char* name() const noexcept = 0;
};

} // namespace mx::anti_emulation
