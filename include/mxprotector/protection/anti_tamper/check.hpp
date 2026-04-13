/**
 * @file check.hpp
 * @brief Abstract anti-tamper check emitter.
 *
 * Anti-tamper checks are the runtime cousins of anti-emulation
 * checks: each one emits a short machine-code sequence that probes
 * a runtime property a healthy host always satisfies and a
 * compromised one (debugger attached, hardware breakpoint set,
 * critical NTDLL function hooked) does not. The probe ends with a
 * `xor [rsp + key_slot_disp], <reg>` that XORs zero on a healthy
 * host and a per-build random non-zero corruption mask otherwise.
 *
 * The interface mirrors `anti_emulation::ICheck` deliberately —
 * same `emit` signature, same key-slot contract — so the
 * `X64VmBackend` orchestration treats both kinds of checks
 * uniformly. They live in separate namespaces (and separate
 * registries) because they evolve independently:
 *
 *   * **Anti-emulation** detects sandboxes by probing CPU/CPUID
 *     quirks. Cheap (~30 bytes) and runs many times per region.
 *
 *   * **Anti-tamper** detects live debuggers, EDR hooks, and
 *     hardware breakpoints. More expensive (~100 bytes per check
 *     because of the syscall scaffolding), and gates calls through
 *     direct `syscall` instructions to bypass user-mode hooks.
 *
 * The split also lets a future CLI flag enable/disable each
 * category independently — e.g. anti-emu only on builds destined
 * for sandbox detection, anti-tamper only on builds shipping into
 * debugger-rich environments.
 *
 * ## Register conventions
 *
 * Same as anti-emu — the check runs in the VM entry stub between
 * key derivation and the first dispatch. Every guest GPR is already
 * saved in a VM context slot, so the check can clobber any GPR
 * including rax/rcx/rdx/r8/r9/r10/r11 freely.
 *
 * The check MUST NOT touch rsp permanently — it can `sub` and `add`
 * it during a syscall scaffold, but the final `xor [rsp + disp]`
 * must reach the same key slot the entry stub computed. Most
 * concrete checks save rsp into r11 around the syscall and restore
 * it before the final XOR.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::anti_tamper {

class ICheck {
public:
    virtual ~ICheck() = default;

    /**
     * @brief Emit the check's machine code into `e`.
     *
     * @param e              Byte emitter appending to the entry stub.
     * @param key_slot_disp  Displacement of the handler-table key slot
     *                       relative to `rsp` at the point the check
     *                       runs. The check's final instruction must
     *                       be `xor [rsp + key_slot_disp], <reg>`
     *                       (or equivalent), with rsp restored to the
     *                       pre-check value first if the check
     *                       temporarily moved it.
     * @param rng            Per-build randomiser. Checks use it to
     *                       pick random corruption masks and any
     *                       internal polymorphism choices.
     */
    virtual void emit(RawEmitter& e,
                      int32_t key_slot_disp,
                      Randomizer& rng) const = 0;

    /// Short human-readable name, for logs and tests.
    [[nodiscard]] virtual const char* name() const noexcept = 0;
};

} // namespace mx::anti_tamper
