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

#include <cstddef>
#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::anti_tamper {

/**
 * @brief A deferred-finalise record produced by the Self-CRC check.
 *
 * Self-CRC cannot bake its expected CRC value at emit time, because
 * the byte range it covers (the entry-stub prefix) includes
 * placeholder bytes that the X64 backend back-patches LATER — most
 * notably the `integrity_table_lea_patch` rel32 inside the
 * handler-table integrity check, which sits in the middle of the
 * CRC range and is still zero at Self-CRC emit time.
 *
 * Instead, Self-CRC emits a placeholder `cmp eax, 0x00000000` at
 * the check's `expected CRC` position and records the patch
 * information here. After every other post-hoc patch has been
 * applied (`table_patches`, `table_key_patches`, handler-table
 * encryption, integrity-check expected sum), the X64 backend
 * calls `finalize_self_crc_patches` to compute the CRC over the
 * final byte contents of the range and write it into the
 * placeholder.
 */
struct SelfCrcPatchRecord {
    size_t placeholder_offset = 0;  ///< Where to write the final u32 CRC.
    size_t range_start        = 0;  ///< First byte of the range to CRC.
    size_t length             = 0;  ///< Number of bytes in the range.
};

/**
 * @brief Build-time context handed to every anti-tamper check.
 *
 * Some checks need to reference the entry-stub bytes that were
 * already emitted before them — for example, a self-CRC check has
 * to compute a CRC over the preceding entry-stub instruction bytes
 * both at build time (to bake the expected CRC) and at runtime (to
 * verify it). Accessing those bytes requires information the check
 * doesn't own itself:
 *
 *   1. `entry_offset` — the absolute offset of the entry stub's
 *      first byte inside the `RawEmitter` buffer. The check
 *      subtracts this from its current position to compute the
 *      length of the CRC range, and uses it to compute a
 *      rip-relative rel32 that points at the entry stub start at
 *      runtime.
 *
 *   2. `self_crc_patches` — optional pointer to a vector into
 *      which the Self-CRC check pushes a `SelfCrcPatchRecord` so
 *      the X64 backend can compute the real CRC over the final
 *      (post-patch) buffer state. If nullptr, the check falls
 *      back to an emit-time CRC, which only catches tampering in
 *      build modes without post-hoc patches (rare — kept as a
 *      sentinel for unit tests that construct a check in
 *      isolation).
 *
 * Checks that don't need any of this (HW breakpoint sweep, import
 * hook detection) simply ignore the context.
 */
struct CheckContext {
    size_t entry_offset = 0;
    std::vector<SelfCrcPatchRecord>* self_crc_patches = nullptr;
};

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
     * @param ctx            Build-time context — see `CheckContext`.
     *                       Checks that don't need it ignore the
     *                       parameter.
     */
    virtual void emit(RawEmitter& e,
                      int32_t key_slot_disp,
                      Randomizer& rng,
                      const CheckContext& ctx) const = 0;

    /**
     * @brief DJB2 hash of the NTDLL function whose SSN this check
     *        needs in `r13d` at runtime, or 0 if it does not call
     *        the kernel.
     *
     * The X64 backend uses this to decide whether to emit a
     * Hell's Gate resolver before the check runs, and which
     * function to resolve. A result of 0 means "no resolver
     * emission needed", keeping the entry stub compact for checks
     * like Self-CRC and Import Hook Detection that work purely on
     * user-mode memory reads.
     *
     * Default implementation returns 0; only override in concrete
     * checks that issue `syscall` instructions.
     */
    [[nodiscard]] virtual uint32_t required_syscall_hash() const noexcept {
        return 0;
    }

    /// Short human-readable name, for logs and tests.
    [[nodiscard]] virtual const char* name() const noexcept = 0;
};

} // namespace mx::anti_tamper
