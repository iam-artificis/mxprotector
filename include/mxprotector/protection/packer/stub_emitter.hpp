/**
 * @file stub_emitter.hpp
 * @brief Stub emitter policy types + build_*_stub_bytes drivers.
 *
 * The packer assembles one of two stub shapes depending on whether
 * the target PE is an executable or a full DLL: both wrap the shared
 * `emit_decrypt_body` cipher body in a save/restore shell, but the
 * DLL variant also gates on `reason == DLL_PROCESS_ATTACH` and
 * preserves the DllMain ABI registers so the real entry point sees
 * unchanged arguments.
 *
 * This header owns the "stub framing" concern: register save order,
 * stolen-bytes inlining, the trailing `jmp rel32` back to the real
 * entry, and the emitter policy classes that expose each shape
 * through the uniform `StubEmitter` concept the packer orchestration
 * uses.
 *
 * The patch descriptors returned by each builder inherit both
 * `CommonStubPatches` (common rel32 slots every stub must produce)
 * and `CipherBodyPatches` (per-layer key LEAs, per-section loop
 * slots, reprotect / IAT / ImageBase metadata). This lets the
 * packer's `finalize_packer_stub` + `execute_encrypted_stub`
 * pipeline patch both concerns through one pointer without
 * branching on stub shape.
 */

#pragma once

#include <array>
#include <concepts>
#include <cstdint>
#include <utility>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"

namespace mx::packer {

/**
 * @brief Patches produced by every stub shape regardless of whether
 *        it's the EXE or full-DLL build.
 *
 *   * `stolen_bytes_offset` — first byte of the embedded OEP stolen
 *     payload inside the stub buffer. Used to fix up CALL rel32
 *     sites inside the stolen range once the stub's runtime RVA is
 *     known.
 *   * `rel_to_oep_at`       — offset of the rel32 slot of the final
 *     `jmp rel32` that branches back into the real entry (OEP for
 *     EXE, DllMain for full-DLL) at `real_entry + stolen_size`.
 */
struct CommonStubPatches {
    uint32_t stolen_bytes_offset = 0;
    uint32_t rel_to_oep_at       = 0;
};

/// EXE stub patches — common frame + cipher body, no extra fields.
struct ExeStubPatches : CommonStubPatches, CipherBodyPatches {};

/**
 * @brief Full-DLL stub patches — same shape as ExeStubPatches.
 *
 * The full-DLL stub still wraps the identical cipher body; the only
 * differences (11 push/pops instead of 5, a `cmp edx, 1; jne
 * .forward` gate around the cipher body) are back-patched inside the
 * emitter itself and don't surface here.
 */
struct DllFullStubPatches : CommonStubPatches, CipherBodyPatches {};

/**
 * @brief Contract every StubEmitter policy must satisfy.
 *
 * A StubEmitter is a stateless (or cheaply copyable) type that turns
 * `(rng, stolen_bytes_view)` into a concrete stub buffer + a
 * patch descriptor. The patch descriptor must derive from
 * `CommonStubPatches` so the shared packer runtime can patch the
 * common rel32 slots (jmp-to-OEP, stolen CALL fix-ups) uniformly.
 */
template <class T>
concept StubEmitter = requires(T& t, Randomizer& rng, ByteView stolen) {
    typename T::patches_type;
    requires std::derived_from<typename T::patches_type, CommonStubPatches>;
    { t.emit(rng, stolen) } ->
        std::same_as<std::pair<ByteBuffer, typename T::patches_type>>;
};

/**
 * @brief Per-stub emission parameters shared by EXE and full-DLL
 *        stubs.
 *
 *   * `section_count`   — number of target sections the decrypt loops
 *                        iterate over.
 *   * `layer_count`     — number of cipher rounds (P2). Each round
 *                        owns its own RC4 key and its own per-section
 *                        PRGA loop; the runtime decrypts layers
 *                        `N-1 → 0`, and build-time encryption applies
 *                        them in the reverse order.
 *   * `enable_veh_trap` — G3 Phase 2 Vectored Exception Handler INT3
 *                        trap. Opt-in (`--anti-tamper-veh`) and
 *                        EXE-only. The DLL stub constructor forces
 *                        this to false because a DLL-installed VEH
 *                        outlives the DLL's unload.
 */
struct StubEmissionParams {
    uint32_t section_count;
    uint32_t layer_count;
    bool     enable_veh_trap;
};

/**
 * @brief Build the EXE stub code bytes (pre-patch).
 *
 * Layout:
 *   1. Save 5 registers (randomised push order — rax/rcx/rdx/rsi/rdi).
 *   2. Emit the shared decrypt body via `emit_decrypt_body`
 *      (anti-debug → KSA → PRGA → reprotect → IAT wipe).
 *   3. Restore the 5 registers in reverse of the saved order (LIFO).
 *   4. Execute the stolen OEP bytes inline.
 *   5. `jmp rel32` → `OEP + stolen_size`.
 *
 * EXE semantics: at stub entry the Windows loader has just `call`ed
 * the entry point, there is no caller to return to that expects
 * nonvolatile-register preservation (OEP is the initial thread
 * entry), so we only save the volatile-but-clobbered set.
 */
[[nodiscard]] std::pair<ByteBuffer, ExeStubPatches>
build_exe_stub_bytes(Randomizer& rng,
                     ByteView    stolen_bytes,
                     uint32_t    section_count,
                     uint32_t    layer_count,
                     bool        enable_veh_trap);

/**
 * @brief Build the full-DLL stub code bytes (pre-patch).
 *
 * Layout:
 *   1. Save all nonvolatile GPRs the cipher body can clobber
 *      (rbx, rbp, rsi, rdi, r12-r15) plus the three DllMain arg
 *      registers (rcx = HINSTANCE, rdx = reason, r8 = lpReserved).
 *      11 pushes total — odd count, so rsp moves from call-site
 *      `mod16 == 8` to `mod16 == 0`, matching what the reprotect
 *      block inside `emit_decrypt_body` expects before its own
 *      `and rsp, -16; sub rsp, 0x50` frame.
 *   2. `cmp edx, 1; jne .forward` — only run the decrypt pipeline
 *      on `DLL_PROCESS_ATTACH`. THREAD_ATTACH (2), THREAD_DETACH
 *      (3), and PROCESS_DETACH (0) fall straight through to the
 *      forward block so the real DllMain sees them untouched.
 *   3. Shared decrypt body — anti-debug, KSA, PRGA per section,
 *      reprotect, IAT wipe — via `emit_decrypt_body`.
 *   4. `.forward:` — back-patch site for the `jne` above.
 *   5. Pop nonvolatiles + DllMain args in reverse push order.
 *   6. Stolen DllMain prologue bytes inline (may be empty).
 *   7. `jmp rel32` → `DllMain + stolen_size`. The real DllMain's
 *      `ret` then returns to the loader with the BOOL in eax.
 *
 * Note on r12: the reprotect block inside the cipher body uses r12
 * as scratch for its own rsp save/restore. That clobbers the live
 * value we pushed in step 1, but the push-to-stack copy is what
 * counts — the `pop r12` in step 5 reloads the caller's original
 * r12 from the stack, untouched.
 */
[[nodiscard]] std::pair<ByteBuffer, DllFullStubPatches>
build_dll_full_stub_bytes(Randomizer& rng,
                          ByteView    stolen_bytes,
                          uint32_t    section_count,
                          uint32_t    layer_count);
// Note: no `enable_veh_trap` parameter — DLLs cannot safely install
// Vectored Exception Handlers (the VEH would outlive the DLL's
// unload). The full-DLL stub always passes false to the cipher body.

/**
 * @brief StubEmitter policy for the EXE shape.
 *
 * `ExeStubEmitter{{section_count, layer_count}}` captures the
 * emission parameters at construction; `emit(rng, stolen)` produces
 * the stub buffer and its patch descriptor.
 */
class ExeStubEmitter {
public:
    using patches_type = ExeStubPatches;

    explicit ExeStubEmitter(StubEmissionParams params) noexcept
        : params_(params) {}

    [[nodiscard]] std::pair<ByteBuffer, ExeStubPatches>
    emit(Randomizer& rng, ByteView stolen_bytes) {
        return build_exe_stub_bytes(rng, stolen_bytes,
                                    params_.section_count,
                                    params_.layer_count,
                                    params_.enable_veh_trap);
    }

private:
    StubEmissionParams params_;
};

/// StubEmitter policy for the full-DLL shape. Same interface as
/// `ExeStubEmitter`, different wire layout.
class DllFullStubEmitter {
public:
    using patches_type = DllFullStubPatches;

    explicit DllFullStubEmitter(StubEmissionParams params) noexcept
        : params_(params) {}

    [[nodiscard]] std::pair<ByteBuffer, DllFullStubPatches>
    emit(Randomizer& rng, ByteView stolen_bytes) {
        return build_dll_full_stub_bytes(rng, stolen_bytes,
                                         params_.section_count,
                                         params_.layer_count);
    }

private:
    StubEmissionParams params_;
};

static_assert(StubEmitter<ExeStubEmitter>,
    "ExeStubEmitter must satisfy the StubEmitter concept");
static_assert(StubEmitter<DllFullStubEmitter>,
    "DllFullStubEmitter must satisfy the StubEmitter concept");

} // namespace mx::packer
