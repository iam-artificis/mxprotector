/**
 * @file guard_veh_emitter.hpp
 * @brief Emits the Vectored Exception Handler body for runtime-guards.
 *
 * The handler lives inside the `.mxguard` section alongside the guard
 * pages and the descriptor table it walks. It is installed once per
 * process (via the TLS install thunk in `guard_tls_installer.hpp`)
 * and fires on every `int3` executed from a guard page's plaintext
 * entry or exit window.
 *
 * ## x64 handler ABI (Windows)
 *
 * The handler is called with:
 *   * `rcx`  = `PEXCEPTION_POINTERS info` — pointer to a two-field
 *     struct `{ PEXCEPTION_RECORD ExceptionRecord; PCONTEXT ContextRecord; }`
 *   * 32 bytes of shadow space at `[rsp + 0x00 .. 0x1F]` (caller-owned)
 *   * `rax` = scratch
 *
 * Return value is a `LONG` in `eax`:
 *   *  `-1` = `EXCEPTION_CONTINUE_EXECUTION` (resume with updated Rip)
 *   *   `0` = `EXCEPTION_CONTINUE_SEARCH`    (not our exception)
 *
 * Nonvolatile callee-saved register set (must be preserved):
 *   * `rbx, rbp, rsi, rdi, r12..r15, xmm6..xmm15`
 *
 * ## What the handler does
 *
 * 1. Reads `ExceptionRecord->ExceptionCode` and bails out with
 *    `CONTINUE_SEARCH` for anything other than `STATUS_BREAKPOINT
 *    (0x80000003)`. This is the "strict filter" pattern we already
 *    use for G3 Phase 2 — a loose filter would swallow C++ `throw`
 *    exceptions and silently break user code.
 *
 * 2. Reads `ExceptionRecord->ExceptionAddress` (the Rip of the
 *    faulting `int3`) and subtracts the image base to get a runtime
 *    RVA. The image base is computed with a rip-relative `lea`:
 *    `lea rbx, [rip + 0]; sub rbx, <imm32_handler_anchor>` — this
 *    works for both EXE and DLL without reading `PEB.ImageBase`
 *    (which is wrong for DLLs loaded into a host EXE).
 *
 * 3. Walks the `.mxguard` descriptor table looking for a matching
 *    `entry_int3_rva` or `exit_int3_rva`. The table address comes
 *    from a rip-relative `lea` that `GuardPass` patches, and the
 *    descriptor count comes from an embedded imm32 that
 *    `GuardPass` also patches.
 *
 * 4. On `entry_int3_rva` match: sets `ContextRecord->Rip = descriptor
 *    .body_start_rva + image_base` and returns
 *    `EXCEPTION_CONTINUE_EXECUTION`. Execution resumes at the first
 *    body byte.
 *
 * 5. On `exit_int3_rva` match: sets `ContextRecord->Rip = descriptor
 *    .return_rva + image_base` and returns
 *    `EXCEPTION_CONTINUE_EXECUTION`. Execution resumes at the
 *    instruction right after `MX_GUARD_END` in the source section.
 *
 * 6. Otherwise returns `CONTINUE_SEARCH`.
 *
 * Commit 3b extends steps 4 and 5 to also toggle the page's write
 * protection and decrypt/re-encrypt the body bytes in place via a
 * cached `NtProtectVirtualMemory` pointer resolved through Hell's
 * Gate. The current commit does not touch memory protection — the
 * pages stay plaintext at rest, which is structurally equivalent to
 * Commit 2 from a dump-resistance standpoint but establishes the
 * VEH plumbing Commit 3b builds on.
 *
 * ## Descriptor table layout
 *
 * 16 bytes per descriptor, tightly packed:
 *
 * ```
 *     +0x00  uint32  entry_int3_rva
 *     +0x04  uint32  exit_int3_rva
 *     +0x08  uint32  body_start_rva
 *     +0x0C  uint32  return_rva
 * ```
 *
 * The handler linearly scans the table — O(N) where N is the number
 * of guards in the binary. Hot-path performance is not a concern:
 * the VEH only fires on guard entry/exit, not on every instruction.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"

namespace mx::guard {

/**
 * @brief Patch sites produced by `emit_guard_veh_handler`.
 *
 * `GuardPass` fills each of these slots once the handler, descriptor
 * table, and `.mxguard` section RVAs are finalised:
 *
 *   * `module_base_sub_imm32_offset` — the imm32 of the `sub rbx,
 *     imm32` that finalises `rbx = module_base`. The caller writes
 *     `handler_rva + module_base_lea_anchor_offset` — equivalently,
 *     the RVA of the instruction right after the rip-relative `lea
 *     rbx, [rip + 0]`.
 *
 *   * `module_base_lea_anchor_offset` — the offset INSIDE the
 *     handler body of the byte right after the `lea rbx, [rip + 0]`.
 *     Used by the caller to compute the `module_base_sub_imm32`
 *     value.
 *
 *   * `descriptor_table_rel32_offset` — offset of the 4-byte rel32
 *     inside the `lea rsi, [rip + rel32]` that loads the descriptor
 *     table base pointer. The caller writes
 *     `table_rva - (handler_rva + descriptor_table_rel32_end_offset)`.
 *
 *   * `descriptor_table_rel32_end_offset` — offset of the byte right
 *     after the rel32, i.e. the value RIP has at the moment the lea
 *     resolves. Used to compute the rel32 value above.
 *
 *   * `descriptor_count_imm32_offset` — offset of the 4-byte imm32
 *     inside the `mov r8d, imm32` that loads the descriptor count.
 *     The caller writes the total number of descriptors.
 */
struct GuardVehEmit {
    uint32_t module_base_sub_imm32_offset      = 0;
    uint32_t module_base_lea_anchor_offset     = 0;
    uint32_t descriptor_table_rel32_offset     = 0;
    uint32_t descriptor_table_rel32_end_offset = 0;
    uint32_t descriptor_count_imm32_offset     = 0;
};

/// Size of one descriptor table entry in bytes. Must match the x64
/// offsets the handler body bakes in via `cmp [rsi+0]` / `mov eax,
/// [rsi+8]` etc.
inline constexpr uint32_t kGuardDescriptorStride = 16;

/**
 * @brief Append the full VEH handler body to `e`.
 *
 * The emitter is byte-deterministic — identical `RawEmitter` state
 * plus identical inputs produce identical output. Patch sites are
 * returned via `GuardVehEmit` and must be finalised by the caller
 * before the binary is written.
 *
 * Post-conditions:
 *   * `e.size()` has grown by the fixed handler body size.
 *   * The handler body is position-independent code — no baked
 *     absolute addresses, only rip-relative `lea`s and imm32
 *     placeholders the caller patches.
 *   * Nonvolatile `rbx`/`rsi`/`rdi` that the handler uses are
 *     saved with `push` at entry and restored with `pop` at exit,
 *     so the handler obeys the Windows x64 ABI.
 */
[[nodiscard]] GuardVehEmit emit_guard_veh_handler(RawEmitter& e);

} // namespace mx::guard
