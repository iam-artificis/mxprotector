/**
 * @file guard_decrypt_vm_lifter.hpp
 * @brief Lift the native guard decrypt unit into a VM runtime blob.
 *
 * The native decrypt unit (FNV-hash-unmasked XOR loop emitted by
 * `emit_guard_decrypt_unit`) is the single piece of the guard
 * dispatcher an attacker MUST understand to recover the per-guard
 * encryption key from a memory dump. Feeding it through
 * `VmLifter` + `VmRuntimeGenerator` replaces the native x64 bytes
 * with VM bytecode — recovering the decrypt logic now requires
 * reversing the per-build handler table, opcode permutation, and
 * bytecode encryption first.
 *
 * The lifter:
 *   1. Emits the native decrypt unit bytes.
 *   2. Replaces the trailing `ret` with `nop` (the lifter rejects
 *      RET; `VmOp::exit` replaces the `ret` semantics at the VM
 *      level).
 *   3. Lifts through `VmLifter::lift`.
 *   4. Appends `VmOp::exit` to the instruction stream.
 *   5. Generates the VM runtime (entry + dispatcher + handlers +
 *      encrypted bytecode) via `VmRuntimeGenerator::generate`.
 *
 * Any failure is returned as an `MxError` — the pipeline promotes it
 * to `ProtectionErrorCode::pass_failed`.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"

namespace mx {
class ProtectionContext;
class Randomizer;
} // namespace mx

namespace mx::guard {

/// Output of `lift_guard_decrypt_to_vm`. The caller appends
/// `blob` to the `.mxguard` section buffer and records
/// `entry_offset` so the VEH handler's two `call rel32` slots can be
/// back-patched to point at the VM entry.
struct GuardDecryptVmBlob {
    ByteBuffer blob;
    uint32_t   entry_offset = 0;
};

/// Emit the native decrypt unit, lift it to a VM instruction stream,
/// and generate a self-contained VM runtime blob. Logs lift /
/// generation statistics to `ctx`.
[[nodiscard]] MxResult<GuardDecryptVmBlob>
lift_guard_decrypt_to_vm(ProtectionContext& ctx, Randomizer& rng);

} // namespace mx::guard
