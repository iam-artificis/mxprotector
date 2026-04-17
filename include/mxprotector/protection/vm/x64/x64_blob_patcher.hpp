/**
 * @file x64_blob_patcher.hpp
 * @brief [BUILDER, x64] Post-emit patch-up of the finished VM blob.
 *
 * Once every emitter has landed — entry stub, handler bodies, inner VM
 * runtime, handler table, bytecode — the blob still has a bunch of
 * zero-filled rel32 / imm32 slots. This file owns the patch pass that
 * fills them:
 *
 *   1. Entry → bytecode rel32: the `lea r11, [rip + rel32]` in the
 *      entry stub.
 *   2. Handler-table rel32s: every tail-dispatch `lea reg, [rip + rel32]`
 *      collected as `table_patches`.
 *   3. Legacy table-key imm32s: placeholder `xor eax, imm32` patches
 *      collected as `table_key_patches` (empty on the ImageBase-key
 *      path).
 *   4. Trampoline fixups: each trampoline's int32 slot gets set to
 *      `target_offset - anchor_offset` where the target is either a
 *      handler id (terminal link) or another trampoline slot id (head
 *      / intermediate link).
 *   5. Handler-table entries: each = `(head_trampoline_offset -
 *      handler_table_offset) ^ table_xor_key`. The running XOR sum
 *      gets folded into the integrity-check expected imm32.
 *   6. Self-CRC finalisation: the runtime CRC loop compares against
 *      an imm32 the patcher computes over the finalised bytes, so
 *      the finalisation MUST run after every other patch has landed.
 *
 * The patcher reports failure only for structural inconsistencies
 * (trampoline chain pointing at an un-emitted slot / handler) — those
 * are bugs in the emission pipeline, not recoverable errors.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/anti_tamper/self_crc_check.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_patch_records.hpp"

namespace mx::vm::x64 {

/// Everything the patcher needs to finish the blob. All vectors and
/// spans are borrowed — the caller owns the storage.
struct BlobPatchInputs {
    // Entry → bytecode patch.
    size_t entry_bc_patch;
    size_t entry_bc_patch_end;
    size_t bytecode_offset;

    // All rel32 patches that target the handler table.
    const std::vector<TablePatch>& table_patches;
    size_t                         handler_table_offset;

    // Legacy `xor eax, imm32` placeholders (empty when
    // `opts.use_imagebase_key` is set — the ImageBase path reads the
    // key from memory instead).
    const std::vector<size_t>& table_key_patches;
    uint32_t                   table_xor_key;

    // G5 trampoline chain fixups + the tables the fixups resolve into.
    const std::vector<TrampolineFixup>& trampoline_fixups;
    const std::vector<size_t>&          handler_offset_by_id;
    const std::vector<size_t>&          trampoline_offset_by_slot;

    // Handler-table entry writer (head trampoline per handler id).
    uint32_t                      total_handlers;
    const std::vector<uint32_t>&  head_slot_of_handler;

    // Integrity-check expected-sum imm32 position (0 when the
    // ImageBase-key block was skipped).
    size_t integrity_expected_patch;

    // Self-CRC patch records (the finalise helper reads & fills them).
    std::vector<anti_tamper::SelfCrcPatchRecord>& self_crc_patches;
};

/// Apply every post-emit patch to `rt.buf`. Returns
/// `vm_translation_error` if a trampoline chain references an un-emitted
/// handler id or slot — a structural bug in the emission pipeline, not
/// a recoverable error.
[[nodiscard]] MxResult<void> apply_blob_patches(
    RawEmitter&            rt,
    const BlobPatchInputs& in);

} // namespace mx::vm::x64
