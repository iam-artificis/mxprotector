/**
 * @file x64_blob_patcher.cpp
 * @brief [BUILDER, x64] Post-emit patch-up — implementation.
 *
 * Split out of `x64_vm_backend.cpp` (R1.6). Pure memcpy-style pass
 * that walks the patch-record vectors the emitters accumulated during
 * their passes and writes the correct rel32 / imm32 values into the
 * finished blob.
 */

#include "mxprotector/protection/vm/x64/x64_blob_patcher.hpp"

#include <cstring>
#include <format>

#include "mxprotector/protection/vm/x64/x64_emitters.hpp"  // patch_rel32

namespace mx::vm::x64 {

MxResult<void> apply_blob_patches(
    RawEmitter&            rt,
    const BlobPatchInputs& in)
{
    // Entry → bytecode (via lea r11, [rip + rel32]).
    patch_rel32(rt.buf, in.entry_bc_patch, in.entry_bc_patch_end, in.bytecode_offset);

    // All tail-dispatch lea reg, [rip + rel32] → handler_table.
    for (const auto& p : in.table_patches) {
        patch_rel32(rt.buf, p.rel32_offset, p.instruction_end, in.handler_table_offset);
    }

    // Patch the legacy `xor eax, imm32` placeholders in tail dispatches.
    // (The ImageBase path leaves `table_key_patches` empty.)
    for (const auto patch_off : in.table_key_patches) {
        std::memcpy(rt.buf.data() + patch_off, &in.table_xor_key, 4);
    }

    // G5: patch each trampoline's placeholder int32 slot with
    // `target_offset - anchor_offset`, sending runtime rip to the next
    // link in the chain. The target can be either a real handler (for
    // the terminal trampoline) or another trampoline (for head /
    // intermediate links). The anchor semantics are shape-specific
    // (see `emit_trampoline`): for Direct and PushRet it is the byte
    // right after the rel32 slot; for CallPop it is the byte right
    // after the `call rel32 = 0` that leaked the anchor onto the stack.
    // The formula is uniform — the shape-specific math is baked into
    // `anchor_offset` at emit time.
    //
    // Every emitted handler has a corresponding chain with every chain
    // slot allocated up front. A missing handler offset or trampoline
    // slot offset means the emission loop lost track of something,
    // which is a bug — we surface it explicitly instead of silently
    // leaving a trampoline whose final jump lands on offset 0.
    for (const auto& tf : in.trampoline_fixups) {
        size_t target_offset = 0;
        switch (tf.target.kind) {
            case TrampolineTarget::Kind::Handler: {
                if (in.handler_offset_by_id[tf.target.id] == SIZE_MAX) {
                    return std::unexpected(MxError(
                        ProtectionErrorCode::vm_translation_error,
                        std::format("X64VmBackend: trampoline chain targets un-emitted handler {}",
                                     tf.target.id)));
                }
                target_offset = in.handler_offset_by_id[tf.target.id];
                break;
            }
            case TrampolineTarget::Kind::Trampoline: {
                if (tf.target.id >= in.trampoline_offset_by_slot.size() ||
                    in.trampoline_offset_by_slot[tf.target.id] == SIZE_MAX) {
                    return std::unexpected(MxError(
                        ProtectionErrorCode::vm_translation_error,
                        std::format("X64VmBackend: trampoline chain targets un-emitted slot {}",
                                     tf.target.id)));
                }
                target_offset = in.trampoline_offset_by_slot[tf.target.id];
                break;
            }
        }
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(target_offset) -
            static_cast<int64_t>(tf.patch.anchor_offset));
        std::memcpy(rt.buf.data() + tf.patch.fixup_offset, &rel, 4);
    }

    // handler_table entries: each = (head_trampoline_offset -
    // table_offset) ^ table_xor_key.
    //
    // G5 phase 3: the entry points at the head of each handler's
    // trampoline chain. Intermediate and terminal trampolines in the
    // chain are reachable only by following the head, which itself
    // reads as one of three polymorphic shapes. The integrity-check
    // XOR sum still works byte-for-byte — it hashes whatever the
    // entries hold, agnostic of what the targets represent — so the
    // check's expected-sum imm32 patched below remains correct.
    uint32_t table_xor_sum = 0;
    for (uint32_t h = 0; h < in.total_handlers; ++h) {
        const uint32_t head_slot = in.head_slot_of_handler[h];
        if (head_slot == UINT32_MAX ||
            head_slot >= in.trampoline_offset_by_slot.size() ||
            in.trampoline_offset_by_slot[head_slot] == SIZE_MAX) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format("X64VmBackend: handler id {} missing trampoline chain", h)));
        }
        auto rel = static_cast<int32_t>(
            static_cast<int64_t>(in.trampoline_offset_by_slot[head_slot]) -
            static_cast<int64_t>(in.handler_table_offset));
        rel ^= static_cast<int32_t>(in.table_xor_key);
        std::memcpy(rt.buf.data() + in.handler_table_offset + h * 4, &rel, 4);
        table_xor_sum ^= static_cast<uint32_t>(rel);
    }

    // Patch the integrity-check expected-XOR-sum into the entry stub.
    if (in.integrity_expected_patch != 0) {
        std::memcpy(rt.buf.data() + in.integrity_expected_patch,
                    &table_xor_sum, 4);
    }

    // Self-CRC finalisation. Must run AFTER every other patch has
    // modified the entry-stub bytes, because the Self-CRC check's CRC
    // range includes bytes that only become stable here (the integrity-
    // check rel32, the integrity expected-sum imm32, and the tail-
    // dispatch rel32s). Computing the expected CRC over the finalised
    // buffer guarantees the runtime loop — which reads the same
    // finalised bytes — gets an identical value.
    anti_tamper::finalize_self_crc_patches(rt, in.self_crc_patches);
    return {};
}

} // namespace mx::vm::x64
