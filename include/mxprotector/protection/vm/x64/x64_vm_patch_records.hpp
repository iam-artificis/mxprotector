/**
 * @file x64_vm_patch_records.hpp
 * @brief [BUILDER, x64] Post-emit patch descriptors for the VM blob.
 *
 * The x64 VM backend builds its runtime blob in two passes: an
 * emission pass that writes placeholder rel32 / imm32 slots as it
 * goes, and a post-emit patch pass that fills those slots once every
 * target offset is known. This header defines the small descriptor
 * types the emission pass uses to remember what to patch later.
 *
 * The descriptors are deliberately minimal — just the byte offsets
 * and the target kind. The patcher reads them without understanding
 * which emitter produced the slot, so new emitters can participate
 * without extending the patcher.
 */

#pragma once

#include <cstdint>
#include <cstddef>

#include "mxprotector/protection/vm/x64/x64_handlers.hpp"

namespace mx::vm::x64 {

/// rel32 from some dispatch / LEA instruction to the handler table.
/// Recorded by every emitter that writes a
/// `lea reg, [rip + rel32_to_handler_table]` or any shape that ends
/// in the same rel32 slot.
///
///   rel32_offset     first byte of the 32-bit displacement
///   instruction_end  byte right after the rel32 (= rip of the
///                    following instruction, the anchor `patch_rel32`
///                    subtracts the target from)
struct TablePatch {
    size_t rel32_offset;
    size_t instruction_end;
};

/// G5 trampoline fixup — records a trampoline's int32 placeholder
/// slot together with its target. The target is either a handler id
/// (terminal trampoline) or another trampoline slot id (head /
/// intermediate links in a chain); the patcher resolves the id to a
/// concrete offset via `handler_offset_by_id` or
/// `trampoline_offset_by_slot` at patch time.
struct TrampolineTarget {
    enum class Kind : uint8_t { Handler, Trampoline };
    Kind     kind;
    uint32_t id;
};

struct PendingTrampoline {
    uint32_t         slot;
    TrampolineTarget target;
};

struct TrampolineFixup {
    TrampolineTarget         target;
    vm::x64::TrampolinePatch patch;
};

} // namespace mx::vm::x64
