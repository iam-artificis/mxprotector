/**
 * @file x64_entry_stub.hpp
 * @brief [BUILDER, x64] Entry stub emission for the VM runtime.
 *
 * Emits the entry stub that every caller of a virtualised region
 * lands on:
 *
 *   pushfq
 *   [G7 random pad-slot pushes]
 *   16 × push reg  (permuted per-build slot → native register map)
 *   seed rolling-key byte inside the junk slot
 *   [vEFLAGS in-slot scramble]
 *   [optional ImageBase-derived handler-table key block:
 *      PEB → ImageBase →
 *      G6 iterated bit-mix loop →
 *      MBA chain →
 *      handler-table integrity-check loop →
 *      anti-emulation / anti-tamper picks]
 *   lea r11, [rip + bytecode_rel32]     ; rel32 patched in step 4
 *   inline first tail dispatch
 *
 * The function is a data-in / blob-out pass. It reads the phase-1
 * randomization outputs (layout / keys / cipher mode / handler count)
 * via `EntryStubInputs`, writes bytes into the caller's `RawEmitter`,
 * and records two kinds of side effects:
 *
 *   * patch records — table-rel32 slots and self-CRC slots get
 *     appended to the caller-owned lists via `EntryStubSinks`. The
 *     final step-4 patcher reads the same lists, so the entry-stub
 *     emitter doesn't need to own them.
 *
 *   * structural outputs — the entry offset, the bytecode-rel32
 *     patch position, the ImageBase key displacement (negative when
 *     the classic imm32 key is used), the handler-table XOR key, and
 *     the two integrity-check patch positions.
 *
 * The per-build inner-VM ISA and trampoline bookkeeping are NOT
 * emitted here — they belong to the handler-emission phase and are
 * owned by the surrounding `GenerationSession`.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/anti_tamper/self_crc_check.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"
#include "mxprotector/protection/vm/vm_stack_layout.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_patch_records.hpp"

namespace mx::vm::x64 {

/// Everything the entry-stub emitter reads from phase 1.
struct EntryStubInputs {
    const VmGenOptions&  opts;
    const VmStackLayout& layout;
    int32_t              rolling_key_disp;
    int32_t              rflags_disp;
    uint8_t              initial_key;
    uint32_t             vflags_key;
    uint32_t             vflags_rol;
    bool                 rolling;
    uint32_t             total_handlers;
    Randomizer&          rng;
};

/// Caller-owned patch sinks. The emitter appends to these as it goes;
/// the patcher reads them in step 4.
struct EntryStubSinks {
    std::vector<TablePatch>&                          table_patches;
    std::vector<size_t>&                              table_key_patches;
    std::vector<anti_tamper::SelfCrcPatchRecord>&     self_crc_patches;
};

/// Structural results of the emission.
struct EntryStubOutputs {
    size_t   entry_offset;                 ///< byte offset of the first emitted byte.
    size_t   entry_bc_patch;                ///< first byte of the rel32 in `lea r11, [rip + rel32]`.
    size_t   entry_bc_patch_end;            ///< byte right after that rel32 (anchor for the patcher).
    int32_t  imagebase_key_disp;            ///< `[rsp + disp8]` location of the runtime-derived key; -1 when disabled.
    uint32_t table_xor_key;                 ///< XOR key for handler-table entries (also used by step-4 patches).
    size_t   integrity_table_lea_patch;     ///< rel32 slot for the integrity-check `lea rbx, [rip + rel32]`; 0 when disabled.
    size_t   integrity_expected_patch;      ///< imm32 slot for the integrity-check expected sum; 0 when disabled.
};

/// Emit the entry stub and return the structural outputs. Appends
/// patch records to `sinks`.
[[nodiscard]] EntryStubOutputs emit_entry_stub(
    RawEmitter&            rt,
    const EntryStubInputs& in,
    EntryStubSinks         sinks);

} // namespace mx::vm::x64
