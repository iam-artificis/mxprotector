/**
 * @file string_decryptor_codegen.hpp
 * @brief [BUILDER] x64 code generation for the S2 stub-mode decryptor.
 *
 * This is the mechanical third stage of the S2 pipeline, after the
 * scanner and xref finder. It emits two kinds of machine code:
 *
 *   1. A single shared `mx_str_get(uint32_t string_id) -> char*`
 *      decryptor (~66 bytes). Given a string_id it looks up the
 *      descriptor, walks to the encrypted bytes, XOR-decrypts them in
 *      place, sets a sticky "already decrypted" flag in the descriptor
 *      so subsequent calls short-circuit, and returns the plaintext
 *      pointer in `rax`. It follows the Windows x64 ABI calling
 *      convention for its arg (`ecx`) and its return (`rax`).
 *
 *   2. One heavyweight trampoline per xref (~38-40 bytes). Each
 *      trampoline replaces a `lea target, [rip+disp32]` at the call
 *      site: the rewriter overwrites the LEA with `call trampoline`,
 *      and the trampoline takes care of (a) preserving every volatile
 *      register and RFLAGS that the original LEA was not going to
 *      clobber, (b) calling `mx_str_get` with the pre-baked string_id,
 *      and (c) delivering the decrypted pointer into the original
 *      LEA's destination register.
 *
 * Both kinds of code are emitted into a single logical `.mxstr`
 * section assembled by the pass orchestrator:
 *
 *   [0x000] shared mx_str_get  <-- `emit_mx_str_get`
 *   [    ] trampoline 0        <-- `emit_trampoline`
 *   [    ] trampoline 1
 *   [    ] ...
 *   [    ] descriptor table    <-- 8 bytes * N, `pack_descriptor`
 *   [    ] encrypted data pool <-- back-to-back ciphertext
 *
 * The two `lea rip+disp32` slots inside `mx_str_get` that point at
 * the descriptor table and the data pool are left zeroed at emit
 * time; their byte offsets are reported in `EmittedDecryptor` so the
 * orchestrator can patch them once the section layout is known.
 * The `call rel32` inside each trampoline works the same way.
 *
 * This header is Zydis-free on purpose. The codegen accepts a plain
 * x64 GPR index in 0..15 (standard AMD64 register encoding: 0=rax,
 * 1=rcx, 2=rdx, 3=rbx, 4=rsp, 5=rbp, 6=rsi, 7=rdi, 8..15=r8..r15).
 * The orchestrator is responsible for translating the
 * `StringXref::dest_reg` Zydis opaque value into this index.
 *
 * Thread-safety note: the XOR decrypt loop is not atomic. If two
 * threads race into `mx_str_get` for the same string_id before
 * either has flipped the "decrypted" flag, one will observe the
 * other's partially-decrypted bytes or double-xor the buffer back to
 * ciphertext. MVP does not guard against this; a lock-free
 * `lock cmpxchg` claim on the flag byte is the obvious future fix
 * and belongs to S3.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::string_protect {

// ---------------------------------------------------------------------------
// On-disk descriptor format (read by the emitted mx_str_get code).
// ---------------------------------------------------------------------------

/// Byte layout of a single descriptor in the `.mxstr` descriptor table.
/// The field offsets here are mirrored inside the hand-rolled x64
/// decryptor code, so tests assert both match.
inline constexpr size_t  kDescriptorSize           = 8;
inline constexpr size_t  kDescriptorOffsetField    = 0;  ///< u32 data_offset
inline constexpr size_t  kDescriptorLengthField    = 4;  ///< u16 length
inline constexpr size_t  kDescriptorKeyField       = 6;  ///< u8  key
inline constexpr size_t  kDescriptorFlagsField     = 7;  ///< u8  flags
inline constexpr uint8_t kDescriptorFlagDecrypted  = 0x01;

struct StringDescriptor {
    uint32_t data_offset = 0;  ///< byte offset into the data pool
    uint16_t length      = 0;  ///< plaintext byte count
    uint8_t  key         = 0;  ///< per-string XOR key (must be non-zero)
    uint8_t  flags       = 0;  ///< bit 0 = sticky "already decrypted"
};

/// Pack a descriptor into its 8-byte on-disk form (little-endian).
[[nodiscard]] std::array<uint8_t, kDescriptorSize>
pack_descriptor(const StringDescriptor& d) noexcept;

// ---------------------------------------------------------------------------
// Register index helpers.
// ---------------------------------------------------------------------------

/// Standard x64 GPR index. 0..15, matching AMD64 encoding order.
/// 0 rax, 1 rcx, 2 rdx, 3 rbx, 4 rsp, 5 rbp, 6 rsi, 7 rdi,
/// 8 r8 .. 15 r15. `rsp` (4) is not a valid target.
using GprIndex = uint8_t;

inline constexpr GprIndex kGprRax = 0;
inline constexpr GprIndex kGprRcx = 1;
inline constexpr GprIndex kGprRdx = 2;
inline constexpr GprIndex kGprRbx = 3;
inline constexpr GprIndex kGprRsp = 4;
inline constexpr GprIndex kGprRbp = 5;
inline constexpr GprIndex kGprRsi = 6;
inline constexpr GprIndex kGprRdi = 7;
inline constexpr GprIndex kGprR8  = 8;
inline constexpr GprIndex kGprR9  = 9;
inline constexpr GprIndex kGprR10 = 10;
inline constexpr GprIndex kGprR11 = 11;
inline constexpr GprIndex kGprR12 = 12;
inline constexpr GprIndex kGprR13 = 13;
inline constexpr GprIndex kGprR14 = 14;
inline constexpr GprIndex kGprR15 = 15;

/// True iff `gpr` is a volatile register under the Windows x64 ABI
/// (rax, rcx, rdx, r8, r9, r10, r11). Volatile targets are saved in
/// the trampoline prologue and patched in place on the stack;
/// non-volatile targets (rbx, rbp, rsi, rdi, r12..r15) receive the
/// pointer via a direct `mov target, rax` after the call, since the
/// original LEA was going to clobber them anyway.
[[nodiscard]] constexpr bool is_volatile_gpr(GprIndex gpr) noexcept {
    return gpr == kGprRax || gpr == kGprRcx || gpr == kGprRdx ||
           gpr == kGprR8  || gpr == kGprR9  || gpr == kGprR10 ||
           gpr == kGprR11;
}

// ---------------------------------------------------------------------------
// Emitter output records.
// ---------------------------------------------------------------------------

/// The shared mx_str_get decryptor. Size is always
/// `kMxStrGetSize` bytes. The two disp32 fields reported here point
/// at the descriptor-table base and the data-pool base; the caller
/// patches them after the final section layout is known.
struct EmittedDecryptor {
    std::vector<uint8_t> code;
    size_t               desc_table_disp32_offset = 0;
    size_t               data_base_disp32_offset  = 0;
};

/// A single per-xref trampoline. `call_rel32_offset` is the byte
/// offset inside `code` of the `call rel32` operand; the caller
/// patches it with `mx_str_get_section_offset - (trampoline_offset +
/// call_rel32_offset + 4)` once both items have known section
/// offsets.
struct EmittedTrampoline {
    std::vector<uint8_t> code;
    size_t               call_rel32_offset = 0;
};

/// Shared decryptor byte size. Asserted in unit tests so that any
/// accidental divergence in `emit_mx_str_get` is caught.
inline constexpr size_t kMxStrGetSize              = 66;

/// Trampoline byte sizes by target category.
inline constexpr size_t kTrampolineSizeVolatile    = 40;
inline constexpr size_t kTrampolineSizeNonVolatile = 38;

/// Byte size of the trampoline that will be emitted for `gpr`.
[[nodiscard]] constexpr size_t
trampoline_size_for(GprIndex gpr) noexcept {
    return is_volatile_gpr(gpr) ? kTrampolineSizeVolatile
                                : kTrampolineSizeNonVolatile;
}

// ---------------------------------------------------------------------------
// Request to emit a single trampoline.
// ---------------------------------------------------------------------------

struct TrampolineRequest {
    /// Value baked into `mov ecx, imm32` — index into the descriptor
    /// table. The orchestrator assigns these densely from 0.
    uint32_t string_id  = 0;
    /// Original LEA destination register (AMD64 index, 0..15).
    /// Must not be `kGprRsp`.
    GprIndex target_reg = 0;
};

// ---------------------------------------------------------------------------
// Emitters.
// ---------------------------------------------------------------------------

/// Emit the shared mx_str_get decryptor. The two `lea rip+disp32`
/// operands are left zeroed; their offsets are recorded in the
/// returned struct so the caller can patch them later.
[[nodiscard]] EmittedDecryptor emit_mx_str_get();

/// Emit a single trampoline for the xref described by `req`. The
/// string_id is baked into the bytes. The `call rel32` operand is
/// left zeroed; its offset is recorded in the returned struct.
[[nodiscard]] EmittedTrampoline
emit_trampoline(const TrampolineRequest& req);

} // namespace mx::string_protect
