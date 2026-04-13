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
 * Thread-safety (S2b): the flag byte is a 3-state word — `0 = idle`,
 * `1 = claimed`, `2 = done`. The first thread to call `mx_str_get`
 * for a given string_id tries a `lock cmpxchg` to atomically flip
 * the flag from 0 → 1; the winner runs the XOR loop, then plain-
 * stores `2` to mark the string decrypted. Concurrent callers that
 * lose the cmpxchg spin-wait on `pause` until they observe the
 * `done` bit set, then return the plaintext pointer. There is no
 * window in which two threads can race into the XOR loop for the
 * same string, and no window in which a caller reads partially-
 * decrypted bytes. S2a had a known race (mvp skipped the claim);
 * S2b closes it.
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

/// S3 ephemeral decryptor. Same input/output ABI as the S2b variant
/// (ecx = string_id in, rax = decrypted char* out) but the body is
/// different: instead of XOR-decrypting the data pool in place and
/// returning a sticky cached pointer, the S3 code allocates a fresh
/// scratch-ring slot via `lock xadd` and copies + decrypts the
/// ciphertext into that slot on every call. The data pool stays
/// ciphertext at rest, and the number of concurrently-decrypted
/// strings in memory is bounded by `kEphemeralRingSlots`.
///
/// The returned struct reports THREE disp32 patch offsets because
/// the body uses three `lea rip+disp32` header loads — one each for
/// the descriptor table, the ciphertext data pool, and the scratch
/// ring base. Each defaults to zero; the pass rewrites them after
/// the section RVA is assigned.
struct EmittedEphemeralDecryptor {
    std::vector<uint8_t> code;
    size_t               desc_table_disp32_offset   = 0;
    size_t               data_base_disp32_offset    = 0;
    size_t               scratch_ring_disp32_offset = 0;
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
///
/// The S2b variant uses a 3-state flag (0 = idle, 1 = claimed,
/// 2 = done) and a `lock cmpxchg` atomic claim so concurrent callers
/// for the same string_id cannot race into a double-XOR back to
/// ciphertext. This is longer than the original S2a body because it
/// must preserve `rax` across the cmpxchg (which clobbers `al`) and
/// includes a pause-based spin-wait for the contended path.
inline constexpr size_t kMxStrGetSize              = 93;

/// Offset inside `emit_mx_str_get()` where the XOR decrypt loop
/// starts. This is the S2c "virtualizable window": four instructions,
/// all of them simple register / r10-or-r8-relative forms that lift
/// cleanly through the existing VM engine.
///
///   .loop:
///     xor  byte [r8], dl    ; 3 bytes
///     inc  r8               ; 3 bytes
///     dec  rcx              ; 3 bytes
///     jnz  .loop            ; 2 bytes
///
/// Narrower than "whole body" on purpose — the VM engine is stress-
/// tested against arbitrary arithmetic, but exotic primitives we
/// carry (`lock cmpxchg`, `pause`, 8-bit memory ops) interact
/// unpredictably with polymorphic handler variants when chained
/// back-to-back as consecutive `VmOp::native` handlers. Lifting only
/// the decrypt loop keeps the VM region small (1 vjcc + 3 natives)
/// and deterministic enough to be stable across per-build RNG draws.
///
/// S2c replaces this range in place with `call rel32 <vm_entry>` +
/// NOP padding. The `jz .mark_done` that precedes the loop targets
/// byte `kMxStrGetLoopEndOffset` (= `.mark_done`), which is outside
/// this range, so the rcx==0 fast-path still bypasses the VM.
inline constexpr size_t kMxStrGetLoopOffset        = 73;

/// Offset (exclusive) of the last byte of the VM-protectable loop.
/// Byte 84 is `.mark_done` (the plain-store of the done flag), which
/// stays plaintext so the lifter's "target == region_end_va" sentinel
/// routes `jnz .loop` fall-through to a VM exit that returns to the
/// instruction immediately after the loop.
inline constexpr size_t kMxStrGetLoopEndOffset     = 84;

/// Number of bytes in the VM-protectable loop window.
inline constexpr size_t kMxStrGetLoopSize          =
    kMxStrGetLoopEndOffset - kMxStrGetLoopOffset;

// ---------------------------------------------------------------------------
// S3 ephemeral decryptor constants
// ---------------------------------------------------------------------------

/// Number of bytes emitted by `emit_mx_str_get_ephemeral()`. The S3
/// body is larger than S2b because it carries a scratch-ring allocator
/// and a copy-then-decrypt loop instead of a sticky flag check.
inline constexpr size_t kMxStrGetEphemeralSize     = 94;

/// Number of scratch slots in the ephemeral ring. Must be a power of
/// two because the allocator masks the `lock xadd` counter with
/// `kEphemeralRingSlots - 1`. 16 is enough headroom for printf-style
/// call sites that consume several mx_str_get return values before
/// the oldest slot gets recycled.
inline constexpr uint32_t kEphemeralRingSlots      = 16;

/// Byte size of one scratch slot. Must be a power of two so the
/// allocator can compute the slot offset with `shl` instead of
/// `imul`. Strings whose plaintext length exceeds
/// `kEphemeralMaxStringLength` are filtered out of S3 protection by
/// the pass — the caller keeps a plaintext LEA to those.
inline constexpr uint32_t kEphemeralSlotSize       = 256;

/// Maximum plaintext length (in bytes) that fits inside one scratch
/// slot. One byte is reserved for a trailing NUL so callers that
/// treat the return value as a C string do not read past the end.
inline constexpr uint32_t kEphemeralMaxStringLength = kEphemeralSlotSize - 1;

/// Byte size of the ring counter. Lives at offset 0 of the scratch
/// ring area; the first slot starts at offset `kEphemeralRingHeaderSize`.
inline constexpr uint32_t kEphemeralRingHeaderSize  = 4;

/// Total size of the scratch ring area that the pass appends to the
/// `.mxstr` section after the ciphertext pool: one header-sized
/// counter followed by `kEphemeralRingSlots` slots.
inline constexpr size_t kEphemeralRingTotalSize =
    kEphemeralRingHeaderSize +
    static_cast<size_t>(kEphemeralRingSlots) * kEphemeralSlotSize;

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

/// Emit the S3 ephemeral mx_str_get decryptor. All three
/// `lea rip+disp32` operands (desc table, data pool, scratch ring)
/// are left zeroed; the returned struct reports their offsets for
/// the pass to patch once section RVAs are final.
[[nodiscard]] EmittedEphemeralDecryptor emit_mx_str_get_ephemeral();

/// Emit a single trampoline for the xref described by `req`. The
/// string_id is baked into the bytes. The `call rel32` operand is
/// left zeroed; its offset is recorded in the returned struct.
[[nodiscard]] EmittedTrampoline
emit_trampoline(const TrampolineRequest& req);

} // namespace mx::string_protect
