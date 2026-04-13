/**
 * @file vm_runtime_gen.cpp
 * @brief [BUILDER] VmRuntimeGenerator — threaded-code VM with rolling-key stream cipher.
 *
 * Architecture (per build, per region):
 *
 *   entry_stub:
 *     pushfq                              ; save rflags
 *     push r15..rax                       ; save 15 GPRs (rsp skipped)
 *     push rax                            ; JUNK push — reserves rolling-key scratch slot
 *     mov byte ptr [rsp + 0], INITIAL_KEY ; seed rolling key
 *     lea r11, [rip + bytecode]           ; vpc
 *     <inline fetch-and-dispatch tail>    ; jump to first handler via handler_table
 *
 *   handler_N:
 *     <operand fetches via rolling key>
 *     <body (ALU / memory / native)>
 *     <inline fetch-and-dispatch tail>    ; jump to NEXT handler via handler_table
 *
 *   exit_handler:
 *     pop  rax..r15  (skip rsp)
 *     add  rsp, 8                          ; discard junk/key slot
 *     popfq
 *     ret
 *
 *   handler_table:
 *     int32[total_handlers]               ; each entry = handler_offset - table_offset
 *     (used by every tail-dispatch via `movsxd rax, [rcx + rax*4]; add rcx, rax; jmp rcx`)
 *
 *   bytecode:
 *     stream-encrypted with rolling key:
 *       enc[i] = plain[i] ^ key[i]
 *       key[i+1] = key[i] ^ plain[i]
 *     Initial key = INITIAL_KEY (per-build random byte).
 *
 * VM stack layout after entry (rsp = caller_rsp - 144):
 *
 *   [rsp +   0] = slot 0  \
 *   [rsp +   8] = slot 1   \
 *       ...                 > 16 slots total (one is the "junk slot", host
 *   [rsp + 120] = slot 15  /  of the rolling-key byte; the other 15 hold
 *                         /   the saved native GPRs in a per-build order).
 *   [rsp + 128] = rflags
 *   [rsp + 136] = CALL return address (back to caller instruction stream)
 *
 * Per-build, `VmRegLayout` randomizes:
 *   - which slot each native GPR lives in (native_to_slot / slot_to_native)
 *   - which slot is the junk / rolling-key host (junk_slot)
 *   - consequently, the rolling-key disp = junk_slot * 8
 *
 * The bytecode operand bytes are remapped at emission time from native-reg
 * indices (produced by the lifter) to virtual-slot indices, so the handlers
 * don't need a runtime lookup — they just use `slot * 8` as the offset.
 *
 * The native-escape handler additionally `sub rsp, 16` to reserve a vpc save
 * slot, then `add rsp, 168` around the raw native bytes so the instruction
 * sees the caller's frame. Context loads/stores during native use
 * [rsp + 24 + slot*8].
 *
 * Per-build randomization summary:
 *   - INITIAL_KEY (non-zero)
 *   - handler_id permutation (VmOp → handler_id)
 *   - register layout (native → slot permutation + junk-slot selection)
 *   - vflags_key (xor scramble for saved RFLAGS)
 *   - table_xor_key (handler-table encryption)
 *   - NO central dispatcher (threaded code — every handler ends with a
 *     `lea rcx, [rip + table]; movsxd rax, [rcx+rax*4]; add rcx, rax; jmp rcx`
 *     so the reverser cannot see a single dispatch point in IDA's CFG)
 */

#include "mxprotector/protection/vm/vm_runtime_gen.hpp"
#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/cfg/mba_transition_gen.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <numeric>

namespace mx::vm {

namespace {

// ============================================================================
// Stack layout constants (must match entry prologue below)
// ============================================================================

/// VM context layout constants. Virtual slot v lives at `[rsp + v*8]` regardless
/// of which native reg is stored there — the native-to-slot mapping is randomized
/// per-build (see VmRegLayout below). Slot-to-native mapping is captured by the
/// entry stub's push order and by bytecode operand remapping at emission time.
///
/// The "junk slot" is one of the 16 slots that does NOT host a real native reg;
/// it hosts the rolling-key scratch byte. Which slot it is, is chosen at random
/// per-build.
constexpr int32_t kRflagsOffset      = 128;  ///< rflags at [rsp + 128]
constexpr int32_t kContextSize       = 136;  ///< 16*8 (regs) + rflags(8) = 136

/// Per-build random mapping between native GPRs (0..15, minus 4=RSP) and
/// virtual context slots (0..15, minus the junk slot).
///
/// Properties:
///   - slot_to_native[v] ∈ [0..15], or 0xFF if v is the junk slot
///   - native_to_slot[n] is the slot holding native reg n; 0xFF if n == 4 (RSP)
///   - exactly one v has slot_to_native[v] == 0xFF, and that v == junk_slot
///   - rolling_key_disp = junk_slot * 8
struct VmRegLayout {
    std::array<uint8_t, 16> slot_to_native{};
    std::array<uint8_t, 16> native_to_slot{};
    uint8_t  junk_slot         = 0;
    int32_t  rolling_key_disp  = 0;
};

/// Build a random register layout. RSP (native 4) is never pushed; the slot
/// that "would" hold it is instead the junk / rolling-key slot.
[[nodiscard]] inline VmRegLayout make_random_layout(Randomizer& rng) {
    VmRegLayout L{};
    // Start with identity permutation of 16 slots...
    std::array<uint8_t, 16> perm{};
    std::iota(perm.begin(), perm.end(), static_cast<uint8_t>(0));
    // ...then Fisher–Yates shuffle.
    for (size_t i = 15; i > 0; --i) {
        const uint32_t j = rng.next_range(0, static_cast<uint32_t>(i));
        std::swap(perm[i], perm[j]);
    }
    // perm[v] == native reg stored at slot v.
    L.slot_to_native = perm;
    L.native_to_slot.fill(0xFF);
    for (uint8_t v = 0; v < 16; ++v) {
        L.native_to_slot[perm[v]] = v;
    }
    // Native 4 = RSP cannot really be pushed; its slot becomes the junk slot.
    L.junk_slot = L.native_to_slot[4];
    L.slot_to_native[L.junk_slot] = 0xFF;
    L.native_to_slot[4] = 0xFF;
    L.rolling_key_disp = static_cast<int32_t>(L.junk_slot) * 8;
    return L;
}

/// Frame shift between the caller's rsp (at CALL time) and vm_rsp inside a
/// native handler after `sub rsp, 16` (vpc scratch). Used to restore the
/// caller's rsp for the native instruction body.
///
///   8 (ret)  + 8 (rflags)  + 128 (16 regs)  + 16 (native scratch)  =  160
constexpr int32_t kNativeFrameShift = 168;

// ============================================================================
// RawEmitter — tiny byte buffer with pos tracking
// ============================================================================

struct RawEmitter {
    ByteBuffer buf;

    void u8(uint8_t b) { buf.push_back(b); }
    void u16(uint16_t v) { u8(static_cast<uint8_t>(v)); u8(static_cast<uint8_t>(v >> 8)); }
    void u32(uint32_t v) {
        u8(static_cast<uint8_t>(v));
        u8(static_cast<uint8_t>(v >> 8));
        u8(static_cast<uint8_t>(v >> 16));
        u8(static_cast<uint8_t>(v >> 24));
    }
    void u64(uint64_t v) {
        u32(static_cast<uint32_t>(v));
        u32(static_cast<uint32_t>(v >> 32));
    }
    void bytes(ByteView data) {
        buf.insert(buf.end(), data.begin(), data.end());
    }
    size_t size() const noexcept { return buf.size(); }
};

// ============================================================================
// Atomic x64 encoders
// ============================================================================

/// movzx r32, byte ptr [base + disp]    (0F B6 /r)
void emit_movzx_r32_byte_mem(RawEmitter& e, uint8_t dst_reg,
                              uint8_t base_reg, int32_t disp)
{
    const bool rex_r = dst_reg >= 8;
    const bool rex_b = base_reg >= 8;
    if (rex_b || rex_r) {
        uint8_t rex = 0x40;
        if (rex_r) rex |= 0x04;
        if (rex_b) rex |= 0x01;
        e.u8(rex);
    }
    e.u8(0x0F);
    e.u8(0xB6);

    const uint8_t dst3  = dst_reg & 0x07;
    const uint8_t base3 = base_reg & 0x07;
    const bool needs_sib = (base3 == 4);  // RSP/R12 encode requires SIB
    const bool base_is_rbp = (base3 == 5); // RBP/R13: disp=0 needs disp8

    if (disp == 0 && !base_is_rbp) {
        e.u8(static_cast<uint8_t>((0 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

/// xor reg8_low, byte ptr [rsp + disp]   (32 /r)
/// For reg 4..7 (SPL/BPL/SIL/DIL) and reg 8..15, force a REX prefix.
void emit_xor_r8l_rsp_disp(RawEmitter& e, uint8_t reg, int32_t disp) {
    if (reg >= 8) {
        e.u8(0x44);  // REX.R
    } else if (reg >= 4) {
        e.u8(0x40);  // empty REX to force SPL/BPL/SIL/DIL (we only use 0..3 anyway)
    }
    e.u8(0x32);

    const uint8_t reg3 = reg & 0x07;
    if (disp == 0) {
        e.u8(static_cast<uint8_t>((0 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

/// xor byte ptr [rsp + disp], reg8_low   (30 /r)
void emit_xor_rsp_disp_r8l(RawEmitter& e, uint8_t reg, int32_t disp) {
    if (reg >= 8) {
        e.u8(0x44);
    } else if (reg >= 4) {
        e.u8(0x40);
    }
    e.u8(0x30);

    const uint8_t reg3 = reg & 0x07;
    if (disp == 0) {
        e.u8(static_cast<uint8_t>((0 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

void emit_inc_r11(RawEmitter& e) {
    // inc r11 = 49 FF C3
    e.u8(0x49); e.u8(0xFF); e.u8(0xC3);
}

size_t emit_lea_r11_rip_rel32(RawEmitter& e) {
    // lea r11, [rip + rel32]  = 4C 8D 1D rel32
    e.u8(0x4C); e.u8(0x8D); e.u8(0x1D);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

size_t emit_lea_rcx_rip_rel32(RawEmitter& e) {
    // lea rcx, [rip + rel32]  = 48 8D 0D rel32
    e.u8(0x48); e.u8(0x8D); e.u8(0x0D);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

/// Emit `lea <reg>, [rip + rel32]` for any reg index 0..15. Returns the
/// file offset of the rel32 placeholder so the caller can patch it.
///
///   Encoding: [REX.W|REX.WR] 8D (00 dst 101) rel32
///   REX is 48 for r0..r7 and 4C for r8..r15.
///   ModRM reg field is dst & 7.
///
/// Used by the tail dispatch to randomize which GPR holds the handler table.
size_t emit_lea_reg_rip_rel32(RawEmitter& e, uint8_t reg) {
    const uint8_t rex = (reg >= 8) ? 0x4C : 0x48;
    e.u8(rex);
    e.u8(0x8D);
    // ModRM: mod=00, reg=dst, rm=101 (RIP-relative marker)
    e.u8(static_cast<uint8_t>(((reg & 0x07) << 3) | 0x05));
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

void emit_ud2(RawEmitter& e) { e.u8(0x0F); e.u8(0x0B); }
void emit_ret(RawEmitter& e) { e.u8(0xC3); }
void emit_pushfq(RawEmitter& e) { e.u8(0x9C); }
void emit_popfq(RawEmitter& e) { e.u8(0x9D); }

void emit_push_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x50 + (reg & 0x07));
}
void emit_pop_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x58 + (reg & 0x07));
}

/// add rsp, imm32  — uses full imm32 form for any displacement
void emit_add_rsp_imm32(RawEmitter& e, int32_t imm) {
    // 48 81 C4 imm32
    e.u8(0x48); e.u8(0x81); e.u8(0xC4); e.u32(static_cast<uint32_t>(imm));
}

/// sub rsp, imm32
void emit_sub_rsp_imm32(RawEmitter& e, int32_t imm) {
    // 48 81 EC imm32
    e.u8(0x48); e.u8(0x81); e.u8(0xEC); e.u32(static_cast<uint32_t>(imm));
}

/// Patch a rel32 placeholder so it jumps from `instruction_end` to `target`.
void patch_rel32(ByteBuffer& buf, size_t patch_offset, size_t instruction_end,
                 size_t target_offset)
{
    const auto rel = static_cast<int32_t>(
        static_cast<int64_t>(target_offset) - static_cast<int64_t>(instruction_end));
    std::memcpy(buf.data() + patch_offset, &rel, sizeof(int32_t));
}

// ============================================================================
// Rolling-key fetch helpers
// ============================================================================
//
// Each fetch:
//    1) movzx r32, byte [r11]           — load encrypted byte
//    2) xor r8_low, [rsp + keyDisp]     — decrypt with current key
//    3) xor [rsp + keyDisp], r8_low     — update key ^= decrypted_byte
//    4) inc r11                         — advance vpc
//
// After step 2, the low 8 bits of the destination register hold the plain
// byte; the upper bits are zero (from the movzx).

/// Fetch one byte into dst_reg (0..3 — rax/rcx/rdx/rbx), decrypt with key.
/// When `rolling` is true the key byte is updated after decryption (stream
/// cipher). When false the key stays constant (static XOR — used for regions
/// containing virtual branches where key-state synchronisation at branch
/// targets is non-trivial).
void emit_fetch_byte(RawEmitter& e, uint8_t dst_reg, int32_t key_disp,
                     bool rolling = true) {
    emit_movzx_r32_byte_mem(e, dst_reg, 11, 0);
    emit_xor_r8l_rsp_disp(e, dst_reg, key_disp);
    if (rolling) {
        emit_xor_rsp_disp_r8l(e, dst_reg, key_disp);
    }
    emit_inc_r11(e);
}

/// Fetch 4 bytes into eax (little-endian), key-decrypted.
void emit_fetch_dword(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 0 /*rax*/, key_disp, rolling);
    for (int i = 1; i < 4; ++i) {
        emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
        e.u8(0xC1); e.u8(0xE1); e.u8(static_cast<uint8_t>(i * 8));
        e.u8(0x09); e.u8(0xC8);
    }
}

/// Fetch 8 bytes into rax (little-endian), key-decrypted.
void emit_fetch_qword(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 0 /*rax*/, key_disp, rolling);
    for (int i = 1; i < 8; ++i) {
        emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
        e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(static_cast<uint8_t>(i * 8));
        e.u8(0x48); e.u8(0x09); e.u8(0xC8);
    }
}

/// Fetch two operand bytes: cl = dst_idx, dl = src_idx (masked 0x0F).
void emit_fetch_2_operand_bytes(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
    emit_fetch_byte(e, 2 /*rdx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE2); e.u8(0x0F);
}

/// Fetch one operand byte: cl = dst_idx (masked).
void emit_fetch_1_operand_byte(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
}

// ============================================================================
// VM-reg address helpers: compute &ctx[reg_idx] into rsi/rdi
// ============================================================================

/// rsi = rsp + rcx * 8 (ctx[reg_idx])
///   shl rcx, 3                     48 C1 E1 03
///   lea rsi, [rsp + rcx*1]         48 8D 34 0C  (mod=00, SIB: scale=0, idx=rcx, base=rsp)
void emit_vmreg_addr_rsi_from_rcx(RawEmitter& e) {
    e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x34); e.u8(0x0C);
}

/// rdi = rsp + rdx * 8 (ctx[reg_idx])
///   shl rdx, 3                     48 C1 E2 03
///   lea rdi, [rsp + rdx*1]         48 8D 3C 14
void emit_vmreg_addr_rdi_from_rdx(RawEmitter& e) {
    e.u8(0x48); e.u8(0xC1); e.u8(0xE2); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x14);
}

// ============================================================================
// Tail dispatch (inlined at end of each handler): fetch next opcode via
// rolling key, look up handler in the handler_table, jump.
// ============================================================================

struct TailDispatchPatch {
    size_t rel32_offset;      ///< offset of the rel32 inside `lea rcx, [rip+rel32]`
    size_t instruction_end;   ///< byte just after the rel32
};

// ---------------------------------------------------------------------------
// vEFLAGS polymorphism
// ---------------------------------------------------------------------------
//
// Every store and every descramble site picks a random variant from a small
// pool of semantically-equivalent byte sequences. This breaks YARA-style
// signature matching across the binary (each sub-VM has 60+ store sites and
// 20+ descramble sites — signing them with one regex used to work).
//
// rol(key, n) is the "pre-rotated" key: rol(real, n) ^ key == rol(real ^ ror(key,n), n)
// so `xor-then-rol` uses ror(key, n) while `rol-then-xor` uses key directly.

/// Rotate a 32-bit value right by n (modulo 32).
[[nodiscard]] inline uint32_t ror32(uint32_t v, uint32_t n) noexcept {
    n &= 31;
    return (n == 0) ? v : (v >> n) | (v << (32 - n));
}

/// Variant selector for vEFLAGS store (write scrambled rflags to slot).
enum class VflagsStoreV : uint8_t {
    RaxRolFirst = 0,  // pushfq; pop rax; rol eax,n; xor eax,key; mov slot,rax
    RaxXorFirst = 1,  // pushfq; pop rax; xor eax,ror(key,n); rol eax,n; mov slot,rax
    InPlace     = 2,  // pushfq; rol [rsp],n; xor [rsp],key; pop qword slot
    kCount      = 3
};

/// Variant selector for vEFLAGS descramble-then-popfq.
enum class VflagsPopfqV : uint8_t {
    RaxXorFirst = 0,  // mov eax,slot; xor eax,key; ror eax,n; push rax; popfq
    RaxRorFirst = 1,  // mov eax,slot; ror eax,n; xor eax,ror(key,n); push rax; popfq
    InPlace     = 2,  // push qword slot; xor [rsp],key; ror [rsp],n; popfq
    kCount      = 3
};

/// Variant selector for vEFLAGS descramble-into-ecx (VJCC bit testing).
enum class VflagsToEcxV : uint8_t {
    XorFirst = 0,     // mov ecx,slot; xor ecx,key; ror ecx,n
    RorFirst = 1,     // mov ecx,slot; ror ecx,n; xor ecx,ror(key,n)
    kCount   = 2
};

[[nodiscard]] inline VflagsStoreV pick_store_variant(Randomizer& rng) {
    return static_cast<VflagsStoreV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsStoreV::kCount) - 1));
}
[[nodiscard]] inline VflagsPopfqV pick_popfq_variant(Randomizer& rng) {
    return static_cast<VflagsPopfqV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsPopfqV::kCount) - 1));
}
[[nodiscard]] inline VflagsToEcxV pick_to_ecx_variant(Randomizer& rng) {
    return static_cast<VflagsToEcxV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsToEcxV::kCount) - 1));
}

/// Helper: emit `mov [rsp + disp], rax` (48 89 84 24 disp32).
inline void emit_mov_rsp_disp_rax(RawEmitter& e, int32_t disp) {
    e.u8(0x48); e.u8(0x89); e.u8(0x84); e.u8(0x24);
    e.u32(static_cast<uint32_t>(disp));
}

/// Helper: emit `mov eax, [rsp + disp]` (8B 84 24 disp32).
inline void emit_mov_eax_rsp_disp(RawEmitter& e, int32_t disp) {
    e.u8(0x8B); e.u8(0x84); e.u8(0x24);
    e.u32(static_cast<uint32_t>(disp));
}

/// Helper: emit `xor eax, imm32` (35 imm32).
inline void emit_xor_eax_imm32(RawEmitter& e, uint32_t imm) {
    e.u8(0x35); e.u32(imm);
}

/// Helper: emit `rol eax, imm8` (C1 C0 imm8).
inline void emit_rol_eax_imm8(RawEmitter& e, uint8_t imm) {
    e.u8(0xC1); e.u8(0xC0); e.u8(imm);
}

/// Helper: emit `ror eax, imm8` (C1 C8 imm8).
inline void emit_ror_eax_imm8(RawEmitter& e, uint8_t imm) {
    e.u8(0xC1); e.u8(0xC8); e.u8(imm);
}

/// vEFLAGS store (polymorphic). Writes `rol(real_rflags, rol) ^ key` into
/// [rsp + rflags_disp].
///
/// All three variants clobber rax or no registers at all (see `InPlace`).
/// Caller is responsible for saving/restoring rax if needed (native handler
/// does this via its scratch slot).
void emit_vflags_store(RawEmitter& e, VflagsStoreV variant,
                       uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    switch (variant) {
        case VflagsStoreV::RaxRolFirst: {
            // 9C        pushfq
            // 58        pop rax
            // C1 C0 n   rol eax, n
            // 35 k32    xor eax, key
            // 48 89 ..  mov [rsp+disp], rax
            e.u8(0x9C); e.u8(0x58);
            if (n != 0) emit_rol_eax_imm8(e, n);
            if (vflags_key != 0) emit_xor_eax_imm32(e, vflags_key);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsStoreV::RaxXorFirst: {
            // 9C        pushfq
            // 58        pop rax
            // 35 k'32   xor eax, ror(key, n)
            // C1 C0 n   rol eax, n
            // 48 89 ..  mov [rsp+disp], rax
            const uint32_t k_pre = ror32(vflags_key, n);
            e.u8(0x9C); e.u8(0x58);
            if (vflags_key != 0) emit_xor_eax_imm32(e, k_pre);
            if (n != 0) emit_rol_eax_imm8(e, n);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsStoreV::InPlace: {
            // 9C                pushfq
            // C1 04 24 n        rol dword [rsp], n
            // 81 34 24 k32      xor dword [rsp], key
            // 8F 84 24 disp32   pop qword [rsp+disp]
            //
            // pop with [rsp+disp] computes the destination address AFTER the
            // rsp increment (Intel SDM), so disp relative to the AFTER-pop rsp
            // is the same as the original rflags_disp.
            e.u8(0x9C);
            if (n != 0) { e.u8(0xC1); e.u8(0x04); e.u8(0x24); e.u8(n); }
            if (vflags_key != 0) {
                e.u8(0x81); e.u8(0x34); e.u8(0x24); e.u32(vflags_key);
            }
            e.u8(0x8F); e.u8(0x84); e.u8(0x24);
            e.u32(static_cast<uint32_t>(rflags_disp));
            return;
        }
        case VflagsStoreV::kCount: break;
    }
}

/// vEFLAGS descramble-and-popfq (polymorphic). Reads the scrambled slot,
/// descrambles, and loads the real RFLAGS into CPU. Clobbers rax (except
/// for the `InPlace` variant which uses no scratch register).
void emit_vflags_popfq(RawEmitter& e, VflagsPopfqV variant,
                       uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    switch (variant) {
        case VflagsPopfqV::RaxXorFirst: {
            // 8B 84 ..  mov eax, [rsp+disp]
            // 35 k32    xor eax, key
            // C1 C8 n   ror eax, n
            // 50        push rax
            // 9D        popfq
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (vflags_key != 0) emit_xor_eax_imm32(e, vflags_key);
            if (n != 0) emit_ror_eax_imm8(e, n);
            e.u8(0x50); e.u8(0x9D);
            return;
        }
        case VflagsPopfqV::RaxRorFirst: {
            // 8B 84 ..  mov eax, [rsp+disp]
            // C1 C8 n   ror eax, n
            // 35 k'32   xor eax, ror(key, n)
            // 50        push rax
            // 9D        popfq
            const uint32_t k_post = ror32(vflags_key, n);
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (n != 0) emit_ror_eax_imm8(e, n);
            if (vflags_key != 0) emit_xor_eax_imm32(e, k_post);
            e.u8(0x50); e.u8(0x9D);
            return;
        }
        case VflagsPopfqV::InPlace: {
            // FF B4 24 disp32   push qword [rsp+disp]
            // 81 34 24 k32      xor dword [rsp], key
            // C1 0C 24 n        ror dword [rsp], n
            // 9D                popfq
            //
            // `push qword [rsp+disp]` uses the rsp value BEFORE the push
            // decrement for the source address. disp remains the original
            // rflags_disp.
            e.u8(0xFF); e.u8(0xB4); e.u8(0x24);
            e.u32(static_cast<uint32_t>(rflags_disp));
            if (vflags_key != 0) {
                e.u8(0x81); e.u8(0x34); e.u8(0x24); e.u32(vflags_key);
            }
            if (n != 0) { e.u8(0xC1); e.u8(0x0C); e.u8(0x24); e.u8(n); }
            e.u8(0x9D);
            return;
        }
        case VflagsPopfqV::kCount: break;
    }
}

/// vEFLAGS load-to-eax (non-polymorphic). Reads and descrambles into eax.
/// Only used by code paths that need the descrambled value in a register but
/// not to popfq. Currently unused — left in for future call sites.
void emit_vflags_load_to_eax(RawEmitter& e, uint32_t vflags_key,
                             uint32_t vflags_rol, int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    emit_mov_eax_rsp_disp(e, rflags_disp);
    if (vflags_key != 0) emit_xor_eax_imm32(e, vflags_key);
    if (n != 0) emit_ror_eax_imm8(e, n);
}

/// Variant selector for in-slot transforms (entry scramble / exit descramble).
enum class VflagsInSlotV : uint8_t {
    RegXorFirst = 0,  // mov eax,[slot]; xor/rol-or-ror; mov [slot],rax  (rax scratch)
    RegRorFirst = 1,  // mov eax,[slot]; ror/rol-or-xor; mov [slot],rax  (rax scratch)
    MemXorFirst = 2,  // xor dword [slot],k; rol/ror dword [slot],n      (no scratch)
    MemRorFirst = 3,  // rol/ror dword [slot],n; xor dword [slot],k'     (no scratch)
    kCount      = 4
};

[[nodiscard]] inline VflagsInSlotV pick_inslot_variant(Randomizer& rng) {
    return static_cast<VflagsInSlotV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsInSlotV::kCount) - 1));
}

/// In-slot FORWARD transform: [slot] (raw rflags) → [slot] (scrambled).
/// Used by the entry stub right after pushfq/16 pushes to convert the
/// freshly-saved rflags into the scrambled form the handlers expect.
///   forward = rol(real, n) ^ key
void emit_vflags_inslot_scramble(RawEmitter& e, VflagsInSlotV variant,
                                  uint32_t vflags_key, uint32_t vflags_rol,
                                  int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    const uint32_t k = vflags_key;
    const uint32_t k_pre = ror32(k, n);

    auto emit_xor_mem_imm32 = [&](uint32_t val) {
        // xor dword [rsp + disp], imm32    81 B4 24 disp32 imm32
        e.u8(0x81); e.u8(0xB4); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u32(val);
    };
    auto emit_rol_mem_imm8 = [&](uint8_t amt) {
        // rol dword [rsp + disp], imm8    C1 84 24 disp32 imm8
        e.u8(0xC1); e.u8(0x84); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u8(amt);
    };

    switch (variant) {
        case VflagsInSlotV::RegXorFirst: {
            // mov eax,[slot]; rol eax,n; xor eax,k; mov [slot],rax
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (n != 0) emit_rol_eax_imm8(e, n);
            if (k != 0) emit_xor_eax_imm32(e, k);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::RegRorFirst: {
            // mov eax,[slot]; xor eax,k_pre; rol eax,n; mov [slot],rax
            // (xor-then-rol ≡ rol-then-xor-with-rol(k_pre,n)=k)
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (k != 0) emit_xor_eax_imm32(e, k_pre);
            if (n != 0) emit_rol_eax_imm8(e, n);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::MemXorFirst: {
            // xor dword [slot], k_pre; rol dword [slot], n
            if (k != 0) emit_xor_mem_imm32(k_pre);
            if (n != 0) emit_rol_mem_imm8(n);
            return;
        }
        case VflagsInSlotV::MemRorFirst: {
            // rol dword [slot], n; xor dword [slot], k
            if (n != 0) emit_rol_mem_imm8(n);
            if (k != 0) emit_xor_mem_imm32(k);
            return;
        }
        case VflagsInSlotV::kCount: break;
    }
}

/// In-slot REVERSE transform: [slot] (scrambled) → [slot] (raw rflags).
/// Used by the exit stub just before the final popfq so the popfq loads
/// real rflags into the CPU without clobbering live regs after.
///   reverse = ror(slot ^ key, n) = ror(slot, n) ^ ror(key, n)
void emit_vflags_inslot_descramble(RawEmitter& e, VflagsInSlotV variant,
                                    uint32_t vflags_key, uint32_t vflags_rol,
                                    int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    const uint32_t k = vflags_key;
    const uint32_t k_post = ror32(k, n);

    auto emit_xor_mem_imm32 = [&](uint32_t val) {
        e.u8(0x81); e.u8(0xB4); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u32(val);
    };
    auto emit_ror_mem_imm8 = [&](uint8_t amt) {
        // ror dword [rsp + disp], imm8    C1 8C 24 disp32 imm8
        e.u8(0xC1); e.u8(0x8C); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u8(amt);
    };

    switch (variant) {
        case VflagsInSlotV::RegXorFirst: {
            // mov eax,[slot]; xor eax,k; ror eax,n; mov [slot],rax
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (k != 0) emit_xor_eax_imm32(e, k);
            if (n != 0) emit_ror_eax_imm8(e, n);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::RegRorFirst: {
            // mov eax,[slot]; ror eax,n; xor eax,k_post; mov [slot],rax
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (n != 0) emit_ror_eax_imm8(e, n);
            if (k != 0) emit_xor_eax_imm32(e, k_post);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::MemXorFirst: {
            // xor dword [slot], k; ror dword [slot], n
            if (k != 0) emit_xor_mem_imm32(k);
            if (n != 0) emit_ror_mem_imm8(n);
            return;
        }
        case VflagsInSlotV::MemRorFirst: {
            // ror dword [slot], n; xor dword [slot], k_post
            if (n != 0) emit_ror_mem_imm8(n);
            if (k != 0) emit_xor_mem_imm32(k_post);
            return;
        }
        case VflagsInSlotV::kCount: break;
    }
}

/// vEFLAGS descramble-to-ecx (polymorphic). Used by VJCC which needs the
/// descrambled value in ecx for subsequent bit tests.
void emit_vflags_to_ecx(RawEmitter& e, VflagsToEcxV variant,
                        uint32_t vflags_key, uint32_t vflags_rol,
                        int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    // mov ecx, [rsp + rflags_disp]    8B 8C 24 disp32
    e.u8(0x8B); e.u8(0x8C); e.u8(0x24);
    e.u32(static_cast<uint32_t>(rflags_disp));

    if (variant == VflagsToEcxV::XorFirst) {
        if (vflags_key != 0) {
            // xor ecx, imm32    81 F1 imm32
            e.u8(0x81); e.u8(0xF1); e.u32(vflags_key);
        }
        if (n != 0) {
            // ror ecx, imm8     C1 C9 imm8
            e.u8(0xC1); e.u8(0xC9); e.u8(n);
        }
    } else {
        // RorFirst: ror first, then xor with ror(key, n)
        if (n != 0) { e.u8(0xC1); e.u8(0xC9); e.u8(n); }
        if (vflags_key != 0) {
            const uint32_t k_post = ror32(vflags_key, n);
            e.u8(0x81); e.u8(0xF1); e.u32(k_post);
        }
    }
}

// ---------------------------------------------------------------------------
// Handler polymorphism: junk prologue + tail dispatch variants.
// ---------------------------------------------------------------------------
//
// Without polymorphism, every handler has the same byte shape at its start
// and its end: fixed handler body, then a verbatim tail dispatch using `rcx`
// as the table base and `jmp rcx` as the indirect branch. That's a strong
// signature — 60+ handlers per build all begin the same way and all end the
// same way, and YARA / statistical analysis picks them up trivially.
//
// Two independent dimensions of polymorphism:
//
//   1. Junk prologue: 0–12 bytes of safe no-ops injected at the start of
//      every handler. Uses the canonical x86 multi-byte NOP forms so the
//      bytes don't look random — they disassemble as `nop` with varying
//      ModRM/SIB encoding so IDA sees them as legitimate filler rather
//      than obfuscation.
//
//   2. Tail dispatch variants. All variants compute the same target
//      address, but:
//      - pick a different GPR as the table base (13 options minus r11,
//        which holds the vpc — any other reg is safe because the next
//        handler reads context from [rsp+slot*8], not from registers)
//      - pick a different indirect-jump shape: direct `jmp reg` vs
//        `push reg + ret`, which look completely different at the byte
//        level and split downstream return-stack prediction in useful ways
//
// Each handler picks variants independently at emission time via rng.

/// Emit a random multi-byte NOP of `size` bytes (1–15). Uses Intel's
/// canonical multi-byte NOP forms which every decoder recognizes as filler.
void emit_nop_run(RawEmitter& e, uint8_t size) {
    const auto nop = x86::make_nop(size);
    for (uint8_t b : nop) e.u8(b);
}

/// Emit a random junk prologue of 0–max_bytes bytes at the current position.
/// max_bytes is clamped to 12 so a handler never pays more than ~12 bytes
/// of alignment padding.
void emit_junk_prologue(RawEmitter& e, Randomizer& rng, uint32_t max_bytes = 8) {
    if (max_bytes == 0) return;
    // Zero-byte prologue is a valid variant (roughly 1/N of handlers).
    const uint32_t total = rng.next_range(0, max_bytes);
    uint32_t remaining = total;
    while (remaining > 0) {
        // Single NOPs of length 1..9 — Intel documents up to NOP9 in the
        // optimization manual. Larger NOPs are synthesized from smaller ones.
        const uint8_t chunk = static_cast<uint8_t>(
            (remaining > 9) ? 9 : remaining);
        emit_nop_run(e, chunk);
        remaining -= chunk;
    }
}

/// Which shape the tail dispatch uses for its indirect branch.
enum class DispatchShape : uint8_t {
    JmpReg       = 0,   ///< jmp <table_base>               FF E0 + reg
    PushRegRet   = 1,   ///< push <table_base>; ret         50+r ; C3
    kCount       = 2
};

[[nodiscard]] inline DispatchShape pick_dispatch_shape(Randomizer& rng) {
    return static_cast<DispatchShape>(rng.next_range(0,
        static_cast<uint32_t>(DispatchShape::kCount) - 1));
}

/// Pick a GPR to use as the table base in the tail dispatch.
///
/// Valid candidates are every GPR except:
///   - rax (0) — already holds the decrypted opcode index
///   - r11 (11) — holds the live vpc, must not be clobbered
///
/// All other regs are safe: the next handler reloads its operands from the
/// VM context slots on the stack, and the saved reg values live in those
/// slots independently of the current CPU register contents. On exit, every
/// slot is popped back into its native register, overwriting whatever the
/// tail dispatch left behind.
[[nodiscard]] inline uint8_t pick_table_base_reg(Randomizer& rng) {
    static constexpr uint8_t candidates[] = {
        1,   // rcx
        2,   // rdx
        3,   // rbx
        6,   // rsi
        7,   // rdi
        8,   // r8
        9,   // r9
        10,  // r10
        12,  // r12
        13,  // r13
        14,  // r14
        15,  // r15
    };
    const uint32_t idx = rng.next_range(0,
        static_cast<uint32_t>(std::size(candidates)) - 1);
    return candidates[idx];
}

/// Emit `mov eax, dword [base + rax*4]` for any GPR `base` (0..15).
///
///   Encoding: [REX.B] 8B mod_reg_rm SIB [disp8]
///   ModRM: reg=000 (eax), rm=100 (SIB follows).
///   SIB:   scale=10 (x4), index=000 (rax), base=base_low.
///
/// Quirk: when (base & 7) == 5 — i.e. rbp or r13 — using mod=00 makes the
/// x86-64 decoder treat the SIB base field as "disp32 only, no base". To
/// actually use that register as a base, the instruction must carry a
/// displacement, so we force mod=01 with disp8=0. Adds 1 byte but decodes
/// as `[r13 + rax*4 + 0]`, which is semantically identical to the desired
/// `[r13 + rax*4]`.
void emit_mov_eax_from_base_rax4(RawEmitter& e, uint8_t base) {
    if (base >= 8) e.u8(0x41);          // REX.B for r8..r15
    e.u8(0x8B);                          // MOV r32, r/m32
    const uint8_t base_low = base & 0x07;
    const uint8_t sib = static_cast<uint8_t>(0x80 | base_low); // scale=x4 index=rax
    if (base_low == 5) {
        // mod=01, reg=000, rm=100 (SIB) → 0x44   + SIB + disp8=0
        e.u8(0x44);
        e.u8(sib);
        e.u8(0x00);
    } else {
        // mod=00, reg=000, rm=100 (SIB) → 0x04   + SIB
        e.u8(0x04);
        e.u8(sib);
    }
}

/// Emit `add <base>, rax` for any GPR base (0..15).
///   Encoding: REX.W[|REX.B] 01 C0|C_rb  — ADD r/m64, r64 (reg=rax, rm=base)
void emit_add_base_rax(RawEmitter& e, uint8_t base) {
    const uint8_t rex = 0x48 | ((base >= 8) ? 0x01 : 0x00);
    e.u8(rex);
    e.u8(0x01);
    // ModRM: mod=11 reg=000 (rax) rm=base_low
    e.u8(static_cast<uint8_t>(0xC0 | (base & 0x07)));
}

/// Emit `jmp <reg>` for any GPR 0..15.    [REX.B] FF E0+reg_low
void emit_jmp_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0xFF);
    e.u8(static_cast<uint8_t>(0xE0 | (reg & 0x07)));
}

/// Emits the tail dispatch stub. Caller must collect the returned patch and
/// fix it up to point at the handler_table once the table offset is known.
///
/// Polymorphism:
///   - If `save_rflags` is set, a random vEFLAGS store variant is emitted.
///   - The table-base register is picked randomly each call (13 options).
///   - The indirect-branch shape is picked randomly (direct `jmp reg` or
///     `push reg; ret`).
///
/// Handler-table key:
///   When `imagebase_key_disp >= 0`, the decrypt step reads the key from
///   `[rsp + imagebase_key_disp]` (the upper 4 bytes of the junk slot,
///   initialized once in the entry stub from PEB.ImageBaseAddress). The
///   immediate form `xor eax, imm32` is not used, so there is no literal
///   key anywhere in the VM blob — `table_key_patches` stays empty and
///   every dispatch site looks like `xor eax, [rsp + disp8]`.
///
///   When `imagebase_key_disp < 0`, the legacy path is used: a placeholder
///   imm32 is emitted and its offset pushed into `table_key_patches` so
///   the caller can patch in the build-time key.
TailDispatchPatch emit_tail_dispatch(RawEmitter& e, int32_t key_disp,
                                     bool rolling,
                                     bool save_rflags,
                                     std::vector<size_t>& table_key_patches,
                                     uint32_t vflags_key,
                                     uint32_t vflags_rol,
                                     Randomizer* rng,
                                     int32_t imagebase_key_disp = -1) {
    // Optionally save CPU rflags into the VM context BEFORE clobbering them
    // with the fetch logic (movzx/xor). This is the single collection point
    // for flag preservation — every handler's body has just finished, and the
    // CPU flags still reflect the last ALU/native operation.
    if (save_rflags) {
        const auto v = (rng != nullptr) ? pick_store_variant(*rng)
                                         : VflagsStoreV::RaxRolFirst;
        emit_vflags_store(e, v, vflags_key, vflags_rol, kRflagsOffset);
    }

    emit_movzx_r32_byte_mem(e, 0 /*rax*/, 11, 0);
    emit_xor_r8l_rsp_disp(e, 0, key_disp);
    if (rolling) {
        emit_xor_rsp_disp_r8l(e, 0, key_disp);
    }
    emit_inc_r11(e);

    // Pick polymorphism variants. When rng is null (deprecated callers that
    // predate polymorphism) fall back to the original rcx+jmp shape.
    const uint8_t       base_reg = (rng != nullptr) ? pick_table_base_reg(*rng) : 1;
    const DispatchShape shape    = (rng != nullptr) ? pick_dispatch_shape(*rng)
                                                     : DispatchShape::JmpReg;

    // lea <base>, [rip + rel32]  — rel32 patched to point at the handler_table
    const auto patch_off = emit_lea_reg_rip_rel32(e, base_reg);
    const auto patch_end = e.size();

    // mov eax, dword [base + rax*4]    — zero-extends the 32-bit table entry
    emit_mov_eax_from_base_rax4(e, base_reg);

    // xor eax, TABLE_KEY — decrypt the table entry.
    //
    // Two forms depending on where the key lives:
    //   imm32 (legacy):  35 imm32                     — 5 bytes
    //   mem32 (ib-key):  33 44 24 disp8               — 4 bytes (disp8 form,
    //                     since the junk-slot disp is always ≤ 120)
    if (imagebase_key_disp >= 0) {
        // xor eax, [rsp + disp8]    33 44 24 disp8
        e.u8(0x33);
        e.u8(0x44);
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(imagebase_key_disp)));
    } else {
        // xor eax, imm32    35 imm32  (placeholder, patched later)
        e.u8(0x35);
        table_key_patches.push_back(e.size());
        e.u32(0);  // placeholder, patched with table_xor_key later
    }

    // movsxd rax, eax   — sign-extend AFTER decryption    48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);

    // add <base>, rax
    emit_add_base_rax(e, base_reg);

    // Indirect branch — polymorphic shape.
    switch (shape) {
        case DispatchShape::JmpReg:
            emit_jmp_reg(e, base_reg);
            break;
        case DispatchShape::PushRegRet:
            // push <base>; ret
            //   push rcx/rdx/... is a 1-byte 50+r form (or 2-byte with REX.B
            //   for r8..r15). ret is C3. Net rsp change is zero: push does
            //   -8, ret does +8. The target handler starts with rsp back at
            //   slot-base.
            emit_push_reg(e, base_reg);
            e.u8(0xC3);
            break;
        case DispatchShape::kCount:
            break;
    }

    return {patch_off, patch_end};
}

// ============================================================================
// Specific handlers (ALU / logic / shift / mov / etc.)
// ============================================================================

void emit_handler_mov_rr(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]   48 8B 07
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // mov [rsi], rax   48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/// Generic r-r ALU using dst-memory addressing and op_mr opcode
/// (add=01, sub=29, xor=31, and=21, or=09).
void emit_handler_alu_rr(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // OP [rsi], rax     48 op_mr 06
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

// ---------------------------------------------------------------------------
// MBA variants — mathematically equivalent alternative encodings that look
// nothing like the straightforward ALU form in a decompiler. Chosen at
// encode time per instruction to defeat simple opcode-table recovery.
// ---------------------------------------------------------------------------

/// ADD variant: x + y ≡ (x ^ y) + 2 * (x & y)
void emit_handler_add_rr_mba(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // rdx = x = [rsi]          48 8B 16
    e.u8(0x48); e.u8(0x8B); e.u8(0x16);
    // rcx = rdx                48 89 D1
    e.u8(0x48); e.u8(0x89); e.u8(0xD1);
    // rcx = x & y              48 21 C1
    e.u8(0x48); e.u8(0x21); e.u8(0xC1);
    // rcx = 2 * (x & y)        48 D1 E1
    e.u8(0x48); e.u8(0xD1); e.u8(0xE1);
    // rdx = x ^ y              48 31 C2
    e.u8(0x48); e.u8(0x31); e.u8(0xC2);
    // rdx = (x^y) + 2*(x&y)    48 01 CA
    e.u8(0x48); e.u8(0x01); e.u8(0xCA);
    // [rsi] = rdx              48 89 16
    e.u8(0x48); e.u8(0x89); e.u8(0x16);
}

/// SUB variant: x - y ≡ x + (-y)
void emit_handler_sub_rr_neg(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // neg rax              48 F7 D8
    e.u8(0x48); e.u8(0xF7); e.u8(0xD8);
    // add [rsi], rax       48 01 06
    e.u8(0x48); e.u8(0x01); e.u8(0x06);
}

/// XOR variant: x ^ y ≡ (x | y) - (x & y)
void emit_handler_xor_rr_mba(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // rdx = x = [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x16);
    // rcx = rdx                48 89 D1
    e.u8(0x48); e.u8(0x89); e.u8(0xD1);
    // rcx = x & y              48 21 C1
    e.u8(0x48); e.u8(0x21); e.u8(0xC1);
    // rdx = x | y              48 09 C2
    e.u8(0x48); e.u8(0x09); e.u8(0xC2);
    // rdx = (x|y) - (x&y)      48 29 CA
    e.u8(0x48); e.u8(0x29); e.u8(0xCA);
    // [rsi] = rdx              48 89 16
    e.u8(0x48); e.u8(0x89); e.u8(0x16);
}

void emit_handler_imul_rr(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // imul rax, [rdi]
    e.u8(0x48); e.u8(0x0F); e.u8(0xAF); e.u8(0x07);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_mov_ri32(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp, rolling);
    // movsxd rax, eax   48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_mov_ri64(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_qword(e, key_disp, rolling);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_alu_ri32(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp, rolling);
    // movsxd rax, eax
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // OP [rsi], rax
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

/// not/neg [rsi]  (/2 for not, /3 for neg)
void emit_handler_unary(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    // 48 F7 /sub_op,rm=6(rsi)
    e.u8(0x48); e.u8(0xF7);
    e.u8(static_cast<uint8_t>((sub_op << 3) | 0x06));
}

void emit_handler_shift(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // mov cl, dl         88 D1
    e.u8(0x88); e.u8(0xD1);
    // OP rax, cl         48 D3 /sub_op
    e.u8(0x48); e.u8(0xD3);
    e.u8(static_cast<uint8_t>(0xC0 | (sub_op << 3)));
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

// ---------------------------------------------------------------------------
// RFLAGS save — needed so VJCC can read flags set by prior ALU handlers
// ---------------------------------------------------------------------------

/// Save current CPU rflags into the VM context slot so that a subsequent
/// VJCC handler can evaluate branch conditions. Called at the END of every
/// handler body that may modify arithmetic flags (ADD, SUB, XOR, AND, OR,
/// IMUL, NOT, NEG, SHL, SHR, SAR, ROL, ROR and native escape).
void emit_save_rflags_to_ctx(RawEmitter& e) {
    // pushfq          9C
    e.u8(0x9C);
    // pop rax         58
    e.u8(0x58);
    // mov [rsp + kRflagsOffset], rax
    // kRflagsOffset = 128: needs disp32 form.
    // 48 89 84 24 80 00 00 00
    e.u8(0x48); e.u8(0x89); e.u8(0x84); e.u8(0x24);
    e.u8(static_cast<uint8_t>(kRflagsOffset & 0xFF));
    e.u8(static_cast<uint8_t>((kRflagsOffset >> 8) & 0xFF));
    e.u8(static_cast<uint8_t>((kRflagsOffset >> 16) & 0xFF));
    e.u8(static_cast<uint8_t>((kRflagsOffset >> 24) & 0xFF));
}

// ---------------------------------------------------------------------------
// VJMP / VJCC handlers
// ---------------------------------------------------------------------------

/// VJMP (unconditional virtual branch).
/// Operand layout: [rel32]. After fetching, r11 already points past rel32.
/// Handler adds rel32 to r11 so the next tail dispatch reads from the target.
void emit_handler_vjmp(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_dword(e, key_disp, rolling);      // eax = rel32
    // movsxd rax, eax     48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // add r11, rax         4C 01 C3 — wait: add r11, rax = 49 01 C3
    // Actually: ADD r/m64, r64 → REX.WB + 01 /r.  r11 = rm, rax = reg
    // ModRM: mod=11, reg=0(rax), rm=3(r11&7) → C3.  REX = 49 (W+B)
    e.u8(0x49); e.u8(0x01); e.u8(0xC3);
}

/// VJCC (conditional virtual branch) with condition `cc` baked in at emit time.
/// Operand layout: [rel32]. The handler_id encodes the condition via the
/// variant system. Instead of pushfq/popfq (fragile), the handler directly
/// bit-tests the saved RFLAGS qword from the ctx slot.
///
/// Supported conditions (single-bit tests):
///   CC 0  (O):  OF (bit 11)          CC 1  (NO): !OF
///   CC 2  (B):  CF (bit 0)           CC 3  (NB): !CF
///   CC 4  (E):  ZF (bit 6)           CC 5  (NE): !ZF
///   CC 8  (S):  SF (bit 7)           CC 9  (NS): !SF
///   CC 10 (P):  PF (bit 2)           CC 11 (NP): !PF
///
/// Multi-bit conditions (CC 6,7,12-15) are supported via compound tests.
void emit_handler_vjcc(RawEmitter& e, int32_t key_disp, bool rolling,
                       uint8_t cc, uint32_t vflags_key,
                       uint32_t vflags_rol, Randomizer& rng) {
    emit_fetch_dword(e, key_disp, rolling);      // eax = rel32
    // movsxd rax, eax        48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);

    // Load and fully descramble saved RFLAGS into ecx (polymorphic).
    emit_vflags_to_ecx(e, pick_to_ecx_variant(rng),
                       vflags_key, vflags_rol, kRflagsOffset);

    // Determine which RFLAGS bit(s) to test and whether to jump-if-set or
    // jump-if-clear. We emit: `test rcx, MASK; jnz taken` or `jz taken`.
    //
    // Flag bit positions: CF=0, PF=2, ZF=6, SF=7, OF=11.
    struct CcInfo { uint32_t mask; bool jump_if_set; };
    constexpr CcInfo cc_table[16] = {
        /* 0  O  */ {1u << 11, true },
        /* 1  NO */ {1u << 11, false},
        /* 2  B  */ {1u << 0,  true },
        /* 3  NB */ {1u << 0,  false},
        /* 4  E  */ {1u << 6,  true },
        /* 5  NE */ {1u << 6,  false},
        /* 6  BE */ {(1u<<0)|(1u<<6), true },  // CF || ZF — test both, jnz if either set
        /* 7  A  */ {(1u<<0)|(1u<<6), false},  // !(CF || ZF)
        /* 8  S  */ {1u << 7,  true },
        /* 9  NS */ {1u << 7,  false},
        /* 10 P  */ {1u << 2,  true },
        /* 11 NP */ {1u << 2,  false},
        /* 12 L  */ {0, true },  // SF!=OF — handled specially below
        /* 13 GE */ {0, false},  // SF==OF
        /* 14 LE */ {0, true },  // ZF || (SF!=OF) — handled specially
        /* 15 G  */ {0, false},  // !ZF && (SF==OF)
    };

    const auto& info = cc_table[cc & 0xF];

    if (cc <= 11 && cc != 6 && cc != 7) {
        // Simple single-bit test:
        //   test ecx, mask     F7 C1 mask32   (or test rcx, imm32 with REX.W if mask > 32-bit — not needed here)
        e.u8(0xF7); e.u8(0xC1);
        e.u8(static_cast<uint8_t>(info.mask & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 8) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 16) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 24) & 0xFF));
    } else if (cc == 6 || cc == 7) {
        // BE / A: test CF|ZF bits.
        e.u8(0xF7); e.u8(0xC1);
        e.u8(static_cast<uint8_t>(info.mask & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 8) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 16) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 24) & 0xFF));
    } else {
        // CC 12-15 (L/GE/LE/G): SF vs OF comparison.
        // Extract SF (bit 7) and OF (bit 11), compare them.
        //   mov edx, ecx      89 CA
        //   shr edx, 4        C1 EA 04   — bring OF (bit 11) down to bit 7
        //   xor edx, ecx      31 CA      — bit 7 of edx: SF ^ OF
        //   test edx, 0x80    F7 C2 80 00 00 00  — test SF^OF bit
        // For LE/G we also need ZF:
        //   or edx, ecx (for LE) at bit 6 — complex. Simplify: use pushfq/popfq fallback.
        // For now: pushfq/popfq for CC 12-15 (less common in unsigned-dominated code).
        e.u8(0x89); e.u8(0xCA);             // mov edx, ecx
        e.u8(0xC1); e.u8(0xEA); e.u8(0x04); // shr edx, 4  (OF bit 11 → bit 7)
        e.u8(0x31); e.u8(0xCA);             // xor edx, ecx (bit 7 = SF^OF)
        if (cc == 14 || cc == 15) {
            // LE: ZF || (SF!=OF). OR in ZF (bit 6) shifted to bit 7:
            //   but ZF is at bit 6 in ecx. We can `or edx, ecx` then test bit 6|7.
            // G: !ZF && (SF==OF). Negate.
            // Simplified: test bits 6 and 7 of (edx | shifted).
            // Actually: merge ZF into the test:
            //   or edx, ecx    09 CA   — bit 6 = ZF from ecx
            e.u8(0x09); e.u8(0xCA);
            // test edx, 0xC0 (bits 6+7)
            e.u8(0xF7); e.u8(0xC2);
            e.u8(0xC0); e.u8(0x00); e.u8(0x00); e.u8(0x00);
        } else {
            // L/GE: just test bit 7 of edx (SF^OF)
            e.u8(0xF7); e.u8(0xC2);
            e.u8(0x80); e.u8(0x00); e.u8(0x00); e.u8(0x00);
        }
    }

    // jnz/jz taken_label. For `jump_if_set`, use JNZ (0x75). For `jump_if_clear`, use JZ (0x74).
    // taken path: add r11, rax (3 bytes). not-taken path: jmp +3 (2 bytes).
    //
    //   jcc +2          ; skip the jmp short
    //   jmp short +3    ; skip the add (not taken path)
    //   add r11, rax    ; taken path

    const uint8_t jcc_opcode = info.jump_if_set ? 0x75 : 0x74;
    e.u8(jcc_opcode);
    e.u8(0x02);         // skip the `jmp short +3` below

    // NOT TAKEN: skip the add r11
    e.u8(0xEB); e.u8(0x03);  // jmp short +3

    // TAKEN: add r11, rax    49 01 C3
    e.u8(0x49); e.u8(0x01); e.u8(0xC3);

    // Both paths converge → tail dispatch follows (emitted by caller).
}

} // anonymous namespace

// ============================================================================
// VmRuntimeGenerator::generate — main entry
// ============================================================================

namespace {

/// How many handler variants each canonical VmOp emits. Ops with multiple
/// variants have two (or more) mathematically equivalent emission forms; the
/// encoder picks one at random per instruction to defeat simple opcode-table
/// recovery.
constexpr uint8_t variant_count_for(VmOp op) {
    switch (op) {
        case VmOp::add_rr:
        case VmOp::sub_rr:
        case VmOp::xor_rr:
            return 2;
        case VmOp::vjcc:
            return 16;   // one handler per x86 condition code (0..F)
        default:
            return 1;
    }
}

} // anonymous namespace

MxResult<VmRuntime> VmRuntimeGenerator::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng,
    VmGenOptions opts)
{
    if (instructions.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            "VmRuntimeGenerator: empty VM instruction list"));
    }

    const bool emit_exit_as_jmp = opts.emit_exit_as_jmp;

    // ------------------------------------------------------------------------
    // Step 1 — per-build randomization: opcode handler_id permutation, handler
    // variant assignment, initial rolling key, vEFLAGS scramble (key + rol).
    // ------------------------------------------------------------------------
    VmOpcodeMap map{};
    do { map.opcode_xor_key = rng.next_u8(); } while (map.opcode_xor_key == 0);
    const uint8_t initial_key = map.opcode_xor_key;

    // vEFLAGS transform: stored_slot = rol(real_rflags, vflags_rol) ^ vflags_key
    //   - key is a full 32-bit random — can land bits anywhere because the exit
    //     stub fully descrambles before popfq (no writable-bits constraint)
    //   - rol is 1..31 (non-zero) so the shape of the `xor imm32; popfq` pattern
    //     breaks completely: the imm32 is different between slots, and there's
    //     always a rol/ror instruction adjacent to it
    const uint32_t vflags_key = rng.next_u32() | 1;      // any non-zero u32
    const uint32_t vflags_rol = rng.next_range(1, 31);   // rotate amount 1..31

    // Per-build random register layout: which virtual slot hosts each native
    // GPR. Cross-VM sub-VMs use independent layouts — register state flows
    // between them via CPU, not via slots.
    const VmRegLayout layout = make_random_layout(rng);
    const int32_t rolling_key_disp = layout.rolling_key_disp;

    const uint32_t native_count = static_cast<uint32_t>(std::count_if(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) { return v.op == VmOp::native; }));

    // Total generic variant slots (sum of variants across all canonical VmOps).
    uint32_t generic_variant_total = 0;
    for (uint32_t i = 0; i < kVmOpCount; ++i) {
        generic_variant_total += variant_count_for(static_cast<VmOp>(i));
    }

    const uint32_t total_handlers = generic_variant_total + native_count;
    if (total_handlers > 255) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            std::format("VmRuntimeGenerator: too many handlers ({} > 255)",
                total_handlers)));
    }
    map.total_handlers = total_handlers;

    // Shuffle handler_id assignment across the entire slot space.
    std::vector<uint8_t> slots(total_handlers);
    std::iota(slots.begin(), slots.end(), static_cast<uint8_t>(0));
    std::shuffle(slots.begin(), slots.end(), rng.engine());

    // variant_handler_ids[op] = list of handler_ids (one per variant).
    std::vector<std::vector<uint8_t>> variant_handler_ids(kVmOpCount);
    {
        uint32_t idx = 0;
        for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
            const uint32_t vcount = variant_count_for(static_cast<VmOp>(opi));
            variant_handler_ids[opi].reserve(vcount);
            for (uint32_t v = 0; v < vcount; ++v) {
                variant_handler_ids[opi].push_back(slots[idx++]);
            }
            // Keep VmOpcodeMap's "canonical" id for compatibility: it stores
            // the FIRST variant's id. Encoders normally bypass this and pick
            // a random variant directly from variant_handler_ids.
            map.generic_handler_id[opi] = variant_handler_ids[opi].front();
        }
    }

    std::vector<uint8_t> native_handler_ids;
    native_handler_ids.reserve(native_count);
    for (uint32_t i = generic_variant_total; i < total_handlers; ++i) {
        native_handler_ids.push_back(slots[i]);
    }

    // ------------------------------------------------------------------------
    // Step 2 — build plain bytecode stream, then stream-encrypt with rolling
    // key. The encryption walks bytes in fetch order (opcode, operands, next
    // opcode, ...) so the runtime decryption order matches.
    // ------------------------------------------------------------------------
    ByteBuffer bytecode_plain;
    bytecode_plain.reserve(instructions.size() * 4);

    uint32_t next_native_idx = 0;
    std::vector<uint32_t> native_handler_of_insn(instructions.size(), UINT32_MAX);

    // --- Phase 1: compute bytecode size per instruction to get offsets. ---
    // We need offsets BEFORE encoding because vjmp/vjcc rel32 depends on the
    // target instruction's bytecode offset.
    auto insn_bc_size = [](const VmInstruction& vi) -> uint32_t {
        // 1 byte for handler_id + operand bytes
        return 1 + vm_op_operand_size(vi.op);
    };

    std::vector<uint32_t> bc_offset(instructions.size() + 1);
    bc_offset[0] = 0;
    for (size_t i = 0; i < instructions.size(); ++i) {
        bc_offset[i + 1] = bc_offset[i] + insn_bc_size(instructions[i]);
    }
    const uint32_t exit_bc_offset = bc_offset.back(); // offset of the terminal exit opcode

    // --- Phase 2: encode bytecode. ---
    auto push32 = [&](int32_t v) {
        const auto u = static_cast<uint32_t>(v);
        bytecode_plain.push_back(static_cast<uint8_t>(u & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 16) & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 24) & 0xFF));
    };
    // Translate a native-reg operand (as emitted by the lifter) to its
    // per-build virtual slot. The lifter refuses to emit RSP operands for
    // generic ops, so native_to_slot[n] must be valid here.
    auto remap_reg = [&](uint8_t native_reg) -> uint8_t {
        const uint8_t slot = layout.native_to_slot[native_reg];
        // Defensive: if the lifter ever lets RSP through, fall back to junk
        // slot rather than writing 0xFF into the bytecode.
        return (slot == 0xFF) ? layout.junk_slot : slot;
    };

    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& vi = instructions[i];
        uint8_t handler_id;
        if (vi.op == VmOp::native) {
            handler_id = native_handler_ids[next_native_idx];
            native_handler_of_insn[i] = next_native_idx;
            ++next_native_idx;
        } else if (vi.op == VmOp::vjcc) {
            // vjcc uses a per-CC variant: variant index = branch_cc.
            const auto& variants = variant_handler_ids[static_cast<uint32_t>(VmOp::vjcc)];
            handler_id = variants[vi.branch_cc];
        } else {
            const auto& variants = variant_handler_ids[static_cast<uint32_t>(vi.op)];
            const uint32_t v = (variants.size() > 1)
                ? rng.next_range(0, static_cast<uint32_t>(variants.size() - 1))
                : 0u;
            handler_id = variants[v];
        }

        bytecode_plain.push_back(handler_id);

        switch (vi.op) {
            case VmOp::mov_rr:
            case VmOp::add_rr:
            case VmOp::sub_rr:
            case VmOp::xor_rr:
            case VmOp::and_rr:
            case VmOp::or_rr:
            case VmOp::imul_rr:
                bytecode_plain.push_back(remap_reg(vi.dst));
                bytecode_plain.push_back(remap_reg(vi.src));
                break;

            case VmOp::mov_ri32:
            case VmOp::add_ri32:
            case VmOp::sub_ri32:
            case VmOp::xor_ri32:
            case VmOp::and_ri32:
            case VmOp::or_ri32:
                bytecode_plain.push_back(remap_reg(vi.dst));
                push32(vi.imm32);
                break;

            case VmOp::mov_ri64:
                bytecode_plain.push_back(remap_reg(vi.dst));
                for (int b = 0; b < 8; ++b)
                    bytecode_plain.push_back(
                        static_cast<uint8_t>((vi.imm64 >> (b * 8)) & 0xFF));
                break;

            case VmOp::not_r:
            case VmOp::neg_r:
                bytecode_plain.push_back(remap_reg(vi.dst));
                break;

            case VmOp::shl_ri:
            case VmOp::shr_ri:
            case VmOp::sar_ri:
            case VmOp::rol_ri:
            case VmOp::ror_ri:
                bytecode_plain.push_back(remap_reg(vi.dst));
                bytecode_plain.push_back(vi.shift_count);
                break;

            case VmOp::vjmp: {
                // rel32 = target_bc_offset - next_insn_bc_offset
                const auto target_off = bc_offset[vi.branch_target_insn];
                const auto next_off   = bc_offset[i + 1];
                push32(static_cast<int32_t>(target_off) -
                       static_cast<int32_t>(next_off));
                break;
            }

            case VmOp::vjcc: {
                // Operand: [rel32]. The CC is baked into the handler variant.
                const auto target_off = bc_offset[vi.branch_target_insn];
                const auto next_off   = bc_offset[i + 1];
                push32(static_cast<int32_t>(target_off) -
                       static_cast<int32_t>(next_off));
                break;
            }

            case VmOp::native:
            case VmOp::exit:
            case VmOp::count_:
                break;
        }
    }

    // Terminal exit opcode.
    bytecode_plain.push_back(
        variant_handler_ids[static_cast<uint32_t>(VmOp::exit)][0]);

    // Detect whether the instruction list contains any virtual branches.
    // If it does, we fall back to static XOR encryption (all bytes XOR'd with
    // the same key) because branch targets would need key-state checkpoints
    // that complicate the first-pass design. Straight-line regions keep the
    // stronger rolling-key cipher.
    const bool has_branches = std::any_of(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) {
            return v.op == VmOp::vjmp || v.op == VmOp::vjcc;
        });
    const bool rolling = !has_branches;

    // Bytecode encryption: rolling-key or static XOR.
    if (rolling) {
        uint8_t key = initial_key;
        for (auto& b : bytecode_plain) {
            const uint8_t plain = b;
            b = static_cast<uint8_t>(plain ^ key);
            key ^= plain;
        }
    } else {
        for (auto& b : bytecode_plain) {
            b ^= initial_key;
        }
    }

    // ------------------------------------------------------------------------
    // Step 3 — emit the runtime blob:
    //   [entry_stub][handlers ...][handler_table][bytecode]
    // ------------------------------------------------------------------------
    RawEmitter rt;

    // Patch-records collected during emission.
    struct TablePatch {
        size_t rel32_offset;
        size_t instruction_end;
    };
    std::vector<TablePatch> table_patches;

    // ---- Entry stub ----------------------------------------------------------
    const size_t entry_offset = rt.size();

    emit_pushfq(rt);
    // 16 register pushes, permuted per-build. Push at position K lands at
    // offset (15-K)*8, so to put slot V at [rsp + V*8] we push it at K=15-V.
    // The junk slot (native RSP's would-be home) is filled with a dummy
    // `push rax` — its byte becomes the rolling-key scratch.
    for (int k = 0; k < 16; ++k) {
        const uint8_t v = static_cast<uint8_t>(15 - k);
        if (v == layout.junk_slot) {
            emit_push_reg(rt, 0);  // dummy push rax (value irrelevant)
        } else {
            emit_push_reg(rt, layout.slot_to_native[v]);
        }
    }

    // Seed the rolling key inside the junk slot. Displacement varies per-build.
    //   C6 44 24 disp8 ib     (if disp <= 127)
    //   C6 84 24 disp32 ib    (otherwise — impossible here, disp ≤ 120)
    rt.u8(0xC6); rt.u8(0x44); rt.u8(0x24);
    rt.u8(static_cast<uint8_t>(rolling_key_disp));
    rt.u8(initial_key);

    // Transform the raw RFLAGS the entry's pushfq just wrote into the scrambled
    // form: slot = rol(real, vflags_rol) ^ vflags_key. Polymorphic — one of
    // four equivalent byte sequences per build. Since the exit stub fully
    // descrambles before popfq, every entry re-scrambles unconditionally.
    if (vflags_key != 0 || vflags_rol != 0) {
        emit_vflags_inslot_scramble(rt, pick_inslot_variant(rng),
                                     vflags_key, vflags_rol, kRflagsOffset);
    }

    // Handler-table key derivation: if `opts.use_imagebase_key` is set,
    // compute the key at runtime from PEB.ImageBaseAddress and store it in
    // the upper 4 bytes of the junk slot ([rsp + rolling_key_disp + 4]).
    // Every tail dispatch then reads `xor eax, [rsp + disp8]` instead of
    // carrying an imm32 — the table key never appears as a literal in the
    // VM blob, and statically extracting it requires simulating the entry.
    //
    // The transformation from `ImageBase_low32` to `table_xor_key` is a
    // random MBA chain (6–12 ops of add/sub/xor/not/rol/ror) generated via
    // `MbaTransitionGenerator`, not a single `xor eax, salt`. A reverser
    // staring at the entry stub sees a sequence of arithmetic ops with no
    // single "this is the key" immediate they can grep for.
    //
    // Precondition: the output binary has ASLR disabled (packer strips
    // relocations + DYNAMIC_BASE). When ASLR is on, runtime ImageBase
    // differs from `opts.preferred_image_base` and the VM silently breaks.
    // The caller in VirtualizationPass only sets this opt when the packer
    // is enabled (which guarantees ASLR is stripped later).
    const int32_t imagebase_key_disp =
        opts.use_imagebase_key ? (rolling_key_disp + 4) : -1;

    // Handler-table encryption key. Two modes decide it here:
    //   1. Legacy static: a per-build random u32, baked into every tail
    //      dispatch as `xor eax, imm32`.
    //   2. ImageBase path: still a per-build random u32 — but the entry
    //      stub transforms `ImageBase_low32` → this value via a random
    //      MBA chain, and dispatches load the result from the slot.
    //
    // We compute it up-front so the MBA chain below can consume it as its
    // target value, and the handler_table encryption in Step 4 uses the
    // same value to seal the entries.
    const uint32_t table_xor_key = opts.use_imagebase_key
        ? rng.next_u32()
        : (rng.next_u32() | 1);  // legacy path wants non-zero

    // Patch offsets for the integrity check that is emitted inside the
    // ImageBase block. Zero when integrity is not enabled.
    size_t integrity_table_lea_patch = 0;
    size_t integrity_expected_patch  = 0;

    if (opts.use_imagebase_key) {
        //   65 48 8B 04 25 60 00 00 00   mov rax, gs:[0x60]    ; PEB
        //   48 8B 40 10                  mov rax, [rax + 0x10] ; ImageBase
        //   <MBA chain>                  transforms eax from IB_low32
        //                                to table_xor_key via random ops
        //   <integrity check>            xor'd into eax; zero if table
        //                                matches build-time, corrupts
        //                                eax if the encrypted handler
        //                                table has been tampered with
        //   89 44 24 <disp8>             mov [rsp + key_disp], eax
        //
        // The MOV [rax+0x10] is a 64-bit load — upper 32 of rax hold
        // ImageBase_high32. The MBA chain emits 32-bit ops (81 /0 etc.)
        // which zero-extend into rax, so the subsequent 32-bit store of
        // eax saves only table_xor_key. Upper half of rax is discarded.
        rt.u8(0x65); rt.u8(0x48); rt.u8(0x8B); rt.u8(0x04); rt.u8(0x25);
        rt.u8(0x60); rt.u8(0x00); rt.u8(0x00); rt.u8(0x00);
        rt.u8(0x48); rt.u8(0x8B); rt.u8(0x40); rt.u8(0x10);

        // Generate the IB_low32 → table_xor_key chain. state_preserved=true
        // because rax already holds the source value (upper 32 of rax are
        // discarded by the 32-bit ops).
        const uint32_t ib_low32 =
            static_cast<uint32_t>(opts.preferred_image_base & 0xFFFFFFFFULL);
        MbaTransitionGenerator mba_gen(Architecture::x64);
        auto chain = mba_gen.generate(
            ib_low32, table_xor_key, x86::Reg::rax, rng,
            /*state_preserved=*/true);
        rt.bytes(ByteView{chain.data(), chain.size()});

        // --- Handler-table integrity check ---------------------------------
        //
        // Walk every encrypted handler-table entry, XOR them all together,
        // and XOR the result with a build-time-computed expected value. If
        // the table is intact, the expected value exactly cancels the
        // running sum and the final edx is 0. If a debugger patched any
        // entry (single-byte hardware breakpoint, memory redirect), the
        // running sum differs and edx is non-zero.
        //
        // We then XOR edx into eax (the MBA-derived key). Correct table →
        // edx=0 → eax unchanged. Tampered table → edx!=0 → eax silently
        // corrupted → every dispatch XORs with the wrong key → wrong
        // table entry decrypt → jump to a random address inside .mxvm →
        // almost always #UD or access violation.
        //
        // No branch to NOP out. The check IS the decryption path.
        //
        //   48 8D 1D <rel32>       lea rbx, [rip + handler_table]
        //   B9 <handler_count>     mov ecx, total_handlers
        //   31 D2                  xor edx, edx
        //  .loop:
        //   33 13                  xor edx, dword [rbx]
        //   48 83 C3 04            add rbx, 4
        //   FF C9                  dec ecx
        //   75 F6                  jnz .loop    (rel8 = -10)
        //   81 F2 <expected32>     xor edx, <build-time expected>
        //   31 D0                  xor eax, edx
        //
        // Both `<rel32>` and `<expected32>` are placeholders patched at
        // the end of generate().

        // lea rbx, [rip + rel32]    48 8D 1D rel32
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0x1D);
        integrity_table_lea_patch = rt.size();
        rt.u32(0);
        table_patches.push_back(
            {integrity_table_lea_patch, rt.size()});

        // mov ecx, total_handlers    B9 imm32
        rt.u8(0xB9);
        rt.u32(total_handlers);

        // xor edx, edx               31 D2
        rt.u8(0x31); rt.u8(0xD2);

        // .loop: xor edx, [rbx]      33 13
        const size_t loop_start = rt.size();
        rt.u8(0x33); rt.u8(0x13);
        // add rbx, 4                 48 83 C3 04
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xC3); rt.u8(0x04);
        // dec ecx                    FF C9
        rt.u8(0xFF); rt.u8(0xC9);
        // jnz .loop                  75 rel8
        const size_t jnz_end = rt.size() + 2;
        const int32_t  rel8    = static_cast<int32_t>(loop_start) -
                                 static_cast<int32_t>(jnz_end);
        rt.u8(0x75); rt.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));

        // xor edx, <expected>        81 F2 imm32
        rt.u8(0x81); rt.u8(0xF2);
        integrity_expected_patch = rt.size();
        rt.u32(0);

        // xor eax, edx               31 D0
        rt.u8(0x31); rt.u8(0xD0);
        // -------------------------------------------------------------------

        // mov [rsp + disp8], eax    89 44 24 disp8  (reg=eax=0, SIB=rsp)
        rt.u8(0x89); rt.u8(0x44); rt.u8(0x24);
        rt.u8(static_cast<uint8_t>(static_cast<int8_t>(imagebase_key_disp)));
    }

    // lea r11, [rip + bytecode_rel32]
    const size_t entry_bc_patch = emit_lea_r11_rip_rel32(rt);
    const size_t entry_bc_patch_end = rt.size();

    // Collection of positions where TABLE_XOR_KEY must be patched into the
    // `xor eax, KEY` instructions inside each tail dispatch. Empty when
    // `use_imagebase_key` is set, since dispatches then load the key from
    // the context slot instead of carrying an imm32.
    std::vector<size_t> table_key_patches;

    // Inline first dispatch (same shape as handler tails): fetch opcode,
    // decrypt, update key, look up handler via encrypted table, jump.
    // Polymorphism on: entry is a prime signature target, so it gets a
    // random table-base reg and dispatch shape just like handler tails.
    const auto entry_tail = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                                false, table_key_patches,
                                                vflags_key, vflags_rol, &rng,
                                                imagebase_key_disp);
    table_patches.push_back({entry_tail.rel32_offset, entry_tail.instruction_end});

    // ---- Handler emission ----------------------------------------------------
    // For each handler_id we record its starting offset so we can fill the
    // handler_table at the end.
    std::vector<size_t> handler_offset_by_id(total_handlers, SIZE_MAX);

    // Records the entry offset for a handler and then emits a random junk
    // prologue of 0–8 bytes. The offset is captured BEFORE the junk so the
    // handler_table entry points at the start of the junk — execution still
    // falls through into the real body after the no-ops, and the junk bytes
    // break signature-matching on the handler prologue.
    auto begin_handler = [&](uint8_t handler_id) {
        handler_offset_by_id[handler_id] = rt.size();
        emit_junk_prologue(rt, rng, /*max_bytes=*/8);
    };

    auto end_handler_tail = [&]() {
        const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                          has_branches, table_key_patches,
                                          vflags_key, vflags_rol, &rng,
                                          imagebase_key_disp);
        table_patches.push_back({p.rel32_offset, p.instruction_end});
    };

    // Emit one body for (op, variant_index). Returns true if a tail dispatch
    // should be appended after the body. The VmOp::exit variant emits its own
    // ret and returns false.
    uint32_t exit_jmp_offset = 0;  // patched if emit_exit_as_jmp

    auto emit_op_variant = [&](VmOp op, uint32_t variant) -> bool {
        switch (op) {
            case VmOp::mov_rr:   emit_handler_mov_rr(rt, rolling_key_disp, rolling);             return true;

            case VmOp::add_rr:
                if (variant == 0) emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x01);
                else              emit_handler_add_rr_mba(rt, rolling_key_disp, rolling);
                return true;

            case VmOp::sub_rr:
                if (variant == 0) emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x29);
                else              emit_handler_sub_rr_neg(rt, rolling_key_disp, rolling);
                return true;

            case VmOp::xor_rr:
                if (variant == 0) emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x31);
                else              emit_handler_xor_rr_mba(rt, rolling_key_disp, rolling);
                return true;

            case VmOp::and_rr:   emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x21);       return true;
            case VmOp::or_rr:    emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x09);       return true;
            case VmOp::imul_rr:  emit_handler_imul_rr(rt, rolling_key_disp, rolling);            return true;

            case VmOp::mov_ri32: emit_handler_mov_ri32(rt, rolling_key_disp, rolling);           return true;
            case VmOp::add_ri32: emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x01);     return true;
            case VmOp::sub_ri32: emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x29);     return true;
            case VmOp::xor_ri32: emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x31);     return true;
            case VmOp::and_ri32: emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x21);     return true;
            case VmOp::or_ri32:  emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x09);     return true;

            case VmOp::mov_ri64: emit_handler_mov_ri64(rt, rolling_key_disp, rolling);           return true;

            case VmOp::not_r:    emit_handler_unary(rt, rolling_key_disp, rolling, 2);           return true;
            case VmOp::neg_r:    emit_handler_unary(rt, rolling_key_disp, rolling, 3);           return true;

            case VmOp::shl_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 4);           return true;
            case VmOp::shr_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 5);           return true;
            case VmOp::sar_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 7);           return true;
            case VmOp::rol_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 0);           return true;
            case VmOp::ror_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 1);           return true;

            case VmOp::vjmp:
                emit_handler_vjmp(rt, rolling_key_disp, rolling);
                return true;

            case VmOp::vjcc:
                emit_handler_vjcc(rt, rolling_key_disp, rolling,
                                  static_cast<uint8_t>(variant),
                                  vflags_key, vflags_rol, rng);
                return true;

            case VmOp::native:
                // Generic native slot is never invoked — each native insn gets
                // its own handler. Trap with ud2 (no tail).
                emit_ud2(rt);
                return false;

            case VmOp::exit: {
                // Before popping, fully descramble the RFLAGS slot in place
                // (polymorphic — one of four variants). The scratch reg
                // variants clobber rax, which is safe here because the
                // subsequent pops will overwrite it.
                if (vflags_key != 0 || vflags_rol != 0) {
                    emit_vflags_inslot_descramble(rt, pick_inslot_variant(rng),
                                                   vflags_key, vflags_rol,
                                                   kRflagsOffset);
                }

                // Exit: pop all 16 slots in slot order (slot 0 at [rsp+0]
                // is popped first, then slot 1, etc.). Each pop either
                // restores a native reg or advances rsp past the junk slot.
                for (uint8_t v = 0; v < 16; ++v) {
                    if (v == layout.junk_slot) {
                        // add rsp, 8       48 83 C4 08
                        rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4); rt.u8(0x08);
                    } else {
                        emit_pop_reg(rt, layout.slot_to_native[v]);
                    }
                }
                emit_popfq(rt);
                if (emit_exit_as_jmp) {
                    // Cross-VM: jmp rel32 to next sub-VM entry (patched later)
                    rt.u8(0xE9);
                    exit_jmp_offset = static_cast<uint32_t>(rt.size());
                    rt.u32(0);  // placeholder rel32
                } else {
                    emit_ret(rt);
                }
                return false;  // no tail dispatch
            }
            case VmOp::count_:
                return false;
        }
        return false;
    };

    // Generic handlers: emit every variant of every canonical VmOp.
    for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
        const auto op = static_cast<VmOp>(opi);
        const auto& variants = variant_handler_ids[opi];
        for (uint32_t v = 0; v < variants.size(); ++v) {
            begin_handler(variants[v]);
            const bool needs_tail = emit_op_variant(op, v);
            if (needs_tail) {
                end_handler_tail();
            }
        }
    }

    // Per-instruction native handlers — one per VmOp::native insn.
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].op != VmOp::native) continue;
        const uint8_t hid = native_handler_ids[native_handler_of_insn[i]];
        begin_handler(hid);

        // sub rsp, 16   — reserve scratch for vpc save
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xEC); rt.u8(0x18);
        // mov [rsp], r11   — save vpc
        rt.u8(0x4C); rt.u8(0x89); rt.u8(0x1C); rt.u8(0x24);

        // Reload native regs from ctx. After `sub rsp, 16` the ctx lives at
        // [rsp + 24 + slot * 8]. Each native reg N (N != 4) lives at its
        // per-build permuted slot layout.native_to_slot[N]. The junk slot
        // (rolling-key scratch) has no native reg mapped to it.
        struct RegLoad { uint8_t native_reg; int32_t offset; };
        RegLoad loads[15];
        {
            size_t k = 0;
            for (uint8_t n = 0; n < 16; ++n) {
                if (n == 4) continue;   // skip RSP
                const uint8_t slot = layout.native_to_slot[n];
                loads[k++] = {n, 24 + static_cast<int32_t>(slot) * 8};
            }
        }

        auto emit_mem_mov = [&](uint8_t opcode, uint8_t reg, int32_t disp) {
            // opcode=0x8B (load) or 0x89 (store)
            uint8_t rex = 0x48 | ((reg >= 8) ? 0x04 : 0x00);
            rt.u8(rex);
            rt.u8(opcode);
            const uint8_t reg3 = reg & 0x07;
            if (disp >= -128 && disp <= 127) {
                rt.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
            } else {
                rt.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u32(static_cast<uint32_t>(disp));
            }
        };

        for (const auto& l : loads) emit_mem_mov(0x8B, l.native_reg, l.offset);

        // Restore CPU flags from ctx so flag-dependent native instructions
        // (CMOV, ADC, SBB, etc.) see the correct state. Polymorphic variant:
        // reg-based variants clobber rax, so we save it to scratch [rsp+8]
        // first; the InPlace variant uses no registers at all.
        {
            const int32_t rf_disp = 24 + kRflagsOffset;
            const auto popfq_v = pick_popfq_variant(rng);
            const bool uses_rax = (popfq_v != VflagsPopfqV::InPlace);
            if (uses_rax) {
                // Save rax to scratch [rsp+8]
                rt.u8(0x48); rt.u8(0x89); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
            emit_vflags_popfq(rt, popfq_v, vflags_key, vflags_rol, rf_disp);
            if (uses_rax) {
                // Restore rax from scratch
                rt.u8(0x48); rt.u8(0x8B); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
        }

        // Shift rsp to caller frame via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(kNativeFrameShift));

        // Execute native bytes (sees correct GPRs, flags, and caller frame).
        rt.bytes(ByteView{
            instructions[i].native_bytes.data(),
            instructions[i].native_bytes.size()});

        // Shift rsp back via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(-kNativeFrameShift));

        // Save CPU flags after native execution into ctx so the NEXT
        // handler (or VJCC) sees the correct flags. Polymorphic — reg
        // variants clobber rax and need the scratch dance, InPlace does not.
        {
            const int32_t rf_disp = 24 + kRflagsOffset;
            const auto store_v = pick_store_variant(rng);
            const bool uses_rax = (store_v != VflagsStoreV::InPlace);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x89); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
            emit_vflags_store(rt, store_v, vflags_key, vflags_rol, rf_disp);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x8B); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
        }

        // Save all native regs back to ctx
        for (const auto& l : loads) emit_mem_mov(0x89, l.native_reg, l.offset);

        // Restore vpc: mov r11, [rsp]    4C 8B 1C 24
        rt.u8(0x4C); rt.u8(0x8B); rt.u8(0x1C); rt.u8(0x24);
        // lea rsp, [rsp + 24]    48 8D 64 24 18  (flags-preserving)
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0x64); rt.u8(0x24); rt.u8(0x18);

        // save_rflags=false: native handler already saved flags above.
        // Polymorphism on (same as handler tails).
        {
            const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                              false, table_key_patches,
                                              vflags_key, vflags_rol, &rng,
                                              imagebase_key_disp);
            table_patches.push_back({p.rel32_offset, p.instruction_end});
        }
    }

    // ---- Handler table -------------------------------------------------------
    // Align to 4 bytes so the 32-bit entries are naturally aligned.
    while (rt.size() % 4 != 0) rt.u8(0xCC);
    const size_t handler_table_offset = rt.size();
    for (uint32_t h = 0; h < total_handlers; ++h) {
        rt.u32(0);  // placeholder, patched below
    }

    // ---- Bytecode ------------------------------------------------------------
    while (rt.size() % 8 != 0) rt.u8(0xCC);
    const size_t bytecode_offset = rt.size();
    rt.bytes(ByteView{bytecode_plain.data(), bytecode_plain.size()});

    // ------------------------------------------------------------------------
    // Step 4 — patch all rel32s and the handler_table entries.
    // ------------------------------------------------------------------------

    // Entry → bytecode (via lea r11, [rip + rel32])
    patch_rel32(rt.buf, entry_bc_patch, entry_bc_patch_end, bytecode_offset);

    // All tail-dispatch lea rcx, [rip + rel32] → handler_table
    for (const auto& p : table_patches) {
        patch_rel32(rt.buf, p.rel32_offset, p.instruction_end, handler_table_offset);
    }

    // `table_xor_key` was fixed up-front (before the entry stub was emitted)
    // so the MBA chain could consume it as its target value. Here we only
    // need to patch the legacy `xor eax, imm32` placeholders in tail
    // dispatches — the ImageBase path leaves `table_key_patches` empty
    // because its dispatches use the memory-load form.
    for (const auto patch_off : table_key_patches) {
        std::memcpy(rt.buf.data() + patch_off, &table_xor_key, 4);
    }

    // handler_table entries: each = (handler_offset - table_offset) ^ table_xor_key
    uint32_t table_xor_sum = 0;  // running XOR of encrypted entries, for integrity check
    for (uint32_t h = 0; h < total_handlers; ++h) {
        if (handler_offset_by_id[h] == SIZE_MAX) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format("VmRuntimeGenerator: handler id {} not emitted", h)));
        }
        auto rel = static_cast<int32_t>(
            static_cast<int64_t>(handler_offset_by_id[h]) -
            static_cast<int64_t>(handler_table_offset));
        rel ^= static_cast<int32_t>(table_xor_key); // encrypt
        std::memcpy(rt.buf.data() + handler_table_offset + h * 4, &rel, 4);
        table_xor_sum ^= static_cast<uint32_t>(rel);
    }

    // Handler-table integrity check: patch the expected XOR sum into the
    // entry stub. At runtime the stub walks the table, XOR-accumulates all
    // entries, and XORs the result with this value. If the table has not
    // been tampered with, the two cancel and leave 0 in edx — the
    // subsequent `xor eax, edx` is a no-op. If the table has been patched
    // (e.g. by a debugger trying to redirect a specific handler), the
    // running sum differs and edx is non-zero, silently corrupting the
    // table_xor_key stored on the stack. Every subsequent dispatch then
    // decrypts wrong, and the VM jumps into garbage on the first opcode.
    if (integrity_expected_patch != 0) {
        std::memcpy(rt.buf.data() + integrity_expected_patch,
                    &table_xor_sum, 4);
    }

    VmRuntime result;
    result.blob = std::move(rt.buf);
    result.entry_offset    = static_cast<uint32_t>(entry_offset);
    result.bytecode_offset = static_cast<uint32_t>(bytecode_offset);
    result.bytecode_size   = static_cast<uint32_t>(bytecode_plain.size());
    result.handler_count   = total_handlers;
    result.opcode_map      = map;
    result.exit_jmp_patch  = exit_jmp_offset;
    return result;
}

} // namespace mx::vm
