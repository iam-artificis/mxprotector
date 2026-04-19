/**
 * @file asm_builder.hpp
 * @brief Mid-level x86-64 emitter on top of `RawEmitter`.
 *
 * `RawEmitter` (core/raw_emitter.hpp) is an append-only byte buffer
 * with `u8/u16/u32/u64` helpers — great for hand-rolled bytes but
 * mute on what the bytes mean. `analysis::X86CodeEmitter` sits at
 * the other end: a full label-aware assembler for generated code.
 *
 * `AsmBuilder` fills the middle: the handful of shortcuts that
 * every pass already re-implements inline — `jmp rel32`,
 * `call rel32`, `ret`, `int3` padding, `mov r64, imm64`,
 * `lea r64, [rip + rel32]`, plus `rex` / `modrm` primitives. No
 * label resolution, no operand decoding; callers that need either
 * should reach for `X86CodeEmitter` instead.
 *
 * The opcode constants in `mx::asm64` make the magic-byte
 * occurrences grep-able and self-documenting at call sites:
 * `0xE9` becomes `asm64::kJmpRel32`, `0xCC` becomes `asm64::kInt3`,
 * etc.
 *
 * Decoding-side x86 helpers (ModR/M extraction, REX bit tests,
 * multi-byte NOP generation) continue to live in
 * `analysis/x86_encoding.hpp` under `mx::x86` — this header is the
 * encoding-side counterpart.
 */

#pragma once

#include <cstdint>
#include <cstring>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::asm64 {

// ============================================================================
// Opcode constants
// ============================================================================

inline constexpr uint8_t kJmpRel32      = 0xE9; ///< `E9 rel32` — JMP rel32
inline constexpr uint8_t kCallRel32     = 0xE8; ///< `E8 rel32` — CALL rel32
inline constexpr uint8_t kRet           = 0xC3; ///< `C3`       — RET (near)
inline constexpr uint8_t kInt3          = 0xCC; ///< `CC`       — INT 3 (trap)
inline constexpr uint8_t kNop           = 0x90; ///< `90`       — NOP (1 byte)
inline constexpr uint8_t kRexW          = 0x48; ///< REX prefix with W bit only
inline constexpr uint8_t kMovR64ImmBase = 0xB8; ///< `B8+r imm64` base for MOV r64, imm64
inline constexpr uint8_t kLeaOpcode     = 0x8D; ///< `8D` — LEA r, m

/**
 * @brief Assemble a REX prefix byte from its four component bits.
 *
 * @param w  REX.W — 64-bit operand size
 * @param r  REX.R — extends ModR/M `reg` to r8–r15
 * @param x  REX.X — extends SIB `index` to r8–r15
 * @param b  REX.B — extends ModR/M `rm` / opcode `+r` / SIB `base`
 */
[[nodiscard]] inline constexpr uint8_t rex(bool w, bool r, bool x, bool b) noexcept {
    return static_cast<uint8_t>(
        0x40u |
        (w ? 0x08u : 0u) |
        (r ? 0x04u : 0u) |
        (x ? 0x02u : 0u) |
        (b ? 0x01u : 0u));
}

// ============================================================================
// AsmBuilder — mid-level fluent-ish emitter
// ============================================================================

/**
 * @brief Incremental x86-64 byte emitter.
 *
 * Owns a `RawEmitter`; exposes it publicly so callers can drop down
 * to raw bytes whenever the builder lacks a shortcut for a specific
 * instruction.
 *
 * No ownership trickery: the buffer grows as methods are called,
 * and `view()` / `buffer()` let the caller read or consume the
 * result. Typical use:
 *
 *     AsmBuilder ab;
 *     ab.jmp_rel32(rel);
 *     ab.int3_pad(pad_size);
 *     out.insert(out.end(), ab.view().begin(), ab.view().end());
 */
class AsmBuilder {
public:
    AsmBuilder() = default;
    explicit AsmBuilder(RawEmitter e) noexcept : raw(std::move(e)) {}

    RawEmitter raw; ///< Backing byte buffer — exposed for raw fallback paths.

    // -- size / view ---------------------------------------------------

    [[nodiscard]] size_t             size()   const noexcept { return raw.size(); }
    [[nodiscard]] const ByteBuffer&  buffer() const noexcept { return raw.buf; }
    [[nodiscard]] ByteBuffer&        buffer()       noexcept { return raw.buf; }
    [[nodiscard]] ByteView           view()   const noexcept { return ByteView{raw.buf}; }

    // -- single-byte instructions --------------------------------------

    void ret()  { raw.u8(kRet);  }
    void int3() { raw.u8(kInt3); }
    void nop1() { raw.u8(kNop);  }

    // -- padding -------------------------------------------------------

    /// Append `count` `INT 3` bytes. Zero `count` is a no-op.
    void int3_pad(size_t count) {
        for (size_t i = 0; i < count; ++i) raw.u8(kInt3);
    }

    // -- REX / ModR/M primitives ---------------------------------------

    /// `REX.W` only (64-bit operand size, no register extensions).
    void rex_w() { raw.u8(kRexW); }

    /// Full REX byte assembled from component bits.
    void rex(bool w, bool r, bool x, bool b) {
        raw.u8(asm64::rex(w, r, x, b));
    }

    /// ModR/M byte from `mod`/`reg`/`rm` fields. Delegates to
    /// `x86::make_modrm` so decoding and encoding agree.
    void modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
        raw.u8(x86::make_modrm(mod, reg, rm));
    }

    // -- relative branches --------------------------------------------

    /// 5-byte `jmp rel32`. `rel` is the signed distance from the byte
    /// following this instruction to the target.
    void jmp_rel32(int32_t rel) {
        raw.u8(kJmpRel32);
        raw.u32(static_cast<uint32_t>(rel));
    }

    /// 5-byte `call rel32`. Same relative-offset convention as `jmp_rel32`.
    void call_rel32(int32_t rel) {
        raw.u8(kCallRel32);
        raw.u32(static_cast<uint32_t>(rel));
    }

    // -- 64-bit data movement -----------------------------------------

    /// 10-byte `mov r64, imm64` (`REX.W [+REX.B] + B8+r + imm64`).
    void mov_r64_imm64(x86::Reg dst, uint64_t imm) {
        const auto reg       = static_cast<uint8_t>(dst);
        const bool extended  = (reg & 0x8u) != 0;
        raw.u8(asm64::rex(/*w=*/true, /*r=*/false, /*x=*/false, /*b=*/extended));
        raw.u8(static_cast<uint8_t>(kMovR64ImmBase + (reg & 0x7u)));
        raw.u64(imm);
    }

    /// 7-byte `lea r64, [rip + rel32]` (`REX.W [+REX.R] + 8D + ModR/M(0, reg, 101) + rel32`).
    void lea_r64_rip_rel(x86::Reg dst, int32_t rel) {
        const auto reg       = static_cast<uint8_t>(dst);
        const bool extended  = (reg & 0x8u) != 0;
        raw.u8(asm64::rex(/*w=*/true, /*r=*/extended, /*x=*/false, /*b=*/false));
        raw.u8(kLeaOpcode);
        raw.u8(x86::make_modrm(/*mod=*/0b00, reg & 0x7u, /*rm=*/0b101));
        raw.u32(static_cast<uint32_t>(rel));
    }
};

// ============================================================================
// In-place writers — for callers patching an existing span in place
// ============================================================================

/**
 * @brief Write `jmp rel32` into the first 5 bytes of `out`.
 *
 * Caller guarantees `out.size() >= 5`.
 */
inline void write_jmp_rel32(MutableByteView out, int32_t rel32) noexcept {
    out[0] = kJmpRel32;
    std::memcpy(out.data() + 1, &rel32, sizeof(rel32));
}

/**
 * @brief Write `call rel32` into the first 5 bytes of `out`.
 *
 * Caller guarantees `out.size() >= 5`.
 */
inline void write_call_rel32(MutableByteView out, int32_t rel32) noexcept {
    out[0] = kCallRel32;
    std::memcpy(out.data() + 1, &rel32, sizeof(rel32));
}

/// Fill every byte of `out` with `kInt3`.
inline void fill_int3(MutableByteView out) noexcept {
    for (auto& b : out) b = kInt3;
}

/// Fill every byte of `out` with `kNop` (1-byte NOP).
///
/// For in-place patches where the trailing bytes must stay decodable
/// as valid x86 (e.g., a 5-byte `jmp rel32` followed by NOP padding
/// inside an original function body). Callers that need the longer
/// multi-byte NOPs from the Intel recommended sequence should still
/// reach for `x86::make_nop` — this helper is the trivial
/// byte-at-a-time fill.
inline void fill_nop(MutableByteView out) noexcept {
    for (auto& b : out) b = kNop;
}

} // namespace mx::asm64
