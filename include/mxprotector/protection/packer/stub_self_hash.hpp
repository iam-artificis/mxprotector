/**
 * @file stub_self_hash.hpp
 * @brief P6 — stub self-integrity hash + per-layer effective-key derivation.
 *
 * Honest positioning: this is **stub tampering protection**, not
 * anti-dumping. A full memory dump of the protected process taken
 * AFTER all cipher layers have run correctly will still contain
 * plaintext. What P6 does protect against is:
 *
 *   * **Stub tampering at rest.** An attacker who modifies any
 *     byte of the packer stub's code (e.g., installs a debugger
 *     INT3, NOP-patches the anti-debug probe, replaces a `jne`
 *     with `je` to flip a control-flow decision) changes the
 *     runtime FNV-1a hash of the stub. The hash feeds into every
 *     layer's effective key via a forward-chained derivation, so
 *     a single modified byte avalanches through all 32 key bytes
 *     of every cipher layer. The KSA produces a diverged S-box,
 *     the PRGA stream doesn't match what the sections were
 *     encrypted with, and every protected section decrypts to
 *     garbage.
 *
 *   * **Static key extraction.** Before P6, an attacker could
 *     read the N base keys out of `.mxpack`, simulate the KSA,
 *     and decrypt the sections offline without ever running the
 *     stub. With P6 the attacker must ALSO compute FNV-1a over
 *     exactly the right byte range of the stub, then apply the
 *     FNV-1a-chain derivation to produce the effective keys.
 *     Both functions are trivially forward-computable given
 *     correct inputs — the protection is not cryptographic
 *     strength, it's the fact that the attacker's "just read the
 *     keys" script no longer works and has to include a
 *     bit-exact simulation of the derivation. That's a real step
 *     up in reverser effort for mass-protected samples, and it
 *     pairs naturally with P7 (per-function runtime decryption
 *     via VEH) when we eventually land that.
 *
 * ## Hash function: FNV-1a (32-bit)
 *
 * Chosen for three reasons:
 *
 *   1. **Tiny runtime emission.** The inner loop is
 *      `movzx edx, [rsi]; xor eax, edx; imul eax, r8d; inc rsi;
 *      dec ecx; jnz` — six instructions, 16 bytes. Runs over
 *      `~2 KB` of stub code in a few microseconds, once per
 *      process start. No measurable runtime cost.
 *
 *   2. **Good avalanche for tamper detection.** FNV-1a's
 *      multiplicative step propagates any input-bit change to
 *      most output bits within a few iterations. A one-byte
 *      stub modification changes the final 32-bit hash
 *      beyond recognition, which is all we need for the
 *      derivation step to garble the effective keys.
 *
 *   3. **Compile-time reference implementation.** The build-side
 *      reference (`mx::hash::fnv1a_32` in
 *      `common/hash/fnv1a.hpp`) is `constexpr` and bit-exact
 *      against the emitted x64 loop, so unit tests can check
 *      "if I compute FNV-1a over some bytes in C++, do I get
 *      the same value the runtime loop produces for those
 *      bytes?" without actually executing the emitted code.
 *      Constants are owned by that header so build-side and
 *      runtime emission can never drift.
 *
 * ## Key derivation: FNV-1a-chain
 *
 * Given a 32-bit stub hash `H` and a 32-byte base key `K`,
 * produce a 32-byte effective key `K'`:
 *
 *     uint32_t state = H;
 *     for (i = 0; i < 32; ++i) {
 *         state ^= K[i];
 *         state *= FNV_PRIME;
 *         K'[i] = static_cast<uint8_t>(state & 0xFF);
 *     }
 *
 * Each output byte depends on `H` and every earlier base-key
 * byte, giving full forward avalanche. The x64 runtime emitter
 * produces a matching loop that reads the base key bytes from a
 * rip-relative `.mxpack` data region and writes the effective
 * bytes back IN PLACE, so downstream KSA sees the derived key
 * without any extra memory shuffling.
 *
 * Compared to a plain `K[i] ^= (H >> (8*(i % 4)))` the
 * multiplicative chain has three advantages the user explicitly
 * asked for:
 *
 *   * Bit-avalanche across all 32 bytes, not just the 4 bytes
 *     that would overlap a 32-bit XOR mask.
 *   * Forward dependency on the PARTIAL sum of base-key bytes,
 *     so a reverser who extracts one base key can't shortcut
 *     the derivation — they need to chain through the whole
 *     key.
 *   * Shared `FNV_PRIME` constant with the self-hash step
 *     means the x64 emission reuses the same register-loaded
 *     prime across both loops, saving a few bytes of stub.
 *
 * ## What's NOT in this module
 *
 *   * Runtime binding to per-process state (TEB pointer, TickCount,
 *     etc.). Adding that is a future enhancement and would tighten
 *     "sandbox-replay" attacks, but the trade-off (harder to debug
 *     failures in the field, potential for fragile runtime math)
 *     pushed it out of this first commit.
 *
 *   * Per-function or per-page on-demand decryption. That's P7's
 *     job and needs a whole VEH-based execution model.
 */

#pragma once

#include <cstdint>

#include "mxprotector/common/hash/fnv1a.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::packer {

/**
 * @brief Apply the FNV-1a-chain derivation to a base key in place.
 *
 * The state register is seeded with `hash` and chained across every
 * base-key byte, writing the low 8 bits of the state back as the
 * effective-key byte. Bit-exact against the x64 runtime emission.
 *
 * `key.size()` is not pinned to 32 — the function works for any
 * length — but the packer only calls it with the 32-byte RC4 key
 * size, matching the `kKeySize` defined in `rc4.hpp`.
 */
void derive_effective_key_in_place(uint32_t hash, MutableByteView key) noexcept;

/**
 * @brief Patch-site offsets produced by `emit_stub_self_hash`.
 *
 * The runtime hash loop reads `[stub_start + hash_range_start,
 * stub_start + hash_range_start + hash_range_count)`. Both ends
 * are determined by the caller:
 *
 *   * `hash_range_start` is always `0` for the current integration
 *     (the loop hashes from the beginning of the stub buffer). It's
 *     still captured in the struct so a future integration can
 *     place the loop somewhere other than offset 0 without changing
 *     the API shape.
 *
 *   * `hash_range_count` is the full byte count the loop must walk.
 *     It is NOT known at emit time because the trailing stub code
 *     (anti-debug probe, layer loops, reprotect, IAT wipe) hasn't
 *     been emitted yet. The caller patches the `count_imm32_offset`
 *     slot once the final stub code size is fixed.
 *
 * `start_disp32_offset` is the offset of the rel32 inside the
 * `lea rsi, [rip + disp32]`. It is ALREADY baked at emit time to
 * point back at `hash_range_start`, so the caller normally leaves
 * it alone — the field exists for diagnostics and unit-test
 * cross-checks.
 */
struct StubSelfHashEmit {
    uint32_t start_disp32_offset;
    uint32_t count_imm32_offset;
    uint32_t hash_range_start;
};

/**
 * @brief Emit the runtime FNV-1a self-hash loop.
 *
 * Emission layout (42 bytes total: 23-byte header, 16-byte loop
 * body, 3-byte trailer):
 *
 *     mov   eax, 0x811C9DC5           ; hash = offset basis
 *     lea   rsi, [rip + start_disp32] ; rsi = stub byte 0
 *     mov   ecx, <patched count>      ; byte count (patched later)
 *     mov   r8d, 0x01000193           ; FNV prime
 *   .loop:
 *     movzx edx, byte [rsi]           ; edx = *rsi
 *     xor   eax, edx                  ; hash ^= byte
 *     imul  eax, r8d                  ; hash *= prime
 *     inc   rsi                       ; advance
 *     dec   ecx                       ; --count
 *     jnz   .loop                     ; loop
 *     mov   r14d, eax                 ; stash hash in r14 for layer derivation
 *
 * After the emit, `r14d` holds the 32-bit stub hash. The caller
 * is responsible for:
 *
 *   1. Not touching `r14` until every layer's key derivation has
 *      run (the packer cipher body's layer loop reads r14d as
 *      input to each `emit_key_derivation_loop`).
 *
 *   2. Patching the `count_imm32_offset` slot with the correct
 *      byte count once the trailing stub code has been emitted
 *      and the total hash range is known.
 *
 * The `lea rsi, [rip + disp32]` disp is baked at emit time to
 * resolve to the stub buffer's offset 0. If the caller wants a
 * different `hash_range_start`, they must adjust the disp32
 * manually via the returned `start_disp32_offset`.
 */
[[nodiscard]] StubSelfHashEmit emit_stub_self_hash(RawEmitter& e);

/**
 * @brief Emit an in-place effective-key derivation loop.
 *
 * Reads:
 *   * `r14d` — stub integrity hash (set by `emit_stub_self_hash`).
 *   * `rsi`  — pointer to the base-key bytes in the `.mxpack`
 *              data region (loaded by the caller's per-layer
 *              `lea rsi, [rip + key_k_rel32]`).
 *
 * Writes:
 *   * `[rsi..rsi+32)` — replaced with the effective key. The
 *     caller's downstream KSA reads from the same rsi so the
 *     replacement is transparent.
 *
 * Clobbers:
 *   * `eax`, `rcx`, `rdx`, `r9d`, RFLAGS.
 *
 * Preserves:
 *   * `rsi` (iterator uses a local `rcx` copy).
 *   * `r14d` (hash is only read, never written).
 *   * `r8`   (S-box pointer — the caller's `lea r8, sbox` remains
 *             valid across the derivation loop because the prime is
 *             loaded into `r9d` instead of `r8d`).
 *
 * Emission layout (32 bytes):
 *
 *     mov   eax, r14d        ; state = hash
 *     mov   rcx, rsi         ; rcx = rsi (iterator copy)
 *     mov   edx, 32          ; counter
 *     mov   r9d, 0x01000193  ; prime
 *   .derive_loop:
 *     xor   al, byte [rcx]   ; state_lo ^= base_key[i]
 *     imul  eax, r9d         ; state *= prime
 *     mov   [rcx], al        ; effective_key[i] = state_lo
 *     inc   rcx              ; advance
 *     dec   edx              ; --count
 *     jnz   .derive_loop     ; loop
 */
void emit_key_derivation_loop(RawEmitter& e);

} // namespace mx::packer
