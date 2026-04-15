/**
 * @file rc4.hpp
 * @brief Build-time RC4 stream cipher used by the packer to encrypt PE sections.
 *
 * The runtime unpacker stub emitted by `emit_decrypt_body` implements
 * standard RC4 (KSA + PRGA) in x64 assembly. This module runs the same
 * algorithm at build time so the encrypted output stored in the protected
 * PE matches what the stub will decrypt at runtime.
 *
 * ## Anti-debug bias
 *
 * `rc4_init` takes an `anti_debug_bias` byte that seeds the KSA's `j`
 * register. The runtime stub reads this bias from `edx` (populated by
 * the anti-debug probe that runs just before the KSA) — normally 0,
 * but 1 when a debugger is present. At build time we always pass 0,
 * so the pre-computed S-box agrees with the runtime one on a clean
 * host. Under a debugger the runtime KSA sees `j = 1` at its very
 * first iteration, produces an entirely different S-box, and the
 * per-section PRGA stream decrypts the ciphertext into garbage. There
 * is no explicit "if debugger then crash" branch — the cipher itself
 * silently fails.
 *
 * ## P2 multi-layer unpack
 *
 * `execute_encrypted_stub` in `packer_pass.cpp` applies the cipher in
 * multiple rounds: one fresh `Rc4State` per cipher layer, each
 * carrying its `(S-box, i, j)` state across every encrypted section
 * within that layer. The layer ordering matches the runtime stub's
 * layer loop, so the cascade of XORs symmetric-unwinds to plaintext.
 */

#pragma once

#include <array>
#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx::packer {

/// RC4 input key size in bytes (256 bits). The emitted runtime stub
/// hard-codes a `k mod 32` mask inside its KSA loop, so build-time and
/// runtime must agree on this value.
constexpr uint32_t kKeySize  = 32;

/// RC4 S-box size — fixed by the algorithm.
constexpr uint32_t kSboxSize = 256;

/// Cipher state: 256-byte permutation + PRGA cursors `(i, j)`.
struct Rc4State {
    std::array<uint8_t, kSboxSize> sbox{};
    uint8_t i = 0;
    uint8_t j = 0;
};

/**
 * @brief Run the RC4 Key Scheduling Algorithm on `key` and store the
 *        permuted S-box in `s`.
 *
 * @param s                 Cipher state (sbox + PRGA cursors) to populate.
 * @param key               Input key bytes — length is free, the KSA
 *                          modularises the index internally.
 * @param anti_debug_bias   Initial value of `j` for KSA phase 2. Always
 *                          0 at build time; 0 or 1 at runtime depending
 *                          on the anti-debug probe.
 */
void rc4_init(Rc4State& s, ByteView key, uint8_t anti_debug_bias) noexcept;

/**
 * @brief PRGA one-shot: XOR `data` with the next `data.size()` bytes of
 *        the RC4 keystream, advancing `s.i / s.j` as it goes.
 *
 * RC4 is self-inverse through XOR — the same call with the same state
 * decrypts whatever was previously encrypted. Callers pass a fresh
 * `Rc4State` per cipher layer so the build-time and runtime streams
 * stay in lockstep.
 */
void rc4_process(Rc4State& s, MutableByteView data) noexcept;

} // namespace mx::packer
