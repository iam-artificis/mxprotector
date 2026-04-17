/**
 * @file packer_section_encryptor.hpp
 * @brief P6 — stub-self-hash → derive effective keys → RC4-encrypt
 *        every target section (build-time half of the runtime cascade).
 *
 * This is the final step of the packer pipeline. By the time it
 * runs:
 *   - the .mxpack section is placed at its final runtime RVA;
 *   - every rel32 inside the cipher body is patched;
 *   - every TLS slot is finalised;
 *   - the target sections are still plaintext (their encryption was
 *     deferred so the effective keys can be derived from the
 *     finalised stub bytes).
 *
 * What this module does, in the same order the runtime stub will
 * undo at process startup:
 *
 *   1. Stamp the runtime self-hash loop's `count imm32` slot with
 *      the finalised hash range length, then compute the FNV-1a
 *      hash over `pack_section_data[0, hash_range_end)`. Bit-exact
 *      against what the runtime will produce on a clean host.
 *
 *   2. For each cipher layer, derive an effective key from the
 *      (still-plaintext) base key by running the same
 *      `derive_effective_key_in_place` FNV-1a chain the runtime
 *      uses.
 *
 *   3. RC4-encrypt every target section with each effective key in
 *      BUILD order `0 -> N-1`. The runtime decrypts in reverse
 *      order `N-1 -> 0`, and each RC4 round is self-inverse, so
 *      the cascade unwinds to plaintext on a clean host. Build-time
 *      anti-debug bias is always 0 (clean host), matching layer 0's
 *      runtime seed when no debugger is attached.
 *
 * Base keys are NOT mutated — they stay as-is inside the stub's
 * data tail so the runtime derivation loop (which reads the base
 * keys and the live self-hash) produces the same effective keys at
 * load time.
 *
 * Fails only when the caller handed us a bad `hash_range_end`
 * (zero or beyond the section bounds) — in every other case the
 * step succeeds, encrypts in place, and logs one line per target
 * section.
 */

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"

namespace mx { class ProtectionContext; }

namespace mx::packer {

/**
 * @brief One target section to encrypt in place.
 *
 * The encryptor writes ciphertext back through
 * `ctx.pe_image().sections()[image_index].data` — it does not index
 * by RVA. `rva` and `size` are carried through for the "зашифрована
 * '.text' RVA=0x… N bytes" log line.
 */
struct EncryptionTarget {
    size_t   image_index = 0;
    Rva      rva         = 0;
    uint32_t size        = 0;
};

/**
 * @brief Run the P6 hash → derive → encrypt cascade.
 *
 * @param ctx                Protection context — read for the
 *                           pe_image (target section access), write
 *                           to the log channel.
 * @param pack_section_data  Mutable stub section bytes. The
 *                           `count imm32` slot inside this buffer is
 *                           patched before the hash is computed so
 *                           the runtime reads the same count from the
 *                           finalised bytes.
 * @param hash_range_end     One-past-last byte of the hashed range
 *                           inside `pack_section_data`. Must be
 *                           nonzero and within the buffer.
 * @param count_imm32_offset Offset of the `mov ecx, <count>` imm32
 *                           slot the runtime self-hash loop reads.
 * @param layer_count        Number of cipher layers — must equal
 *                           `layer_keys.size()` and be ≥ 1.
 * @param layer_keys         Per-layer 32-byte base RC4 keys. Not
 *                           mutated; the derivation is applied to
 *                           local copies.
 * @param targets            Sections to encrypt, in build order
 *                           (layer 0 first, then 1, …, then N-1).
 */
[[nodiscard]] MxStatus hash_derive_and_encrypt(
    mx::ProtectionContext&            ctx,
    ByteBuffer&                       pack_section_data,
    uint32_t                          hash_range_end,
    uint32_t                          count_imm32_offset,
    uint32_t                          layer_count,
    const std::vector<ByteBuffer>&    layer_keys,
    std::span<const EncryptionTarget> targets);

} // namespace mx::packer
