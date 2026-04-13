/**
 * @file string_encryptor.hpp
 * @brief [BUILDER] Per-string XOR encryption for the S2 pipeline.
 *
 * The S2 decryptor (both stub and VM-lifted variants) implements a
 * single XOR cipher: `byte[i] ^= key`. This is the simplest scheme
 * that resists a `strings` scan of the packed binary. Per-string
 * keys mean an attacker cannot recover the key from known-plaintext
 * on one string and apply it to another, even though the same cipher
 * is used across the whole section.
 *
 * XOR is obviously not cryptographically strong. The S2 defense
 * value comes from two downstream choices:
 *
 *   * `StringProtectionMode::stub` adds cost only against
 *     `strings`-style tools and trivially static dumpers. The key
 *     is visible in the decryptor code if the decryptor is plain
 *     x64.
 *
 *   * `StringProtectionMode::virtualized` hides the decryptor
 *     inside a VM region, so the attacker has to defeat the VM
 *     before they can even see the XOR loop. At that point the
 *     weakness of XOR stops mattering — the constraint is
 *     extraction cost, not cipher strength.
 *
 * S3 (planned) layers ephemeral per-session keys on top by deriving
 * the XOR key at runtime from `(string_id, TEB.Tid, tick_count)`.
 * That's a separate pass and doesn't change the build-time data
 * flow: the encryptor still produces encrypted bytes + a "key"
 * field, but the key is a seed instead of a byte value.
 *
 * This header exposes the encryptor as a pure pair of free
 * functions that operate on byte views, so unit tests can
 * round-trip a buffer without instantiating any class state.
 * A batch `encrypt_all` helper aggregates the per-string records
 * the runtime emitter will consume.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"

namespace mx::string_protect {

/**
 * @brief Encrypt / decrypt `data` in place with a single-byte XOR
 *        key.
 *
 * Both operations are the same function — XOR is self-inverse —
 * but we expose them under two names so call sites read naturally.
 * An empty span is a no-op.
 */
void xor_apply(MutableByteView data, uint8_t key) noexcept;

inline void xor_encrypt(MutableByteView data, uint8_t key) noexcept {
    xor_apply(data, key);
}
inline void xor_decrypt(MutableByteView data, uint8_t key) noexcept {
    xor_apply(data, key);
}

/**
 * @brief One encrypted string ready to be serialised into the
 *        `.mxstr` section.
 *
 * `rva_start` and `length` mirror the fields of `FoundString` so
 * the pass can pair each record with its source candidate. `key`
 * is the per-string XOR key chosen by the encryptor. `ciphertext`
 * owns the encrypted bytes — a copy of the original plaintext
 * with `xor_apply(..., key)` applied. The plaintext buffer is NOT
 * mutated here; that decision (overwrite the original `.rdata`
 * bytes vs. move the ciphertext into a dedicated section) is
 * deferred to the pass orchestrator.
 */
struct EncryptedString {
    Rva                  rva_start  = 0;
    uint32_t             length     = 0;
    uint8_t              key        = 0;
    std::vector<uint8_t> ciphertext;
};

/**
 * @brief Encrypt every candidate in `strings` with a freshly-drawn
 *        per-string key.
 *
 * @param strings  The candidate list from `StringScanner::scan`.
 *                 Their `bytes` views must still be valid — we
 *                 read plaintext from there.
 * @param rng      Randomizer used for key generation. Same seed
 *                 → identical key sequence, so two builds driven
 *                 by the same seed produce byte-identical output.
 *
 * @return One `EncryptedString` per input candidate, in the same
 *         order. The caller owns the ciphertext buffers.
 */
[[nodiscard]] std::vector<EncryptedString>
encrypt_all(const std::vector<FoundString>& strings, Randomizer& rng);

} // namespace mx::string_protect
