/**
 * @file string_encryptor.cpp
 * @brief [BUILDER] Single-byte XOR encryptor, per-string key.
 *
 * Two observations drive the implementation:
 *
 *   * The cipher is self-inverse: `xor_apply(xor_apply(x)) == x`.
 *     There's no separate "decrypt" code path anywhere in the
 *     codebase — build-time encryption and runtime decryption
 *     use the same bytes-in, bytes-out transform.
 *
 *   * Keys MUST be non-zero. A zero-byte key leaves the ciphertext
 *     identical to plaintext; if the RNG rolls 0, a `strings` scan
 *     of the packed binary recovers the string for free. We bias
 *     the key generator to skip 0 — it costs one extra draw per
 *     few hundred strings on average and guarantees the invariant.
 *
 * Everything else is linear and trivial.
 */

#include "mxprotector/protection/string/string_encryptor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace mx::string_protect {

void xor_apply(MutableByteView data, uint8_t key) noexcept {
    for (uint8_t& b : data) {
        b = static_cast<uint8_t>(b ^ key);
    }
}

std::vector<EncryptedString>
encrypt_all(const std::vector<FoundString>& strings, Randomizer& rng)
{
    std::vector<EncryptedString> result;
    result.reserve(strings.size());

    for (const auto& fs : strings) {
        // Reject a zero key — it would leave the ciphertext equal
        // to the plaintext, which defeats the entire pass on that
        // specific string.
        uint8_t key = 0;
        do { key = rng.next_u8(); } while (key == 0);

        EncryptedString enc{};
        enc.rva_start = fs.rva_start;
        enc.length    = fs.length;
        enc.key       = key;
        enc.ciphertext.resize(fs.length);
        for (size_t i = 0; i < fs.length; ++i) {
            enc.ciphertext[i] = static_cast<uint8_t>(
                static_cast<uint8_t>(fs.bytes[i]) ^ key);
        }

        result.push_back(std::move(enc));
    }

    return result;
}

} // namespace mx::string_protect
