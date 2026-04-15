/**
 * @file rc4.cpp
 * @brief Build-time RC4 implementation — see rc4.hpp for rationale.
 */

#include "mxprotector/protection/packer/rc4.hpp"

#include <algorithm>

namespace mx::packer {

void rc4_init(Rc4State& s, ByteView key, uint8_t anti_debug_bias) noexcept {
    for (uint32_t k = 0; k < kSboxSize; ++k) {
        s.sbox[k] = static_cast<uint8_t>(k);
    }
    uint8_t j = anti_debug_bias;
    for (uint32_t k = 0; k < kSboxSize; ++k) {
        j = static_cast<uint8_t>(
            j + s.sbox[k] + key[k % key.size()]);
        std::swap(s.sbox[k], s.sbox[j]);
    }
    s.i = 0;
    s.j = 0;
}

void rc4_process(Rc4State& s, MutableByteView data) noexcept {
    for (auto& b : data) {
        s.i = static_cast<uint8_t>(s.i + 1);
        s.j = static_cast<uint8_t>(s.j + s.sbox[s.i]);
        std::swap(s.sbox[s.i], s.sbox[s.j]);
        const uint8_t k = s.sbox[
            static_cast<uint8_t>(s.sbox[s.i] + s.sbox[s.j])];
        b = static_cast<uint8_t>(b ^ k);
    }
}

} // namespace mx::packer
