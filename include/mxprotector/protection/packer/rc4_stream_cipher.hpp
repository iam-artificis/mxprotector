/**
 * @file rc4_stream_cipher.hpp
 * @brief RC4 implementation of `mx::IStreamCipher` — wraps the
 *        primitive `rc4_init` / `rc4_process` calls.
 *
 * @details The packer uses RC4 today; a future stronger cipher
 *          (ChaCha20, AEGIS) lands as another `IStreamCipher` impl
 *          and a one-line factory swap. Call sites that take
 *          `IStreamCipher&` keep working unchanged.
 *
 *          Behaviour preserved exactly: `init(key, bias)` runs the
 *          KSA seeded by the bias byte; `process(data)` advances the
 *          PRGA byte-by-byte across the data span.
 */

#pragma once

#include "mxprotector/core/interfaces.hpp"
#include "mxprotector/protection/packer/rc4.hpp"

namespace mx::packer {

/// `mx::IStreamCipher` backed by the RC4 primitive in `rc4.hpp`.
class Rc4StreamCipher final : public mx::IStreamCipher {
public:
    Rc4StreamCipher() noexcept = default;

    void init(ByteView key, std::uint8_t bias = 0) noexcept override {
        rc4_init(state_, key, bias);
    }

    void process(MutableByteView data) noexcept override {
        rc4_process(state_, data);
    }

    [[nodiscard]] std::size_t key_size() const noexcept override {
        return kKeySize;
    }

    [[nodiscard]] std::string_view algorithm_name() const noexcept override {
        return "RC4";
    }

private:
    Rc4State state_{};
};

} // namespace mx::packer
