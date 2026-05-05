/**
 * @file rc4_stream_cipher_test.cpp
 * @brief Unit tests for `packer::Rc4StreamCipher`.
 *
 * @details Verifies the RC4 wrapper of `mx::IStreamCipher`:
 *            * `init(key, bias)` then `process(buf)` matches the
 *              primitive `rc4_init` + `rc4_process` byte-for-byte;
 *            * stateful streaming — two back-to-back `process` calls
 *              produce the same bytes as one call over the
 *              concatenated input;
 *            * self-inverse — encrypting then decrypting (with an
 *              independently-initialised cipher) yields the original
 *              bytes;
 *            * `algorithm_name()` returns `"RC4"`;
 *            * `key_size()` returns the expected `kKeySize`.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "mxprotector/protection/packer/rc4.hpp"
#include "mxprotector/protection/packer/rc4_stream_cipher.hpp"

using namespace mx;
using namespace mx::packer;

namespace {

constexpr std::array<uint8_t, 8> kPlaintext  = {1, 2, 3, 4, 5, 6, 7, 8};
constexpr std::array<uint8_t, 4> kKey        = {0xDE, 0xAD, 0xBE, 0xEF};

} // namespace

TEST(Rc4StreamCipherTest, MatchesPrimitiveByteForByte) {
    Rc4State direct{};
    rc4_init(direct, ByteView{kKey.data(), kKey.size()}, /*bias=*/0);
    std::array<uint8_t, kPlaintext.size()> direct_out = kPlaintext;
    rc4_process(direct, MutableByteView{direct_out.data(), direct_out.size()});

    Rc4StreamCipher wrapped;
    wrapped.init(ByteView{kKey.data(), kKey.size()}, /*bias=*/0);
    std::array<uint8_t, kPlaintext.size()> wrapped_out = kPlaintext;
    wrapped.process(MutableByteView{wrapped_out.data(), wrapped_out.size()});

    EXPECT_EQ(direct_out, wrapped_out);
}

TEST(Rc4StreamCipherTest, StatefulStreamingProducesContinuousKeystream) {
    Rc4StreamCipher one_shot;
    one_shot.init(ByteView{kKey.data(), kKey.size()});
    std::array<uint8_t, 8> one_shot_buf = kPlaintext;
    one_shot.process(MutableByteView{one_shot_buf.data(), one_shot_buf.size()});

    Rc4StreamCipher chunked;
    chunked.init(ByteView{kKey.data(), kKey.size()});
    std::array<uint8_t, 8> chunked_buf = kPlaintext;
    chunked.process(MutableByteView{chunked_buf.data(), 4});
    chunked.process(MutableByteView{chunked_buf.data() + 4, 4});

    EXPECT_EQ(one_shot_buf, chunked_buf);
}

TEST(Rc4StreamCipherTest, IsSelfInverse) {
    std::array<uint8_t, kPlaintext.size()> buf = kPlaintext;

    Rc4StreamCipher enc;
    enc.init(ByteView{kKey.data(), kKey.size()});
    enc.process(MutableByteView{buf.data(), buf.size()});

    Rc4StreamCipher dec;
    dec.init(ByteView{kKey.data(), kKey.size()});
    dec.process(MutableByteView{buf.data(), buf.size()});

    EXPECT_EQ(buf, kPlaintext);
}

TEST(Rc4StreamCipherTest, BiasByteFlowsToKsa) {
    Rc4StreamCipher with_bias_zero;
    with_bias_zero.init(ByteView{kKey.data(), kKey.size()}, /*bias=*/0);
    std::array<uint8_t, 8> buf_zero = kPlaintext;
    with_bias_zero.process(MutableByteView{buf_zero.data(), buf_zero.size()});

    Rc4StreamCipher with_bias_one;
    with_bias_one.init(ByteView{kKey.data(), kKey.size()}, /*bias=*/1);
    std::array<uint8_t, 8> buf_one = kPlaintext;
    with_bias_one.process(MutableByteView{buf_one.data(), buf_one.size()});

    // Different KSA seed → different keystream → different ciphertext.
    EXPECT_NE(buf_zero, buf_one);
}

TEST(Rc4StreamCipherTest, ReportsAlgorithmName) {
    Rc4StreamCipher c;
    EXPECT_EQ(c.algorithm_name(), "RC4");
}

TEST(Rc4StreamCipherTest, ReportsKeySize) {
    Rc4StreamCipher c;
    EXPECT_EQ(c.key_size(), kKeySize);
}
