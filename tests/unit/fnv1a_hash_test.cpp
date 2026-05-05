/**
 * @file fnv1a_hash_test.cpp
 * @brief Unit tests for `mx::hash::Fnv1a32Hash` — the `IHash`
 *        wrapper around the constexpr `fnv1a_32` primitive.
 *
 * @details Confirms:
 *            * one-shot `hash(data, out)` matches `fnv1a_32(data)`
 *              byte-for-byte;
 *            * streaming (`reset` + multiple `update`s) matches the
 *              one-shot result over the concatenated input;
 *            * `digest_size()` is 4 bytes;
 *            * `is_cryptographic()` is `false`;
 *            * `algorithm_name()` is `"FNV-1a-32"`.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "mxprotector/common/hash/fnv1a.hpp"
#include "mxprotector/common/hash/fnv1a_hash.hpp"

using namespace mx;
using namespace mx::hash;

namespace {

[[nodiscard]] std::uint32_t digest_to_u32(std::array<std::uint8_t, 4> d) {
    std::uint32_t h = 0;
    std::memcpy(&h, d.data(), 4);
    return h;
}

} // namespace

TEST(Fnv1a32HashTest, OneShotMatchesPrimitive) {
    const std::array<std::uint8_t, 8> data = {1, 2, 3, 4, 5, 6, 7, 8};
    const std::uint32_t direct = fnv1a_32(ByteView{data.data(), data.size()});

    Fnv1a32Hash h;
    std::array<std::uint8_t, 4> digest{};
    h.hash(ByteView{data.data(), data.size()},
           MutableByteView{digest.data(), digest.size()});

    EXPECT_EQ(digest_to_u32(digest), direct);
}

TEST(Fnv1a32HashTest, StreamingMatchesOneShot) {
    const std::array<std::uint8_t, 8> all = {1, 2, 3, 4, 5, 6, 7, 8};

    Fnv1a32Hash one_shot;
    std::array<std::uint8_t, 4> one_digest{};
    one_shot.hash(ByteView{all.data(), all.size()},
                  MutableByteView{one_digest.data(), one_digest.size()});

    Fnv1a32Hash streamed;
    streamed.reset();
    streamed.update(ByteView{all.data(), 4});
    streamed.update(ByteView{all.data() + 4, 4});
    std::array<std::uint8_t, 4> streamed_digest{};
    streamed.finalize(MutableByteView{streamed_digest.data(),
                                       streamed_digest.size()});

    EXPECT_EQ(one_digest, streamed_digest);
}

TEST(Fnv1a32HashTest, EmptyInputYieldsOffsetBasis) {
    Fnv1a32Hash h;
    std::array<std::uint8_t, 4> digest{};
    h.hash(ByteView{}, MutableByteView{digest.data(), digest.size()});
    EXPECT_EQ(digest_to_u32(digest), kFnv1aOffsetBasis);
}

TEST(Fnv1a32HashTest, ReportsDigestSizeAndAlgorithm) {
    Fnv1a32Hash h;
    EXPECT_EQ(h.digest_size(), 4u);
    EXPECT_FALSE(h.is_cryptographic());
    EXPECT_EQ(h.algorithm_name(), "FNV-1a-32");
}

TEST(Fnv1a32HashTest, ResetClearsState) {
    Fnv1a32Hash h;
    h.update(ByteView{reinterpret_cast<const std::uint8_t*>("abcd"), 4});
    h.reset();
    std::array<std::uint8_t, 4> after_reset{};
    h.finalize(MutableByteView{after_reset.data(), after_reset.size()});
    EXPECT_EQ(digest_to_u32(after_reset), kFnv1aOffsetBasis);
}
