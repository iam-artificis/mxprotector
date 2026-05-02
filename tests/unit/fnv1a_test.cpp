/**
 * @file fnv1a_test.cpp
 * @brief Unit tests for the FNV-1a-32 reference primitive
 *        (`include/mxprotector/common/hash/fnv1a.hpp`).
 *
 * Why these tests live separately from `stub_self_hash_test.cpp`:
 * the FNV-1a primitive is a stand-alone, dependency-free utility
 * shared by the packer P6 self-hash, the guard VEH-handler CRC, and
 * any future module that needs a deterministic 32-bit digest. Pinning
 * its canonical values here keeps the reference contract independent
 * of any one consumer — if a packer-internal refactor ever changes
 * `stub_self_hash`, the FNV-1a baseline still has its own ground
 * truth.
 *
 * Coverage:
 *   - Canonical reference values (empty input, single byte, well-known
 *     ASCII strings).
 *   - `constexpr` evaluation: the reference implementation must fold
 *     at compile time on constant inputs.
 *   - Avalanche on a 1-bit input flip.
 *   - Constant pinning: the offset basis and prime must not silently
 *     drift, otherwise every protected binary would decrypt to garbage.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "mxprotector/common/hash/fnv1a.hpp"
#include "mxprotector/core/types.hpp"

namespace {

using mx::ByteView;
using mx::hash::fnv1a_32;
using mx::hash::kFnv1aOffsetBasis;
using mx::hash::kFnv1aPrime;

[[nodiscard]] ByteView as_bytes(std::string_view s) noexcept {
    return ByteView{
        reinterpret_cast<const std::uint8_t*>(s.data()),
        s.size()};
}

// ---------------------------------------------------------------------------
// Canonical constants
// ---------------------------------------------------------------------------

TEST(Fnv1aHash, OffsetBasisMatchesCanonicalSpec) {
    EXPECT_EQ(kFnv1aOffsetBasis, 0x811C9DC5u);
}

TEST(Fnv1aHash, PrimeMatchesCanonicalSpec) {
    EXPECT_EQ(kFnv1aPrime, 0x01000193u);
}

// ---------------------------------------------------------------------------
// Reference values
// ---------------------------------------------------------------------------

TEST(Fnv1aHash, EmptyInputReturnsOffsetBasis) {
    static_assert(fnv1a_32(ByteView{}) == kFnv1aOffsetBasis,
        "FNV-1a of the empty input must equal the offset basis");
    EXPECT_EQ(fnv1a_32(ByteView{}), 0x811C9DC5u);
}

TEST(Fnv1aHash, SingleByteAMatchesHandComputedValue) {
    // Hand-computed: ((0x811C9DC5 ^ 0x61) * 0x01000193) & 0xFFFFFFFF
    //              =  (0x811C9DA4         * 0x01000193) & 0xFFFFFFFF
    //              =  0xE40C292C
    constexpr std::uint8_t payload[1] = {'a'};
    EXPECT_EQ(fnv1a_32(ByteView{payload, 1}), 0xE40C292Cu);
}

TEST(Fnv1aHash, AsciiFooMatchesPublicReference) {
    // Reference value sourced from the FNV-1a-32 specification's
    // canonical test vector for the input "foo".
    EXPECT_EQ(fnv1a_32(as_bytes("foo")), 0xA9F37ED7u);
}

TEST(Fnv1aHash, AsciiFoobarMatchesPublicReference) {
    EXPECT_EQ(fnv1a_32(as_bytes("foobar")), 0xBF9CF968u);
}

TEST(Fnv1aHash, DistinctInputsProduceDistinctHashes) {
    EXPECT_NE(fnv1a_32(as_bytes("abc")),
              fnv1a_32(as_bytes("abd")));
    EXPECT_NE(fnv1a_32(as_bytes("abc")),
              fnv1a_32(as_bytes("xyz")));
}

// ---------------------------------------------------------------------------
// Avalanche (informal — exact bound is a property of the multiplicative
// step, not a security claim)
// ---------------------------------------------------------------------------

TEST(Fnv1aHash, OneBitInputFlipChangesDigest) {
    constexpr std::array<std::uint8_t, 4> a = {0x00, 0x00, 0x00, 0x00};
    constexpr std::array<std::uint8_t, 4> b = {0x00, 0x00, 0x00, 0x01};
    EXPECT_NE(
        fnv1a_32(ByteView{a.data(), a.size()}),
        fnv1a_32(ByteView{b.data(), b.size()}));
}

// ---------------------------------------------------------------------------
// constexpr foldability — guards against any non-constexpr drift on
// future edits to `fnv1a.hpp`.
// ---------------------------------------------------------------------------

TEST(Fnv1aHash, IsConstexprFoldable) {
    constexpr std::array<std::uint8_t, 3> payload = {'a', 'b', 'c'};
    constexpr std::uint32_t digest =
        fnv1a_32(ByteView{payload.data(), payload.size()});
    static_assert(digest != 0, "constexpr fold must produce a value");
    // Hand-checked: FNV-1a-32("abc") == 0x1A47E90B
    EXPECT_EQ(digest, 0x1A47E90Bu);
}

} // namespace
