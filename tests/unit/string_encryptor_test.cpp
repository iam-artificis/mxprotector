/**
 * @file string_encryptor_test.cpp
 * @brief [TESTS] Unit tests for the S2 per-string XOR encryptor.
 *
 * Covers:
 *   - `xor_apply` is self-inverse (encrypt + encrypt == identity)
 *   - Empty buffer is a no-op
 *   - Identity key (all zeros) DOES leave plaintext unchanged — the
 *     classifier-level guarantee is enforced by the RNG path, not
 *     by `xor_apply` itself
 *   - `encrypt_all` produces one record per input
 *   - `encrypt_all` never produces a zero key
 *   - Same RNG seed → byte-identical ciphertext and keys (build
 *     determinism)
 *   - Different seeds → different keys (at least one string
 *     differs) — smoke test, not a distribution test
 *   - Round trip: `encrypt_all` then decrypt each record → the
 *     original bytes are recovered exactly
 *   - Multiple strings with varying lengths are all handled
 *   - A "vector of strings" shaped input (several entries with
 *     realistic content) encrypts end to end without state leakage
 *     between entries
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/string/string_encryptor.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"

namespace {

using mx::MutableByteView;
using mx::Randomizer;
using mx::Rva;
using mx::string_protect::EncryptedString;
using mx::string_protect::FoundString;

/// Build a synthetic FoundString record backed by a caller-owned
/// string buffer. The caller holds the storage so the view stays
/// valid for the test's lifetime.
FoundString make_found(const std::string& owner, Rva rva) {
    FoundString fs{};
    fs.rva_start = rva;
    fs.length    = static_cast<uint32_t>(owner.size());
    fs.bytes     = std::string_view{owner};
    return fs;
}

// ---------------------------------------------------------------------------
// xor_apply primitive
// ---------------------------------------------------------------------------

TEST(StringEncryptorPrimitive, XorApplyIsSelfInverse) {
    const std::vector<uint8_t> original = {'h','e','l','l','o',',',' ','w','o','r','l','d'};
    std::vector<uint8_t> buf = original;

    mx::string_protect::xor_apply(MutableByteView{buf.data(), buf.size()}, 0x5A);
    EXPECT_NE(buf, original) << "encryption must change the bytes";

    mx::string_protect::xor_apply(MutableByteView{buf.data(), buf.size()}, 0x5A);
    EXPECT_EQ(buf, original) << "second application must restore the original";
}

TEST(StringEncryptorPrimitive, XorApplyEmptyIsNoop) {
    std::vector<uint8_t> buf;
    // Just verify no crash / UB.
    mx::string_protect::xor_apply(MutableByteView{buf.data(), buf.size()}, 0x42);
    EXPECT_TRUE(buf.empty());
}

TEST(StringEncryptorPrimitive, XorApplyZeroKeyLeavesBytesUnchanged) {
    // Documents the behaviour: xor_apply with a 0 key is a no-op.
    // The public `encrypt_all` guards against this so the caller
    // never actually sees a 0 key, but at the primitive level the
    // identity is a consequence of the math, not a bug.
    const std::vector<uint8_t> original = {1, 2, 3, 4, 5};
    std::vector<uint8_t> buf = original;
    mx::string_protect::xor_apply(MutableByteView{buf.data(), buf.size()}, 0);
    EXPECT_EQ(buf, original);
}

// ---------------------------------------------------------------------------
// encrypt_all — batch behaviour
// ---------------------------------------------------------------------------

TEST(StringEncryptorBatch, ProducesOneRecordPerCandidate) {
    std::string s1 = "first_string!";
    std::string s2 = "second!!";
    std::string s3 = "third_and_a_bit_longer";

    const std::vector<FoundString> inputs = {
        make_found(s1, 0x2000),
        make_found(s2, 0x2100),
        make_found(s3, 0x2200),
    };

    Randomizer rng(12345);
    auto out = mx::string_protect::encrypt_all(inputs, rng);

    ASSERT_EQ(out.size(), inputs.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        EXPECT_EQ(out[i].rva_start, inputs[i].rva_start);
        EXPECT_EQ(out[i].length,    inputs[i].length);
        EXPECT_EQ(out[i].ciphertext.size(), inputs[i].length);
    }
}

TEST(StringEncryptorBatch, NeverProducesZeroKey) {
    // Run a long batch with a deterministic seed; every record must
    // carry a non-zero key. If the RNG happens to roll 0, the
    // encryptor should spin until it produces a non-zero value.
    std::vector<std::string> owners;
    std::vector<FoundString> inputs;
    for (int i = 0; i < 200; ++i) {
        owners.push_back("string_number_" + std::to_string(i));
    }
    for (size_t i = 0; i < owners.size(); ++i) {
        inputs.push_back(make_found(owners[i], 0x3000 + static_cast<Rva>(i * 32)));
    }

    Randomizer rng(0xABCDEF);
    auto out = mx::string_protect::encrypt_all(inputs, rng);

    ASSERT_EQ(out.size(), inputs.size());
    for (size_t i = 0; i < out.size(); ++i) {
        EXPECT_NE(out[i].key, 0u) << "record " << i;
    }
}

TEST(StringEncryptorBatch, SameSeedProducesIdenticalOutput) {
    std::string a = "alpha_long_enough";
    std::string b = "beta_long_enough_2";
    const std::vector<FoundString> inputs = {
        make_found(a, 0x2000),
        make_found(b, 0x2100),
    };

    Randomizer rng1(42);
    Randomizer rng2(42);
    auto out1 = mx::string_protect::encrypt_all(inputs, rng1);
    auto out2 = mx::string_protect::encrypt_all(inputs, rng2);

    ASSERT_EQ(out1.size(), out2.size());
    for (size_t i = 0; i < out1.size(); ++i) {
        EXPECT_EQ(out1[i].key,        out2[i].key);
        EXPECT_EQ(out1[i].ciphertext, out2[i].ciphertext);
    }
}

TEST(StringEncryptorBatch, DifferentSeedsProduceDifferentKeys) {
    // Not a distribution test — we only need at least one
    // difference across the batch to know the RNG is actually
    // consulted.
    std::vector<std::string> owners;
    for (int i = 0; i < 10; ++i) {
        owners.push_back("str_" + std::to_string(i) + "_payload");
    }
    std::vector<FoundString> inputs;
    for (size_t i = 0; i < owners.size(); ++i) {
        inputs.push_back(make_found(owners[i], 0x4000 + static_cast<Rva>(i * 32)));
    }

    Randomizer rng_a(1);
    Randomizer rng_b(2);
    auto out_a = mx::string_protect::encrypt_all(inputs, rng_a);
    auto out_b = mx::string_protect::encrypt_all(inputs, rng_b);

    bool any_key_diff = false;
    for (size_t i = 0; i < out_a.size(); ++i) {
        if (out_a[i].key != out_b[i].key) { any_key_diff = true; break; }
    }
    EXPECT_TRUE(any_key_diff);
}

// ---------------------------------------------------------------------------
// Round trip — vector-of-strings shape
// ---------------------------------------------------------------------------

TEST(StringEncryptorRoundTrip, MultipleStringsRestoredExactly) {
    // Simulates the "static const char* kNames[] = { ... }" layout
    // at the byte level. Plain-text owners stored alongside the
    // inputs so we can compare against the decrypted output.
    const std::vector<std::string> owners = {
        "monday_v1",
        "tuesday_v1",
        "wednesday_v1",
        "thursday_v1",
        "friday_v1",
    };
    std::vector<FoundString> inputs;
    for (size_t i = 0; i < owners.size(); ++i) {
        inputs.push_back(make_found(owners[i], 0x5000 + static_cast<Rva>(i * 64)));
    }

    Randomizer rng(0xC0FFEE);
    auto enc = mx::string_protect::encrypt_all(inputs, rng);
    ASSERT_EQ(enc.size(), owners.size());

    // Decrypt and compare byte-for-byte.
    for (size_t i = 0; i < enc.size(); ++i) {
        std::vector<uint8_t> buf = enc[i].ciphertext;
        mx::string_protect::xor_decrypt(
            MutableByteView{buf.data(), buf.size()}, enc[i].key);

        std::string restored(reinterpret_cast<const char*>(buf.data()),
                              buf.size());
        EXPECT_EQ(restored, owners[i]) << "record " << i;
    }
}

TEST(StringEncryptorRoundTrip, EmptyPlaintextRoundTripIsNoop) {
    std::string empty{};
    const std::vector<FoundString> inputs = { make_found(empty, 0x6000) };

    Randomizer rng(7);
    auto out = mx::string_protect::encrypt_all(inputs, rng);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].length, 0u);
    EXPECT_TRUE(out[0].ciphertext.empty());
    // Key still non-zero even for an empty string — the guard is
    // unconditional.
    EXPECT_NE(out[0].key, 0u);
}

TEST(StringEncryptorRoundTrip, VaryingLengthStringsAllRoundTrip) {
    const std::vector<std::string> owners = {
        "a",                                          // 1
        "ab",                                         // 2
        "tiny!",                                       // 5
        "medium_length_string",                       // 20
        std::string(200, 'x') + std::string(200, 'y'),// 400 — long
    };
    std::vector<FoundString> inputs;
    for (size_t i = 0; i < owners.size(); ++i) {
        inputs.push_back(make_found(owners[i], 0x7000 + static_cast<Rva>(i * 512)));
    }

    Randomizer rng(0xDEADBEEF);
    auto enc = mx::string_protect::encrypt_all(inputs, rng);
    ASSERT_EQ(enc.size(), owners.size());

    for (size_t i = 0; i < enc.size(); ++i) {
        // The ciphertext must not match the plaintext (caveat: very
        // short strings could theoretically map through xor to
        // themselves, but only for key=0 which we reject). All
        // non-empty owners in this test have more than one unique
        // byte, so a non-zero key always changes at least one.
        if (!owners[i].empty()) {
            bool any_diff = false;
            for (size_t j = 0; j < owners[i].size(); ++j) {
                if (enc[i].ciphertext[j] !=
                    static_cast<uint8_t>(owners[i][j]))
                {
                    any_diff = true;
                    break;
                }
            }
            EXPECT_TRUE(any_diff) << "record " << i << " unchanged by xor";
        }

        std::vector<uint8_t> buf = enc[i].ciphertext;
        mx::string_protect::xor_decrypt(
            MutableByteView{buf.data(), buf.size()}, enc[i].key);
        const std::string restored(
            reinterpret_cast<const char*>(buf.data()), buf.size());
        EXPECT_EQ(restored, owners[i]) << "record " << i;
    }
}

} // namespace
