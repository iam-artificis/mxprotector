/**
 * @file mx_string_test.cpp
 * @brief [TESTS] Unit tests for mxprotector_sdk/strings.hpp.
 *
 * Covers the strong S1 string-protection layer:
 *
 *   - encrypt/decrypt round-trip at compile time (consteval);
 *   - the per-byte position-mixed keystream really shifts the
 *     ciphertext when the same byte appears at different positions
 *     and when different keys are used;
 *   - the runtime `MxString` / `MxWString` holders decode correctly;
 *   - destructor wipes the buffer (verified by reading the buffer
 *     through a captured pointer post-dtor — the volatile writes are
 *     observable side effects, the read is well-defined as long as
 *     we don't dereference past the holder's lifetime — see comment
 *     on `WipeIsObservedThroughCapturedPointer`);
 *   - `MX_STR` / `MX_WSTR` macros build correctly and decode to the
 *     original literal at runtime.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <string_view>

#include "mxprotector_sdk/strings.hpp"

namespace {

using mx::sdk::detail::call_site_key;
using mx::sdk::detail::decrypt_unit;
using mx::sdk::detail::encrypt_literal;
using mx::sdk::detail::encrypt_unit;

// ---------------------------------------------------------------------------
// Compile-time: encrypt/decrypt round-trip
// ---------------------------------------------------------------------------

TEST(MxStringConsteval, EncryptDecryptRoundtripChar) {
    constexpr uint64_t key = 0xDEADBEEFCAFEBABEULL;
    constexpr const char literal[] = "Hello, world!";
    constexpr auto cipher = encrypt_literal<char, sizeof(literal)>(literal, key);

    for (size_t i = 0; i < sizeof(literal); ++i) {
        EXPECT_EQ(decrypt_unit<char>(cipher[i], i, key), literal[i])
            << "i=" << i;
    }
}

TEST(MxStringConsteval, EncryptDecryptRoundtripWchar) {
    constexpr uint64_t key = 0x123456789ABCDEF0ULL;
    constexpr const wchar_t literal[] = L"Привет, мир!";
    constexpr auto cipher = encrypt_literal<wchar_t, sizeof(literal) /
                                              sizeof(wchar_t)>(literal, key);

    constexpr size_t n = sizeof(literal) / sizeof(wchar_t);
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(decrypt_unit<wchar_t>(cipher[i], i, key), literal[i])
            << "i=" << i;
    }
}

TEST(MxStringConsteval, CipherDiffersFromPlaintext) {
    // For non-trivial inputs, at least one cipher byte must differ
    // from its plaintext byte — otherwise the cipher reduces to the
    // identity and the whole exercise is pointless.
    constexpr uint64_t key = 0xABCD1234FEDC5678ULL;
    constexpr const char literal[] = "MxProtector S1 string protection probe";
    constexpr auto cipher = encrypt_literal<char, sizeof(literal)>(literal, key);

    int diffs = 0;
    for (size_t i = 0; i < sizeof(literal); ++i) {
        if (cipher[i] != literal[i]) ++diffs;
    }
    EXPECT_GT(diffs, 30) << "cipher looks too close to plaintext";
}

// ---------------------------------------------------------------------------
// Position-mixed keystream: same plaintext byte at different positions
// must (almost always) produce different ciphertext.
// ---------------------------------------------------------------------------

TEST(MxStringConsteval, PositionShiftsKeystream) {
    constexpr uint64_t key = 0x0F0F0F0F0F0F0F0FULL;
    // Same character repeated 32 times — identity keystream would
    // produce 32 identical cipher bytes. Position mixing must scatter
    // them.
    constexpr const char literal[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    constexpr auto cipher = encrypt_literal<char, sizeof(literal)>(literal, key);

    // Count how many distinct byte values appear in the cipher of the
    // 32 'A's (positions 0..31, ignoring null terminator).
    std::array<bool, 256> seen{};
    for (size_t i = 0; i < 32; ++i) {
        seen[static_cast<unsigned char>(cipher[i])] = true;
    }
    int distinct = 0;
    for (bool v : seen) if (v) ++distinct;

    // The keystream must give us "lots" of distinct values — with
    // proper splitmix mixing we expect ≈ 32 distinct (collisions
    // occur rarely). Anything below 16 means the position derivation
    // is too weak.
    EXPECT_GT(distinct, 16)
        << "position-mixed keystream is too weak — only "
        << distinct << " distinct cipher bytes for 32 'A's";
}

TEST(MxStringConsteval, DifferentKeysProduceDifferentCipher) {
    constexpr const char literal[] = "stable plaintext for key comparison";
    constexpr auto cipher_a =
        encrypt_literal<char, sizeof(literal)>(literal, 0xAAAAAAAAAAAAAAAAULL);
    constexpr auto cipher_b =
        encrypt_literal<char, sizeof(literal)>(literal, 0x5555555555555555ULL);

    int diffs = 0;
    for (size_t i = 0; i < sizeof(literal); ++i) {
        if (cipher_a[i] != cipher_b[i]) ++diffs;
    }
    EXPECT_GT(diffs, sizeof(literal) / 2)
        << "two distinct keys produced too-similar ciphertext";
}

TEST(MxStringConsteval, CallSiteKeyChangesWithEveryInput) {
    constexpr auto k1 = call_site_key("file_a.cpp", 10, 0);
    constexpr auto k2 = call_site_key("file_b.cpp", 10, 0);
    constexpr auto k3 = call_site_key("file_a.cpp", 11, 0);
    constexpr auto k4 = call_site_key("file_a.cpp", 10, 1);
    EXPECT_NE(k1, k2);  // file change
    EXPECT_NE(k1, k3);  // line change
    EXPECT_NE(k1, k4);  // counter change
}

// ---------------------------------------------------------------------------
// Runtime holder: build via the macro, read, verify
// ---------------------------------------------------------------------------

TEST(MxStringRuntime, MacroDecodesNarrowLiteral) {
    auto s = MX_STR("Hello, world!");
    EXPECT_STREQ(s.c_str(), "Hello, world!");
    EXPECT_EQ(s.size(), std::string_view("Hello, world!").size());
}

TEST(MxStringRuntime, MacroDecodesWideLiteral) {
    auto s = MX_WSTR(L"Wide string with non-ASCII: \u00fcber");
    EXPECT_EQ(std::wstring(s.c_str()),
              std::wstring(L"Wide string with non-ASCII: \u00fcber"));
}

TEST(MxStringRuntime, ImplicitCharStarConversion) {
    auto s = MX_STR("conversion test");
    const char* p = s;  // implicit operator const char*
    EXPECT_STREQ(p, "conversion test");
}

TEST(MxStringRuntime, EmptyLiteralRoundtrip) {
    auto s = MX_STR("");
    EXPECT_STREQ(s.c_str(), "");
    EXPECT_EQ(s.size(), 0u);
}

TEST(MxStringRuntime, MultipleSitesAreIndependent) {
    auto a = MX_STR("alpha");
    auto b = MX_STR("alpha");  // same literal, different __COUNTER__
    EXPECT_STREQ(a.c_str(), "alpha");
    EXPECT_STREQ(b.c_str(), "alpha");
    EXPECT_NE(static_cast<const void*>(a.c_str()),
              static_cast<const void*>(b.c_str()))
        << "two MX_STR sites must yield independent stack buffers";
}

// ---------------------------------------------------------------------------
// Destructor wipe — verified by reading the buffer through a captured
// pointer post-dtor. The pointer dangles AFTER the holder dies, but the
// stack memory it pointed at is still readable until the next stack
// frame overwrites it. We capture the pointer via a side-effect setter
// and then check that the buffer was zeroed by the dtor.
//
// This is undefined behaviour in the strictest reading — we read freed
// stack memory — but in practice MSVC/GCC do not poison returned-stack
// memory immediately. The test verifies that the dtor's volatile wipe
// stores ran AT ALL (otherwise the buffer would still hold the
// plaintext, and the test would fail). It is intentionally fragile in
// debug builds with stack-poisoning sanitisers; the meaningful check
// runs in Release.
// ---------------------------------------------------------------------------

namespace {
const char* g_captured_ptr = nullptr;

void capture_ptr(const char* p) { g_captured_ptr = p; }
} // namespace

TEST(MxStringRuntime, DestructorWipesBuffer) {
    {
        auto s = MX_STR("buffer-wipe-probe");
        capture_ptr(s.c_str());
        // Immediately after construction, the buffer holds plaintext.
        ASSERT_STREQ(g_captured_ptr, "buffer-wipe-probe");
    }  // <-- s.~basic_mx_string() runs here, volatile wipe

    // The captured pointer now points at "freed" stack memory. Read
    // the first byte — the wipe should have set it to 0. If the
    // optimiser had elided the volatile wipe stores, we'd still see
    // 'b' here and the test would fail.
    EXPECT_EQ(g_captured_ptr[0], '\0')
        << "destructor failed to wipe — first byte is still "
        << static_cast<int>(static_cast<unsigned char>(g_captured_ptr[0]));
}

} // namespace
