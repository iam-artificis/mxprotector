/**
 * @file string_scanner_test.cpp
 * @brief [TESTS] Unit tests for the S2 string scanner.
 *
 * Covers the shapes a real `.rdata` section tends to contain:
 *
 *   * A single `const char*` literal
 *   * Several adjacent C strings separated by one NUL byte each —
 *     this is how MSVC lays out string literals from the same TU
 *   * A "vector of strings" layout: a pointer table followed by a
 *     pool of strings, mirroring `static const char* kNames[] = ...`
 *     which is the most common array-of-string idiom in C and C++
 *   * Rejection cases: too-short runs, interior NUL without full
 *     termination, non-printable garbage, lack of NUL terminator at
 *     end of buffer (when strict mode is on), bytes near the buffer
 *     edge
 *   * Configurable length thresholds (min/max)
 *   * Classifier sanity: printable vs. non-printable
 *
 * The tests only exercise the scanner in isolation — no PE parsing,
 * no XREF logic. All inputs are hand-assembled `std::vector<uint8_t>`
 * buffers so failures point at a specific line in this file rather
 * than at some opaque integration step.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"

namespace {

using mx::ByteView;
using mx::Rva;
using mx::string_protect::FoundString;
using mx::string_protect::ScannerConfig;
using mx::string_protect::StringScanner;

/// Convenience: append a null-terminated ASCII literal to a byte buffer
/// and return the offset at which it was placed. Used by every "build
/// a synthetic .rdata" test below so the string layout is explicit.
size_t push_cstr(std::vector<uint8_t>& buf, std::string_view s) {
    const size_t off = buf.size();
    buf.insert(buf.end(), s.begin(), s.end());
    buf.push_back(0x00);
    return off;
}

/// Overload that appends `count` copies of `pad_byte` to simulate
/// padding / alignment bytes that `.rdata` tends to contain.
void push_pad(std::vector<uint8_t>& buf, uint8_t pad_byte, size_t count) {
    buf.insert(buf.end(), count, pad_byte);
}

/// Look up a candidate by its raw bytes — tests don't care about order.
const FoundString* find_by_text(const std::vector<FoundString>& v,
                                 std::string_view text)
{
    for (const auto& fs : v) {
        if (fs.bytes == text) return &fs;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

TEST(StringScannerClassifier, AcceptsPrintableAscii) {
    // Every byte in the printable range 0x20..0x7E is a valid string byte.
    for (int c = 0x20; c <= 0x7E; ++c) {
        EXPECT_TRUE(StringScanner::is_string_byte(static_cast<uint8_t>(c)))
            << "byte 0x" << std::hex << c << " should be a string byte";
    }
}

TEST(StringScannerClassifier, AcceptsTab) {
    EXPECT_TRUE(StringScanner::is_string_byte(0x09));
}

TEST(StringScannerClassifier, RejectsNulAndControlBytes) {
    EXPECT_FALSE(StringScanner::is_string_byte(0x00));
    EXPECT_FALSE(StringScanner::is_string_byte(0x0A));  // \n
    EXPECT_FALSE(StringScanner::is_string_byte(0x0D));  // \r
    EXPECT_FALSE(StringScanner::is_string_byte(0x1F));
    EXPECT_FALSE(StringScanner::is_string_byte(0x7F));
    EXPECT_FALSE(StringScanner::is_string_byte(0xFF));
}

// ---------------------------------------------------------------------------
// Empty / edge cases
// ---------------------------------------------------------------------------

TEST(StringScannerEdge, EmptyBufferReturnsNoCandidates) {
    StringScanner scanner;
    auto result = scanner.scan(ByteView{}, /*base_rva=*/0x1000);
    EXPECT_TRUE(result.empty());
}

TEST(StringScannerEdge, SingleShortRunBelowMinIsRejected) {
    // "hi\0" — only 2 printable bytes, default min_length=6.
    std::vector<uint8_t> buf;
    push_cstr(buf, "hi");
    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);
    EXPECT_TRUE(result.empty());
}

TEST(StringScannerEdge, RunExactlyAtMinLengthAccepted) {
    // Exactly 6 chars — right at the threshold.
    std::vector<uint8_t> buf;
    push_cstr(buf, "hello!");  // 6 chars
    StringScanner scanner;     // default min_length=6
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].length, 6u);
    EXPECT_EQ(result[0].bytes, "hello!");
}

TEST(StringScannerEdge, NoNullTerminatorAtBufferEndIsRejectedInStrictMode) {
    // Strict mode: a run that runs off the end of the buffer is ambiguous
    // — we don't know whether the next byte (out of bounds) would be NUL.
    // The safe default is to drop it.
    std::vector<uint8_t> buf;
    const std::string_view s = "hello world";  // 11 chars
    buf.insert(buf.end(), s.begin(), s.end());  // NO trailing NUL

    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);
    EXPECT_TRUE(result.empty());
}

TEST(StringScannerEdge, NoNullTerminatorAcceptedInPermissiveMode) {
    std::vector<uint8_t> buf;
    const std::string_view s = "hello world";
    buf.insert(buf.end(), s.begin(), s.end());

    ScannerConfig cfg{};
    cfg.require_null_terminator = false;
    StringScanner scanner{cfg};

    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].bytes, s);
}

TEST(StringScannerEdge, InteriorGarbageInvalidatesRun) {
    // "hell\x01o\0" — the 0x01 byte is neither printable nor NUL, so the
    // run "hell" is thrown away (too short to have been emitted anyway),
    // and "o" by itself is also too short. Nothing emitted.
    std::vector<uint8_t> buf{
        'h', 'e', 'l', 'l', 0x01, 'o', 0x00
    };
    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);
    EXPECT_TRUE(result.empty());
}

TEST(StringScannerEdge, GarbageInterruptsRunButValidRunAcceptedAfter) {
    // Garbage byte kills the first run, a valid one follows.
    std::vector<uint8_t> buf{
        'a', 'b', 'c', 0xFF,
        'v', 'a', 'l', 'i', 'd', '!', 0x00,
    };
    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].bytes, "valid!");
}

// ---------------------------------------------------------------------------
// Single string
// ---------------------------------------------------------------------------

TEST(StringScannerSingle, ConstCStringFoundAtCorrectRva) {
    // Layout: 0x10 bytes of padding, then the string.
    std::vector<uint8_t> buf;
    push_pad(buf, 0x00, 0x10);
    const size_t off = push_cstr(buf, "hello, world!");

    constexpr Rva kBase = 0x20000;
    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, kBase);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].bytes, "hello, world!");
    EXPECT_EQ(result[0].length, 13u);
    EXPECT_EQ(result[0].rva_start, kBase + off);
}

// ---------------------------------------------------------------------------
// Multiple strings — "several const char* from the same TU"
// ---------------------------------------------------------------------------

TEST(StringScannerMultiple, AdjacentConstStringsAllFound) {
    // Classic MSVC .rdata layout: three string literals placed back to
    // back with a single NUL terminator between them.
    //     const char* a = "alpha";
    //     const char* b = "bravo__";
    //     const char* c = "charlie!";
    std::vector<uint8_t> buf;
    const size_t off_a = push_cstr(buf, "alpha");      // 5 chars — BELOW min
    const size_t off_b = push_cstr(buf, "bravo__");    // 7 chars
    const size_t off_c = push_cstr(buf, "charlie!");   // 8 chars
    (void)off_a;

    constexpr Rva kBase = 0x3000;
    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, kBase);

    // "alpha" is only 5 chars, default min is 6 — so we expect 2 hits.
    ASSERT_EQ(result.size(), 2u);

    const auto* b = find_by_text(result, "bravo__");
    const auto* c = find_by_text(result, "charlie!");
    ASSERT_NE(b, nullptr);
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(b->rva_start, kBase + off_b);
    EXPECT_EQ(c->rva_start, kBase + off_c);
    EXPECT_EQ(b->length, 7u);
    EXPECT_EQ(c->length, 8u);
}

TEST(StringScannerMultiple, LowerMinLengthAcceptsShorterRuns) {
    // With min_length=4 we now pick up "alpha" (5 chars) that the default
    // configuration dropped above.
    std::vector<uint8_t> buf;
    push_cstr(buf, "alpha");
    push_cstr(buf, "bravo__");

    ScannerConfig cfg{};
    cfg.min_length = 4;
    StringScanner scanner{cfg};
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);

    ASSERT_EQ(result.size(), 2u);
    EXPECT_NE(find_by_text(result, "alpha"), nullptr);
    EXPECT_NE(find_by_text(result, "bravo__"), nullptr);
}

TEST(StringScannerMultiple, MaxLengthExcludesHugeRuns) {
    // A run of 40 printable bytes, then a short valid one. With
    // max_length=20 the long run is dropped but the short one stays.
    std::vector<uint8_t> buf;
    push_cstr(buf, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");  // 40 chars
    push_cstr(buf, "valid!!");                                      // 7 chars

    ScannerConfig cfg{};
    cfg.max_length = 20;
    StringScanner scanner{cfg};
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].bytes, "valid!!");
}

// ---------------------------------------------------------------------------
// Vector of strings — pointer table + string pool
// ---------------------------------------------------------------------------

TEST(StringScannerVectorOfStrings, PointerTableIgnoredStringsFound) {
    // Simulates:
    //     static const char* kWeekdays[] = {
    //         "monday", "tuesday", "wednesday", "thursday", "friday"
    //     };
    //
    // Layout:
    //   [0x00 .. 0x28]   pointer table (5 × 8-byte pointers)
    //   [0x28 ..     ]   string pool: 5 null-terminated strings
    //
    // The pointer table contents are made up of "address-ish" bytes
    // (non-printable low bytes mixed with high bytes) so the scanner
    // won't accidentally read the pointer table as a string.
    std::vector<uint8_t> buf;

    // Pointer table — 40 bytes of garbage that looks like 8-byte
    // pointers. Contains mostly control bytes so no run is emitted
    // here even without NUL filtering.
    const uint8_t pointer_bytes[40] = {
        0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4D, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    buf.insert(buf.end(), std::begin(pointer_bytes), std::end(pointer_bytes));

    // String pool.
    const size_t off_mon = push_cstr(buf, "monday");
    const size_t off_tue = push_cstr(buf, "tuesday");
    const size_t off_wed = push_cstr(buf, "wednesday");
    const size_t off_thu = push_cstr(buf, "thursday");
    const size_t off_fri = push_cstr(buf, "friday");
    (void)off_mon; (void)off_tue; (void)off_wed; (void)off_thu; (void)off_fri;

    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, /*base=*/0);

    // All five string literals should be recognised. The pointer
    // table contributes nothing.
    ASSERT_EQ(result.size(), 5u);
    EXPECT_NE(find_by_text(result, "monday"),    nullptr);
    EXPECT_NE(find_by_text(result, "tuesday"),   nullptr);
    EXPECT_NE(find_by_text(result, "wednesday"), nullptr);
    EXPECT_NE(find_by_text(result, "thursday"),  nullptr);
    EXPECT_NE(find_by_text(result, "friday"),    nullptr);
}

TEST(StringScannerVectorOfStrings, NonConstWriteBuffersStillDiscovered) {
    // Even "non-const char buf[] = \"literal\";" style strings end up in
    // .rdata as the initialiser that the compiler memcpys from at
    // runtime. From the scanner's perspective the distinction doesn't
    // exist: it's a printable-ASCII run with a NUL terminator, so the
    // scanner picks it up. This test documents that behaviour so a
    // future change that tries to filter "writable copies" gets caught.
    std::vector<uint8_t> buf;
    push_cstr(buf, "init_data_abc");
    push_cstr(buf, "another_init_here");

    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, 0);

    ASSERT_EQ(result.size(), 2u);
    EXPECT_NE(find_by_text(result, "init_data_abc"),      nullptr);
    EXPECT_NE(find_by_text(result, "another_init_here"),  nullptr);
}

// ---------------------------------------------------------------------------
// Base RVA arithmetic
// ---------------------------------------------------------------------------

TEST(StringScannerRva, RvaStartTracksOffsetPlusBase) {
    // Place a string at a specific offset and verify the arithmetic.
    std::vector<uint8_t> buf;
    push_pad(buf, 0xCC, 0x400);     // 1 KB of padding (int3 bytes)
    const size_t off = push_cstr(buf, "needle__");

    constexpr Rva kBase = 0x10000;
    StringScanner scanner;
    auto result = scanner.scan(ByteView{buf.data(), buf.size()}, kBase);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].rva_start, kBase + static_cast<Rva>(off));
    EXPECT_EQ(result[0].rva_start, 0x10000 + static_cast<Rva>(off));
}

TEST(StringScannerRva, TwoScansWithSameDataDifferentBaseDiffer) {
    // The scanner is pure with respect to base_rva — identical input
    // scanned with two different bases should differ only in
    // rva_start, with everything else equal.
    std::vector<uint8_t> buf;
    push_cstr(buf, "shared!");

    StringScanner scanner;
    auto a = scanner.scan(ByteView{buf.data(), buf.size()}, 0x1000);
    auto b = scanner.scan(ByteView{buf.data(), buf.size()}, 0x8000);

    ASSERT_EQ(a.size(), 1u);
    ASSERT_EQ(b.size(), 1u);
    EXPECT_EQ(a[0].bytes, b[0].bytes);
    EXPECT_EQ(a[0].length, b[0].length);
    EXPECT_EQ(b[0].rva_start - a[0].rva_start, 0x8000u - 0x1000u);
}

} // namespace
