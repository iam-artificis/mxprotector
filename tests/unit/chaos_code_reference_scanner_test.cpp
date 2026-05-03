/**
 * @file chaos_code_reference_scanner_test.cpp
 * @brief [TESTS] B.4.2 — `CodeReferenceScanner` contract.
 *
 * Pins the four invariants the chaos pipeline depends on:
 *
 *   1. `CALL rel32` produces one `code_branch_or_call` reference at
 *      the rel32 slot (1 byte after opcode), with target RVA equal
 *      to the absolute branch target.
 *   2. `JMP rel8` produces one `byte1` reference.
 *   3. `MOV rax, [rip+disp32]` produces one `code_rip_relative`
 *      reference at the disp32 slot, target = next_inst + disp32.
 *   4. Decoder errors are tolerated — a single bad byte does not
 *      stop the scan; subsequent valid instructions are still
 *      emitted.
 */

#include <gtest/gtest.h>

#include <vector>

#include "mxprotector/pe/chaos/code_reference_scanner.hpp"
#include "mxprotector/pe/chaos/reference.hpp"

namespace {

using mx::Rva;
using mx::pe::chaos::CodeReferenceScanner;
using mx::pe::chaos::Reference;
using mx::pe::chaos::ReferenceEncoding;
using mx::pe::chaos::ReferenceOrigin;
using mx::pe::chaos::ReferenceTable;
using mx::pe::chaos::ReferenceWidth;

[[nodiscard]] std::vector<std::uint8_t> bytes(
    std::initializer_list<std::uint8_t> v)
{
    return std::vector<std::uint8_t>{v};
}

// ---------------------------------------------------------------------------
// Branch immediates
// ---------------------------------------------------------------------------

TEST(CodeReferenceScanner, CallRel32EmitsOneRel4Reference) {
    // CALL 0x2000 from RVA 0x1000 → rel32 = 0x2000 - 0x1005 = 0xFFB.
    // Bytes: E8 FB 0F 00 00 (5 bytes).
    const auto code = bytes({0xE8, 0xFB, 0x0F, 0x00, 0x00});

    CodeReferenceScanner s;
    ReferenceTable t;
    auto errors = s.scan(
        mx::ByteView{code.data(), code.size()},
        /*base_rva=*/0x1000,
        t);
    EXPECT_EQ(errors, 0u);
    ASSERT_EQ(t.size(), 1u);

    const auto& r = t.slots()[0];
    EXPECT_EQ(r.location_rva, 0x1001u);
    EXPECT_EQ(r.target_rva,   0x2000u);
    EXPECT_EQ(r.width,        ReferenceWidth::byte4);
    EXPECT_EQ(r.encoding,     ReferenceEncoding::rel);
    EXPECT_EQ(r.origin,       ReferenceOrigin::code_branch_or_call);
}

TEST(CodeReferenceScanner, JmpRel8EmitsOneByte1Reference) {
    // JMP 0x1010 from RVA 0x1000 → rel8 = 0x1010 - 0x1002 = 0x0E.
    // Bytes: EB 0E (2 bytes).
    const auto code = bytes({0xEB, 0x0E});

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    ASSERT_EQ(t.size(), 1u);

    const auto& r = t.slots()[0];
    EXPECT_EQ(r.location_rva, 0x1001u);
    EXPECT_EQ(r.target_rva,   0x1010u);
    EXPECT_EQ(r.width,        ReferenceWidth::byte1);
    EXPECT_EQ(r.encoding,     ReferenceEncoding::rel);
    EXPECT_EQ(r.origin,       ReferenceOrigin::code_branch_or_call);
}

TEST(CodeReferenceScanner, JeRel32EmitsOneByte4Reference) {
    // JE 0x2000 from RVA 0x1000 → rel32 = 0x2000 - 0x1006 = 0xFFA.
    // Bytes: 0F 84 FA 0F 00 00 (6 bytes).
    const auto code = bytes({0x0F, 0x84, 0xFA, 0x0F, 0x00, 0x00});

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    ASSERT_EQ(t.size(), 1u);

    const auto& r = t.slots()[0];
    EXPECT_EQ(r.location_rva, 0x1002u) << "rel32 starts at byte 2";
    EXPECT_EQ(r.target_rva,   0x2000u);
    EXPECT_EQ(r.width,        ReferenceWidth::byte4);
}

// ---------------------------------------------------------------------------
// RIP-relative memory
// ---------------------------------------------------------------------------

TEST(CodeReferenceScanner, MovRipRelativeEmitsOneRipReference) {
    // MOV rax, [rip + 0x100] from RVA 0x1000.
    // Bytes: 48 8B 05 00 01 00 00 (7 bytes).
    // disp32 starts at byte 3; target = 0x1007 + 0x100 = 0x1107.
    const auto code = bytes({0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00});

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    ASSERT_EQ(t.size(), 1u);

    const auto& r = t.slots()[0];
    EXPECT_EQ(r.location_rva, 0x1003u);
    EXPECT_EQ(r.target_rva,   0x1107u);
    EXPECT_EQ(r.width,        ReferenceWidth::byte4);
    EXPECT_EQ(r.encoding,     ReferenceEncoding::rel);
    EXPECT_EQ(r.origin,       ReferenceOrigin::code_rip_relative);
}

TEST(CodeReferenceScanner, LeaRipRelativeEmitsOneRipReference) {
    // LEA rax, [rip + 0x40] from RVA 0x1000.
    // Bytes: 48 8D 05 40 00 00 00 (7 bytes).
    // target = 0x1007 + 0x40 = 0x1047.
    const auto code = bytes({0x48, 0x8D, 0x05, 0x40, 0x00, 0x00, 0x00});

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.slots()[0].target_rva, 0x1047u);
    EXPECT_EQ(t.slots()[0].origin, ReferenceOrigin::code_rip_relative);
}

// ---------------------------------------------------------------------------
// Mixed and edge cases
// ---------------------------------------------------------------------------

TEST(CodeReferenceScanner, MultipleInstructionsEmitMultipleReferences) {
    // CALL 0x2000 (5 bytes) at 0x1000 + JMP 0x1010 (2 bytes) at 0x1005.
    // Wait — JMP 0x1010 from 0x1005: rel8 = 0x1010 - 0x1007 = 9 → bytes EB 09.
    const auto code = bytes({
        0xE8, 0xFB, 0x0F, 0x00, 0x00,  // CALL 0x2000
        0xEB, 0x09,                     // JMP 0x1010
    });

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t.slots()[0].target_rva, 0x2000u);
    EXPECT_EQ(t.slots()[1].target_rva, 0x1010u);
}

TEST(CodeReferenceScanner, NonRelativeInstructionsEmitNothing) {
    // MOV rax, rcx (no immediate, no memory): 48 89 C8.
    // PUSH rax: 50.
    // RET: C3.
    const auto code = bytes({0x48, 0x89, 0xC8, 0x50, 0xC3});

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    EXPECT_EQ(t.size(), 0u);
}

TEST(CodeReferenceScanner, AbsoluteImmediateMovDoesNotEmitReference) {
    // MOV rax, 0x12345678 (uses imm32, NOT relative): 48 C7 C0 78 56 34 12.
    const auto code = bytes({0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12});

    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{code.data(), code.size()}, 0x1000, t), 0u);
    EXPECT_EQ(t.size(), 0u) << "non-relative immediate must not emit a reference";
}

TEST(CodeReferenceScanner, BadByteIsSkippedAndScanContinues) {
    // 0xFF 0xFF is not a complete instruction by itself (incomplete
    // ModR/M); decoder fails. Following bytes form a valid CALL.
    // Pad with another bad byte at the start, then CALL.
    const auto code = bytes({
        0x06,                          // POP es — invalid in 64-bit mode
        0xE8, 0xFB, 0x0F, 0x00, 0x00,  // CALL 0x2000 from RVA 0x1001
    });
    // CALL at offset 1, base 0x1000 → RVA 0x1001. Length 5 → next 0x1006.
    // disp = 0xFFB → target = 0x1006 + 0xFFB = 0x2001.

    CodeReferenceScanner s;
    ReferenceTable t;
    auto errors = s.scan(
        mx::ByteView{code.data(), code.size()}, 0x1000, t);
    EXPECT_EQ(errors, 1u);
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.slots()[0].location_rva, 0x1002u);
    EXPECT_EQ(t.slots()[0].target_rva,   0x2001u);
}

TEST(CodeReferenceScanner, EmptyBufferEmitsNothing) {
    CodeReferenceScanner s;
    ReferenceTable t;
    EXPECT_EQ(s.scan(mx::ByteView{}, 0x1000, t), 0u);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
