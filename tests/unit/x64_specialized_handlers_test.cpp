/**
 * @file x64_specialized_handlers_test.cpp
 * @brief [TESTS] Unit tests for G1 specialised handler emitters.
 *
 * The specialised handlers are the body of the G1 "virtual CPU"
 * extension: per-build, the X64 backend picks K random
 * (op, dst_vreg, src_vreg) tuples and emits a dedicated handler with
 * the slot disps hard-coded. Bytecode for matching instructions then
 * carries only the handler_id (1 byte) instead of the generic
 * `handler_id + dst_byte + src_byte` (3 bytes), making the bytecode
 * variable-length per instruction.
 *
 * These tests verify the byte-level encoding of those specialised
 * bodies in isolation. The end-to-end stress build verifies they
 * actually decode correctly at runtime.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/vm/x64/x64_handlers.hpp"

namespace {

using mx::RawEmitter;
using mx::vm::x64::emit_handler_alu_rr_specialized;
using mx::vm::x64::emit_handler_mov_rr_specialized;

// ---------------------------------------------------------------------------
// mov_rr specialised
// ---------------------------------------------------------------------------

TEST(X64SpecializedHandlers, MovRrEmitsTenBytes) {
    RawEmitter e;
    emit_handler_mov_rr_specialized(e, /*dst_disp=*/24, /*src_disp=*/56);
    EXPECT_EQ(e.size(), 10u);
}

TEST(X64SpecializedHandlers, MovRrCorrectOpcodes) {
    RawEmitter e;
    emit_handler_mov_rr_specialized(e, /*dst_disp=*/24, /*src_disp=*/56);
    ASSERT_EQ(e.size(), 10u);

    // mov rax, [rsp + 56]    48 8B 44 24 38
    EXPECT_EQ(e.buf[0], 0x48);  // REX.W
    EXPECT_EQ(e.buf[1], 0x8B);  // MOV r64, r/m64
    EXPECT_EQ(e.buf[2], 0x44);  // ModRM: mod=01, reg=000(rax), rm=100(SIB)
    EXPECT_EQ(e.buf[3], 0x24);  // SIB:   scale=00, index=100(none), base=100(rsp)
    EXPECT_EQ(e.buf[4], 56);    // disp8 (src)

    // mov [rsp + 24], rax    48 89 44 24 18
    EXPECT_EQ(e.buf[5], 0x48);
    EXPECT_EQ(e.buf[6], 0x89);  // MOV r/m64, r64
    EXPECT_EQ(e.buf[7], 0x44);
    EXPECT_EQ(e.buf[8], 0x24);
    EXPECT_EQ(e.buf[9], 24);    // disp8 (dst)
}

TEST(X64SpecializedHandlers, MovRrDispsThreadedThrough) {
    // Cover every legal slot disp (0, 8, ..., 120) for both operands.
    for (uint8_t dst = 0; dst <= 120; dst += 8) {
        for (uint8_t src = 0; src <= 120; src += 8) {
            RawEmitter e;
            emit_handler_mov_rr_specialized(e, dst, src);
            ASSERT_EQ(e.size(), 10u) << "dst=" << int{dst} << " src=" << int{src};
            EXPECT_EQ(e.buf[4], src);
            EXPECT_EQ(e.buf[9], dst);
        }
    }
}

// ---------------------------------------------------------------------------
// alu_rr specialised
// ---------------------------------------------------------------------------

TEST(X64SpecializedHandlers, AluRrEmitsTenBytes) {
    RawEmitter e;
    emit_handler_alu_rr_specialized(e, /*op_mr=*/0x01, 24, 56);
    EXPECT_EQ(e.size(), 10u);
}

TEST(X64SpecializedHandlers, AluRrCarriesOpMrByte) {
    // For each documented r-r ALU op opcode, verify the second
    // instruction's opcode byte at offset 6 matches.
    constexpr struct { uint8_t op_mr; const char* name; } cases[] = {
        {0x01, "add"},
        {0x29, "sub"},
        {0x31, "xor"},
        {0x21, "and"},
        {0x09, "or"},
    };
    for (const auto& c : cases) {
        RawEmitter e;
        emit_handler_alu_rr_specialized(e, c.op_mr, /*dst=*/16, /*src=*/40);
        ASSERT_EQ(e.size(), 10u) << c.name;
        SCOPED_TRACE(c.name);

        // First insn: mov rax, [rsp + 40]
        EXPECT_EQ(e.buf[0], 0x48);
        EXPECT_EQ(e.buf[1], 0x8B);
        EXPECT_EQ(e.buf[2], 0x44);
        EXPECT_EQ(e.buf[3], 0x24);
        EXPECT_EQ(e.buf[4], 40);

        // Second insn: OP [rsp + 16], rax
        EXPECT_EQ(e.buf[5], 0x48);
        EXPECT_EQ(e.buf[6], c.op_mr);
        EXPECT_EQ(e.buf[7], 0x44);
        EXPECT_EQ(e.buf[8], 0x24);
        EXPECT_EQ(e.buf[9], 16);
    }
}

TEST(X64SpecializedHandlers, AluRrDispsThreadedThrough) {
    for (uint8_t dst = 0; dst <= 120; dst += 8) {
        for (uint8_t src = 0; src <= 120; src += 8) {
            RawEmitter e;
            emit_handler_alu_rr_specialized(e, 0x01, dst, src);
            ASSERT_EQ(e.size(), 10u);
            EXPECT_EQ(e.buf[4], src);
            EXPECT_EQ(e.buf[9], dst);
        }
    }
}

TEST(X64SpecializedHandlers, NoSharedBytePatternBetweenMovAndAlu) {
    // Specialised mov_rr and specialised add_rr share the same shape
    // *except* for the opcode byte at offset 6 (0x89 vs 0x01). The
    // whole point of specialisation is that each variant looks
    // distinct from the others — verify the byte at offset 6 differs.
    RawEmitter mov_e;
    RawEmitter add_e;
    emit_handler_mov_rr_specialized(mov_e, 24, 56);
    emit_handler_alu_rr_specialized(add_e, 0x01, 24, 56);
    ASSERT_EQ(mov_e.size(), 10u);
    ASSERT_EQ(add_e.size(), 10u);
    EXPECT_EQ(mov_e.buf[6], 0x89);  // MOV r/m64, r64
    EXPECT_EQ(add_e.buf[6], 0x01);  // ADD r/m64, r64
    EXPECT_NE(mov_e.buf[6], add_e.buf[6]);
}

} // namespace
