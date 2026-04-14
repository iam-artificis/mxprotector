/**
 * @file x64_inner_vm_runtime_test.cpp
 * @brief [TESTS] Byte-level stability + structural invariants for the G2
 *        inner VM runtime (`emit_inner_vm_runtime`).
 *
 * Current pinned shape: 132-byte runtime, 11 opcodes (9 core + 2
 * flag-transparent helpers `iload_src_accum` / `iret_noflag` used
 * by the `mov_rr` V2 wrapper).
 *
 * The inner VM runtime is hand-assembled byte by byte. A single wrong
 * bit in a REX prefix, ModRM byte, or jump displacement silently
 * miscompiles every outer handler that uses V2. The byte-level
 * regression test in this file captures the exact emission of every
 * byte of the current runtime so that any future edit (opcode add,
 * flag-scheme change, handler table reshuffle) either:
 *
 *   (a) intentionally breaks the expected hex blob — fine, the test
 *       fails loudly, the author updates the expected bytes and the
 *       reviewer sees the machine-code diff in the PR;
 *   (b) unintentionally breaks some byte — the test catches it
 *       immediately without a round-trip through the full
 *       protect-and-run stress pipeline.
 *
 * The structural checks (runtime size, dispatcher prefix, handler
 * table at fixed offset, entry offset == 0) additionally pin down
 * invariants the backend relies on when patching `call rel32
 * inner_vm_entry` sites.
 *
 * If you change the runtime layout intentionally, update
 * `kExpectedRuntime` below AND bump the comment at the top to the
 * new size/opcode count. Do not relax the checks — they are cheap
 * and they catch real bugs.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

namespace {

using mx::RawEmitter;
using mx::vm::x64::emit_inner_vm_runtime;
using mx::vm::x64::InnerVmOp;
using mx::vm::x64::kInnerVmRuntimeSize;

// Expected hex emission of the 132-byte runtime, as of G2-extended
// (11-opcode multi-step ISA, rcx-carrier flag scheme + flag-transparent
// iload_src_accum / iret_noflag helpers). Every byte is cross-
// referenced against the layout comment in x64_inner_vm.cpp. If this
// array needs to change, the runtime source has changed — make sure
// the change is intentional and update both in lockstep.
constexpr std::array<uint8_t, 132> kExpectedRuntime = {{
    // +0  lea r13, [rip+81]   (disp32 = handler_table - end_of_lea = 88 - 7)
    0x4C, 0x8D, 0x2D, 0x51, 0x00, 0x00, 0x00,
    // +7  .loop: movzx eax, byte [r12]
    0x41, 0x0F, 0xB6, 0x04, 0x24,
    // +12 inc r12
    0x49, 0xFF, 0xC4,
    // +15 mov eax, [r13 + rax*4 + 0]
    0x41, 0x8B, 0x44, 0x85, 0x00,
    // +20 movsxd rax, eax
    0x48, 0x63, 0xC0,
    // +23 add rax, r13
    0x4C, 0x01, 0xE8,
    // +26 jmp rax
    0xFF, 0xE0,

    // +28 H_iload_src:  mov r15, [rdi]; jmp .loop  (rel8 = 7 - 33 = -26)
    0x4C, 0x8B, 0x3F, 0xEB, 0xE6,
    // +33 H_iload_dst:  mov r14, [rsi]; jmp .loop  (rel8 = 7 - 38 = -31)
    0x4C, 0x8B, 0x36, 0xEB, 0xE1,
    // +38 H_istore_dst: mov [rsi], r14; jmp .loop  (rel8 = 7 - 43 = -36)
    0x4C, 0x89, 0x36, 0xEB, 0xDC,

    // +43 H_iadd_rr: add r14,r15; pushfq; pop rcx; jmp .loop (rel8 = 7 - 50 = -43)
    0x4D, 0x01, 0xFE, 0x9C, 0x59, 0xEB, 0xD5,
    // +50 H_isub_rr: sub r14,r15; ...; jmp .loop (rel8 = 7 - 57 = -50)
    0x4D, 0x29, 0xFE, 0x9C, 0x59, 0xEB, 0xCE,
    // +57 H_ixor_rr: xor r14,r15; ...; jmp .loop (rel8 = 7 - 64 = -57)
    0x4D, 0x31, 0xFE, 0x9C, 0x59, 0xEB, 0xC7,
    // +64 H_iand_rr: and r14,r15; ...; jmp .loop (rel8 = 7 - 71 = -64)
    0x4D, 0x21, 0xFE, 0x9C, 0x59, 0xEB, 0xC0,
    // +71 H_ior_rr: or r14,r15; ...; jmp .loop (rel8 = 7 - 78 = -71)
    0x4D, 0x09, 0xFE, 0x9C, 0x59, 0xEB, 0xB9,

    // +78 H_iret: push rcx; popfq; ret
    0x51, 0x9D, 0xC3,

    // +81 H_iload_src_accum: mov r14, [rdi]; jmp .loop (rel8 = 7 - 86 = -79)
    0x4C, 0x8B, 0x37, 0xEB, 0xB1,

    // +86 H_iret_noflag: ret
    0xC3,

    // +87 padding (1 × 0xCC)
    0xCC,

    // +88 handler table: 11 × int32 signed offsets from table base
    //   iload_src       (+28 - +88) = -60  = 0xFFFFFFC4
    0xC4, 0xFF, 0xFF, 0xFF,
    //   iload_dst       (+33 - +88) = -55  = 0xFFFFFFC9
    0xC9, 0xFF, 0xFF, 0xFF,
    //   istore_dst      (+38 - +88) = -50  = 0xFFFFFFCE
    0xCE, 0xFF, 0xFF, 0xFF,
    //   iadd_rr         (+43 - +88) = -45  = 0xFFFFFFD3
    0xD3, 0xFF, 0xFF, 0xFF,
    //   isub_rr         (+50 - +88) = -38  = 0xFFFFFFDA
    0xDA, 0xFF, 0xFF, 0xFF,
    //   ixor_rr         (+57 - +88) = -31  = 0xFFFFFFE1
    0xE1, 0xFF, 0xFF, 0xFF,
    //   iand_rr         (+64 - +88) = -24  = 0xFFFFFFE8
    0xE8, 0xFF, 0xFF, 0xFF,
    //   ior_rr          (+71 - +88) = -17  = 0xFFFFFFEF
    0xEF, 0xFF, 0xFF, 0xFF,
    //   iret            (+78 - +88) = -10  = 0xFFFFFFF6
    0xF6, 0xFF, 0xFF, 0xFF,
    //   iload_src_accum (+81 - +88) = -7   = 0xFFFFFFF9
    0xF9, 0xFF, 0xFF, 0xFF,
    //   iret_noflag     (+86 - +88) = -2   = 0xFFFFFFFE
    0xFE, 0xFF, 0xFF, 0xFF,
}};

static_assert(kExpectedRuntime.size() == kInnerVmRuntimeSize,
              "expected runtime size must match public kInnerVmRuntimeSize");

// ---------------------------------------------------------------------------
// Structural invariants
// ---------------------------------------------------------------------------

TEST(X64InnerVmRuntime, EmitsExactlyKInnerVmRuntimeSize) {
    RawEmitter e;
    const size_t entry = emit_inner_vm_runtime(e);

    EXPECT_EQ(entry, 0u)
        << "dispatcher entry must be at the very start of the emitted blob";
    EXPECT_EQ(e.size(), kInnerVmRuntimeSize)
        << "runtime size drifted from kInnerVmRuntimeSize; update the header "
           "constant AND the expected-bytes array in this test together";
}

TEST(X64InnerVmRuntime, DispatcherPrologueIsLeaR13RipPlus81) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e);
    ASSERT_GE(e.size(), 7u);

    // lea r13, [rip + 81]
    //   REX.W|R (0x4C) + 0x8D + ModRM(00 101 101 = 0x2D, rip-rel) + disp32=81
    EXPECT_EQ(e.buf[0], 0x4C);
    EXPECT_EQ(e.buf[1], 0x8D);
    EXPECT_EQ(e.buf[2], 0x2D);
    const int32_t disp32 =
        static_cast<int32_t>(static_cast<uint32_t>(e.buf[3])      |
                             (static_cast<uint32_t>(e.buf[4]) << 8) |
                             (static_cast<uint32_t>(e.buf[5]) << 16)|
                             (static_cast<uint32_t>(e.buf[6]) << 24));
    EXPECT_EQ(disp32, 81)
        << "handler table sits at +88; disp32 = 88 - end_of_lea(7) = 81. "
           "If you moved the table, update this expectation.";
}

TEST(X64InnerVmRuntime, DispatcherEndsWithJmpRax) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e);
    ASSERT_GE(e.size(), 28u);

    // Dispatcher ends at +28, last two bytes at +26..+27 = FF E0 (jmp rax).
    EXPECT_EQ(e.buf[26], 0xFF);
    EXPECT_EQ(e.buf[27], 0xE0);
}

TEST(X64InnerVmRuntime, IretHandlerIsPushRcxPopfqRet) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e);
    ASSERT_GE(e.size(), 81u);

    // iret lives at +78 and is exactly 3 bytes: push rcx (51), popfq (9D), ret (C3).
    EXPECT_EQ(e.buf[78], 0x51);
    EXPECT_EQ(e.buf[79], 0x9D);
    EXPECT_EQ(e.buf[80], 0xC3);
}

TEST(X64InnerVmRuntime, HandlerTableHoldsElevenInt32Entries) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e);
    ASSERT_EQ(e.size(), kInnerVmRuntimeSize);

    // Table at +88, 11 × int32 = 44 bytes, ends at +132 (end of block).
    constexpr size_t table_off = 88;
    auto read_i32 = [&](size_t at) {
        return static_cast<int32_t>(
            static_cast<uint32_t>(e.buf[at])          |
            (static_cast<uint32_t>(e.buf[at + 1]) << 8)  |
            (static_cast<uint32_t>(e.buf[at + 2]) << 16) |
            (static_cast<uint32_t>(e.buf[at + 3]) << 24));
    };

    // Each entry is (handler_offset - table_offset), signed.
    EXPECT_EQ(read_i32(table_off +  0), 28 - 88);  // iload_src
    EXPECT_EQ(read_i32(table_off +  4), 33 - 88);  // iload_dst
    EXPECT_EQ(read_i32(table_off +  8), 38 - 88);  // istore_dst
    EXPECT_EQ(read_i32(table_off + 12), 43 - 88);  // iadd_rr
    EXPECT_EQ(read_i32(table_off + 16), 50 - 88);  // isub_rr
    EXPECT_EQ(read_i32(table_off + 20), 57 - 88);  // ixor_rr
    EXPECT_EQ(read_i32(table_off + 24), 64 - 88);  // iand_rr
    EXPECT_EQ(read_i32(table_off + 28), 71 - 88);  // ior_rr
    EXPECT_EQ(read_i32(table_off + 32), 78 - 88);  // iret
    EXPECT_EQ(read_i32(table_off + 36), 81 - 88);  // iload_src_accum
    EXPECT_EQ(read_i32(table_off + 40), 86 - 88);  // iret_noflag
}

TEST(X64InnerVmRuntime, OpcodeEnumIndexesHandlerTableCorrectly) {
    // The backend uses `static_cast<uint8_t>(InnerVmOp::xxx)` as an index
    // into the handler table. This test pins the enum values so a future
    // reorder (e.g. alphabetising) can't silently mis-index.
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iload_src),       0x00);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iload_dst),       0x01);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::istore_dst),      0x02);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iadd_rr),         0x03);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::isub_rr),         0x04);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::ixor_rr),         0x05);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iand_rr),         0x06);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::ior_rr),          0x07);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iret),            0x08);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iload_src_accum), 0x09);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::iret_noflag),     0x0A);
}

TEST(X64InnerVmRuntime, IretNoFlagHandlerIsBareRet) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e);
    ASSERT_GE(e.size(), 87u);

    // iret_noflag at +86 is exactly one byte: `ret` (0xC3). No push,
    // no popfq — guarantees flag-transparency for mov_rr lifts.
    EXPECT_EQ(e.buf[86], 0xC3);
}

// ---------------------------------------------------------------------------
// Byte-for-byte stability
// ---------------------------------------------------------------------------

TEST(X64InnerVmRuntime, ByteForByteMatchesExpectedBlob) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e);
    ASSERT_EQ(e.size(), kExpectedRuntime.size());

    for (size_t i = 0; i < kExpectedRuntime.size(); ++i) {
        EXPECT_EQ(e.buf[i], kExpectedRuntime[i])
            << "runtime byte @+" << i << " diverged from expected; "
            << "if intentional, update kExpectedRuntime";
    }
}

TEST(X64InnerVmRuntime, EmissionIsDeterministic) {
    // Two independent calls must produce identical byte sequences. The
    // emitter has no hidden state or randomness today, but future
    // per-build inner-ISA randomization hooks will change that — this
    // test then needs to take a seed and pin the shape for a fixed seed.
    RawEmitter a, b;
    (void)emit_inner_vm_runtime(a);
    (void)emit_inner_vm_runtime(b);
    ASSERT_EQ(a.size(), b.size());
    EXPECT_EQ(a.buf, b.buf);
}

} // namespace
