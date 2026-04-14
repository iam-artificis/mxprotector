/**
 * @file x64_inner_vm_runtime_test.cpp
 * @brief [TESTS] Byte-level stability + structural invariants for the G2
 *        inner VM runtime (`emit_inner_vm_runtime`).
 *
 * Current pinned shape: 160-byte runtime, 14 opcodes (9 r-r ALU
 * core + 2 helpers for mov_rr: `iload_src_accum` / `iret_noflag` +
 * 2 unary: `inot_r14` / `ineg_r14` + 1 vjcc taken: `itake_branch`).
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
#include <set>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

namespace {

using mx::RawEmitter;
using mx::Randomizer;
using mx::vm::x64::emit_inner_vm_runtime;
using mx::vm::x64::InnerVmIsa;
using mx::vm::x64::InnerVmOp;
using mx::vm::x64::kInnerVmOpCount;
using mx::vm::x64::kInnerVmRuntimeSize;
using mx::vm::x64::make_identity_inner_vm_isa;
using mx::vm::x64::make_random_inner_vm_isa;

// All tests below emit under the identity ISA by default — that's
// the shape pinned in `kExpectedRuntime`. Randomization is exercised
// by the X64InnerVmIsa test suite at the bottom of this file.
const InnerVmIsa kIdentityIsa = make_identity_inner_vm_isa();

// Expected hex emission of the 160-byte runtime, as of G2-extended
// with vjcc V2 (itake_branch added). 14-opcode multi-step ISA.
// Every byte is cross-referenced against the layout comment in
// x64_inner_vm.cpp. If this array needs to change, the runtime
// source has changed — make sure the change is intentional and
// update both in lockstep.
constexpr std::array<uint8_t, 160> kExpectedRuntime = {{
    // +0  lea r13, [rip+97]   (disp32 = handler_table - end_of_lea = 104 - 7)
    0x4C, 0x8D, 0x2D, 0x61, 0x00, 0x00, 0x00,
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

    // +87 H_inot_r14: not r14; jmp .loop (rel8 = 7 - 92 = -85)
    0x49, 0xF7, 0xD6, 0xEB, 0xAB,

    // +92 H_ineg_r14: neg r14; pushfq; pop rcx; jmp .loop (rel8 = 7 - 99 = -92)
    0x49, 0xF7, 0xDE, 0x9C, 0x59, 0xEB, 0xA4,

    // +99 H_itake_branch: add r11, r15; jmp .loop (rel8 = 7 - 104 = -97)
    0x4D, 0x01, 0xFB, 0xEB, 0x9F,

    // +104 handler table: 14 × int32 signed offsets from table base
    //   iload_src       (+28 - +104) = -76  = 0xFFFFFFB4
    0xB4, 0xFF, 0xFF, 0xFF,
    //   iload_dst       (+33 - +104) = -71  = 0xFFFFFFB9
    0xB9, 0xFF, 0xFF, 0xFF,
    //   istore_dst      (+38 - +104) = -66  = 0xFFFFFFBE
    0xBE, 0xFF, 0xFF, 0xFF,
    //   iadd_rr         (+43 - +104) = -61  = 0xFFFFFFC3
    0xC3, 0xFF, 0xFF, 0xFF,
    //   isub_rr         (+50 - +104) = -54  = 0xFFFFFFCA
    0xCA, 0xFF, 0xFF, 0xFF,
    //   ixor_rr         (+57 - +104) = -47  = 0xFFFFFFD1
    0xD1, 0xFF, 0xFF, 0xFF,
    //   iand_rr         (+64 - +104) = -40  = 0xFFFFFFD8
    0xD8, 0xFF, 0xFF, 0xFF,
    //   ior_rr          (+71 - +104) = -33  = 0xFFFFFFDF
    0xDF, 0xFF, 0xFF, 0xFF,
    //   iret            (+78 - +104) = -26  = 0xFFFFFFE6
    0xE6, 0xFF, 0xFF, 0xFF,
    //   iload_src_accum (+81 - +104) = -23  = 0xFFFFFFE9
    0xE9, 0xFF, 0xFF, 0xFF,
    //   iret_noflag     (+86 - +104) = -18  = 0xFFFFFFEE
    0xEE, 0xFF, 0xFF, 0xFF,
    //   inot_r14        (+87 - +104) = -17  = 0xFFFFFFEF
    0xEF, 0xFF, 0xFF, 0xFF,
    //   ineg_r14        (+92 - +104) = -12  = 0xFFFFFFF4
    0xF4, 0xFF, 0xFF, 0xFF,
    //   itake_branch    (+99 - +104) = -5   = 0xFFFFFFFB
    0xFB, 0xFF, 0xFF, 0xFF,
}};

static_assert(kExpectedRuntime.size() == kInnerVmRuntimeSize,
              "expected runtime size must match public kInnerVmRuntimeSize");

// ---------------------------------------------------------------------------
// Structural invariants
// ---------------------------------------------------------------------------

TEST(X64InnerVmRuntime, EmitsExactlyKInnerVmRuntimeSize) {
    RawEmitter e;
    const size_t entry = emit_inner_vm_runtime(e, kIdentityIsa);

    EXPECT_EQ(entry, 0u)
        << "dispatcher entry must be at the very start of the emitted blob";
    EXPECT_EQ(e.size(), kInnerVmRuntimeSize)
        << "runtime size drifted from kInnerVmRuntimeSize; update the header "
           "constant AND the expected-bytes array in this test together";
}

TEST(X64InnerVmRuntime, DispatcherPrologueIsLeaR13RipPlus97) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 7u);

    // lea r13, [rip + 97]
    //   REX.W|R (0x4C) + 0x8D + ModRM(00 101 101 = 0x2D, rip-rel) + disp32=97
    EXPECT_EQ(e.buf[0], 0x4C);
    EXPECT_EQ(e.buf[1], 0x8D);
    EXPECT_EQ(e.buf[2], 0x2D);
    const int32_t disp32 =
        static_cast<int32_t>(static_cast<uint32_t>(e.buf[3])      |
                             (static_cast<uint32_t>(e.buf[4]) << 8) |
                             (static_cast<uint32_t>(e.buf[5]) << 16)|
                             (static_cast<uint32_t>(e.buf[6]) << 24));
    EXPECT_EQ(disp32, 97)
        << "handler table sits at +104; disp32 = 104 - end_of_lea(7) = 97. "
           "If you moved the table, update this expectation.";
}

TEST(X64InnerVmRuntime, DispatcherEndsWithJmpRax) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 28u);

    // Dispatcher ends at +28, last two bytes at +26..+27 = FF E0 (jmp rax).
    EXPECT_EQ(e.buf[26], 0xFF);
    EXPECT_EQ(e.buf[27], 0xE0);
}

TEST(X64InnerVmRuntime, IretHandlerIsPushRcxPopfqRet) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 81u);

    // iret lives at +78 and is exactly 3 bytes: push rcx (51), popfq (9D), ret (C3).
    EXPECT_EQ(e.buf[78], 0x51);
    EXPECT_EQ(e.buf[79], 0x9D);
    EXPECT_EQ(e.buf[80], 0xC3);
}

TEST(X64InnerVmRuntime, HandlerTableHoldsFourteenInt32Entries) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_EQ(e.size(), kInnerVmRuntimeSize);

    // Table at +104, 14 × int32 = 56 bytes, ends at +160 (end of block).
    constexpr size_t table_off = 104;
    auto read_i32 = [&](size_t at) {
        return static_cast<int32_t>(
            static_cast<uint32_t>(e.buf[at])          |
            (static_cast<uint32_t>(e.buf[at + 1]) << 8)  |
            (static_cast<uint32_t>(e.buf[at + 2]) << 16) |
            (static_cast<uint32_t>(e.buf[at + 3]) << 24));
    };

    // Each entry is (handler_offset - table_offset), signed.
    EXPECT_EQ(read_i32(table_off +  0), 28 - 104);  // iload_src
    EXPECT_EQ(read_i32(table_off +  4), 33 - 104);  // iload_dst
    EXPECT_EQ(read_i32(table_off +  8), 38 - 104);  // istore_dst
    EXPECT_EQ(read_i32(table_off + 12), 43 - 104);  // iadd_rr
    EXPECT_EQ(read_i32(table_off + 16), 50 - 104);  // isub_rr
    EXPECT_EQ(read_i32(table_off + 20), 57 - 104);  // ixor_rr
    EXPECT_EQ(read_i32(table_off + 24), 64 - 104);  // iand_rr
    EXPECT_EQ(read_i32(table_off + 28), 71 - 104);  // ior_rr
    EXPECT_EQ(read_i32(table_off + 32), 78 - 104);  // iret
    EXPECT_EQ(read_i32(table_off + 36), 81 - 104);  // iload_src_accum
    EXPECT_EQ(read_i32(table_off + 40), 86 - 104);  // iret_noflag
    EXPECT_EQ(read_i32(table_off + 44), 87 - 104);  // inot_r14
    EXPECT_EQ(read_i32(table_off + 48), 92 - 104);  // ineg_r14
    EXPECT_EQ(read_i32(table_off + 52), 99 - 104);  // itake_branch
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
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::inot_r14),        0x0B);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::ineg_r14),        0x0C);
    EXPECT_EQ(static_cast<uint8_t>(InnerVmOp::itake_branch),    0x0D);
}

TEST(X64InnerVmRuntime, ItakeBranchHandlerIsAddR11R15JmpLoop) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 104u);

    // itake_branch at +99: `add r11, r15` = 4D 01 FB, then `jmp
    // rel8` back to .loop. Used by vjcc V2's taken path to advance
    // the outer VPC (r11) by the pre-loaded rel32 (r15). If this
    // handler stops advancing r11 or accidentally touches r14 or
    // rcx, every nested vjcc in every build goes to a wrong target.
    EXPECT_EQ(e.buf[99],  0x4D);  // REX.W|R|B
    EXPECT_EQ(e.buf[100], 0x01);  // add r/m64, r64 opcode
    EXPECT_EQ(e.buf[101], 0xFB);  // ModRM: reg=r15, rm=r11
    EXPECT_EQ(e.buf[102], 0xEB);  // jmp rel8 back to .loop
}

TEST(X64InnerVmRuntime, IretNoFlagHandlerIsBareRet) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 87u);

    // iret_noflag at +86 is exactly one byte: `ret` (0xC3). No push,
    // no popfq — guarantees flag-transparency for mov_rr / not_r lifts.
    EXPECT_EQ(e.buf[86], 0xC3);
}

TEST(X64InnerVmRuntime, InotR14DoesNotSaveFlags) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 92u);

    // inot_r14 at +87: `not r14` = 49 F7 D6, then `jmp rel8`. No
    // pushfq/pop rcx between the ALU and the jmp — `not` is
    // flag-transparent on x86, so this handler intentionally
    // doesn't touch rcx. If someone adds flag-save here, the
    // next `not_r` V2 would write junk to rcx and downstream
    // vjcc might read corrupted vflags.
    EXPECT_EQ(e.buf[87], 0x49);  // REX.W|B
    EXPECT_EQ(e.buf[88], 0xF7);  // opcode
    EXPECT_EQ(e.buf[89], 0xD6);  // ModRM /2 = not, rm=r14
    EXPECT_EQ(e.buf[90], 0xEB);  // jmp rel8 immediately after
}

TEST(X64InnerVmRuntime, InegR14SavesFlagsToRcx) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_GE(e.size(), 99u);

    // ineg_r14 at +92: `neg r14` = 49 F7 DE, then pushfq/pop rcx,
    // then `jmp rel8`. `neg` IS flag-producing on x86 (CF, SF, ZF,
    // OF, PF), so this handler MUST stash the fresh flags in rcx.
    // If someone accidentally drops the pushfq/pop pair, vjcc
    // after `neg_r` V2 will see the dispatcher's add-rax-r13
    // flags instead of the guest neg's flags.
    EXPECT_EQ(e.buf[92], 0x49);  // REX.W|B
    EXPECT_EQ(e.buf[93], 0xF7);  // opcode
    EXPECT_EQ(e.buf[94], 0xDE);  // ModRM /3 = neg, rm=r14
    EXPECT_EQ(e.buf[95], 0x9C);  // pushfq
    EXPECT_EQ(e.buf[96], 0x59);  // pop rcx
    EXPECT_EQ(e.buf[97], 0xEB);  // jmp rel8
}

// ---------------------------------------------------------------------------
// Byte-for-byte stability
// ---------------------------------------------------------------------------

TEST(X64InnerVmRuntime, ByteForByteMatchesExpectedBlob) {
    RawEmitter e;
    (void)emit_inner_vm_runtime(e, kIdentityIsa);
    ASSERT_EQ(e.size(), kExpectedRuntime.size());

    for (size_t i = 0; i < kExpectedRuntime.size(); ++i) {
        EXPECT_EQ(e.buf[i], kExpectedRuntime[i])
            << "runtime byte @+" << i << " diverged from expected; "
            << "if intentional, update kExpectedRuntime";
    }
}

TEST(X64InnerVmRuntime, EmissionIsDeterministicUnderIdentityIsa) {
    // Two independent calls with the identity ISA must produce
    // identical byte sequences — the emitter itself has no hidden
    // state. Randomization-driven divergence is tested separately
    // in the X64InnerVmIsa suite below, where different ISAs
    // intentionally produce different byte sequences.
    RawEmitter a, b;
    (void)emit_inner_vm_runtime(a, kIdentityIsa);
    (void)emit_inner_vm_runtime(b, kIdentityIsa);
    ASSERT_EQ(a.size(), b.size());
    EXPECT_EQ(a.buf, b.buf);
}

// ---------------------------------------------------------------------------
// InnerVmIsa — per-build ISA permutation
// ---------------------------------------------------------------------------
//
// These tests cover the randomization layer: the `InnerVmIsa` factory
// functions, the invariant that any ISA (identity or random) is a
// valid permutation, and the resulting runtime's structural integrity
// regardless of which permutation is applied. They do NOT pin specific
// random byte sequences (that would couple the test to the Randomizer
// implementation); they pin invariants instead.

TEST(X64InnerVmIsa, IdentityIsaMapsEachOpcodeToItsOwnByte) {
    const InnerVmIsa isa = make_identity_inner_vm_isa();
    for (uint8_t i = 0; i < kInnerVmOpCount; ++i) {
        EXPECT_EQ(isa.to_byte[i], i)
            << "identity ISA must map logical index " << int{i}
            << " to byte " << int{i};
    }
    // byte_of() sugar should match the raw array lookup.
    EXPECT_EQ(isa.byte_of(InnerVmOp::iload_src),
              static_cast<uint8_t>(InnerVmOp::iload_src));
    EXPECT_EQ(isa.byte_of(InnerVmOp::iret_noflag),
              static_cast<uint8_t>(InnerVmOp::iret_noflag));
}

TEST(X64InnerVmIsa, RandomIsaIsABijectionOfTheOpcodeSpace) {
    // A valid ISA must be a permutation of [0, kInnerVmOpCount) —
    // every byte value in that range appears exactly once. A bug in
    // the Fisher–Yates could produce duplicates that silently break
    // the handler table (two table slots would point at the same
    // body, one body would be unreachable).
    Randomizer rng(0xCAFE'BABE'D15EA5E1ULL);
    const InnerVmIsa isa = make_random_inner_vm_isa(rng);

    std::set<uint8_t> seen;
    for (uint8_t i = 0; i < kInnerVmOpCount; ++i) {
        const uint8_t bv = isa.to_byte[i];
        ASSERT_LT(bv, kInnerVmOpCount)
            << "random ISA produced out-of-range byte " << int{bv};
        const bool inserted = seen.insert(bv).second;
        EXPECT_TRUE(inserted)
            << "random ISA byte " << int{bv}
            << " appears more than once — not a valid permutation";
    }
    EXPECT_EQ(seen.size(), kInnerVmOpCount);
}

TEST(X64InnerVmIsa, TwoDifferentSeedsYieldDifferentPermutations) {
    // Determinism guarantee (same seed → same output) is already
    // covered by the Randomizer's own tests. Here we only assert
    // that two UNRELATED seeds don't happen to collapse to the
    // same permutation — the Fisher–Yates is deterministic but
    // should spread its output space widely enough that two random
    // draws are almost never equal.
    Randomizer a(0x1111'2222'3333'4444ULL);
    Randomizer b(0xAAAA'BBBB'CCCC'DDDDULL);
    const InnerVmIsa isa_a = make_random_inner_vm_isa(a);
    const InnerVmIsa isa_b = make_random_inner_vm_isa(b);
    EXPECT_NE(isa_a.to_byte, isa_b.to_byte)
        << "two different seeds produced the same inner VM ISA — "
           "extremely unlikely, possible only if Randomizer is broken";
}

TEST(X64InnerVmIsa, RandomIsaRuntimeHasSameSizeAndDispatcherShape) {
    // Whatever permutation the ISA produces, the runtime size and
    // dispatcher-prologue bytes are FIXED — only the handler table
    // entries reshuffle. This catches a hypothetical future bug
    // where a randomization path accidentally affects layout.
    Randomizer rng(0xBAAD'F00D'DEAD'BEEFULL);
    const InnerVmIsa isa = make_random_inner_vm_isa(rng);

    RawEmitter e;
    (void)emit_inner_vm_runtime(e, isa);

    ASSERT_EQ(e.size(), kInnerVmRuntimeSize);
    // Dispatcher prologue is `lea r13, [rip+97]` regardless of ISA.
    EXPECT_EQ(e.buf[0], 0x4C);
    EXPECT_EQ(e.buf[1], 0x8D);
    EXPECT_EQ(e.buf[2], 0x2D);
    EXPECT_EQ(e.buf[3], 0x61);  // disp32 low byte = 97
    EXPECT_EQ(e.buf[4], 0x00);
    EXPECT_EQ(e.buf[5], 0x00);
    EXPECT_EQ(e.buf[6], 0x00);
    // Every handler body is at its fixed offset too; check iret at +78.
    EXPECT_EQ(e.buf[78], 0x51);  // push rcx
    EXPECT_EQ(e.buf[79], 0x9D);  // popfq
    EXPECT_EQ(e.buf[80], 0xC3);  // ret
}

TEST(X64InnerVmIsa, HandlerTableEntriesFollowPermutation) {
    // For a random ISA, the handler table entry at slot `to_byte[op]`
    // must point at op's fixed handler body. This is the core
    // correctness invariant that makes the permuted opcode byte
    // in the wrapper's inline bytecode reach the right handler
    // through the dispatcher's `mov eax, [r13+rax*4]` lookup.
    Randomizer rng(0xFEED'FACE'CAFE'D00DULL);
    const InnerVmIsa isa = make_random_inner_vm_isa(rng);

    RawEmitter e;
    (void)emit_inner_vm_runtime(e, isa);
    ASSERT_EQ(e.size(), kInnerVmRuntimeSize);

    // Expected handler offsets — must match the constants in
    // x64_inner_vm.cpp. Listed here in logical-op order.
    constexpr std::array<int32_t, kInnerVmOpCount> kHandlerOffsets = {{
        28, 33, 38, 43, 50, 57, 64, 71, 78, 81, 86, 87, 92, 99
    }};
    constexpr size_t table_off = 104;

    auto read_i32 = [&](size_t at) {
        return static_cast<int32_t>(
            static_cast<uint32_t>(e.buf[at])          |
            (static_cast<uint32_t>(e.buf[at + 1]) << 8)  |
            (static_cast<uint32_t>(e.buf[at + 2]) << 16) |
            (static_cast<uint32_t>(e.buf[at + 3]) << 24));
    };

    for (uint8_t op = 0; op < kInnerVmOpCount; ++op) {
        const uint8_t slot = isa.to_byte[op];
        const int32_t got = read_i32(table_off + slot * 4);
        const int32_t expected =
            kHandlerOffsets[op] - static_cast<int32_t>(table_off);
        EXPECT_EQ(got, expected)
            << "logical op " << int{op} << " at permuted slot "
            << int{slot} << " must point at handler +"
            << kHandlerOffsets[op];
    }
}

} // namespace
