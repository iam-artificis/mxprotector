/**
 * @file guard_veh_emitter_test.cpp
 * @brief [TESTS] Unit tests for `mx::guard::emit_guard_veh_handler`.
 *
 * The VEH handler is 125 bytes of hand-emitted x64 with several
 * forward and backward rel8 branches. Any accidental instruction
 * size change would shift every downstream offset, so the tests
 * pin down:
 *
 *   * The exact total size (regression guard on any structural
 *     change).
 *   * The byte values at every label / patch site (prologue,
 *     ExceptionCode compare, module-base computation, descriptor
 *     table load, descriptor count load, loop body, entry match,
 *     exit match, continue_search, done).
 *   * The returned `GuardVehEmit` patch-slot offsets match the
 *     actual byte positions.
 *   * Determinism: identical emitters produce identical bytes.
 *   * Independence from the starting emitter offset — the handler
 *     reports its patch slots as offsets WITHIN the handler body,
 *     so placing it at a non-zero starting offset must not change
 *     the returned values.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

namespace {

using mx::ByteBuffer;
using mx::RawEmitter;
using mx::guard::emit_guard_veh_handler;
using mx::guard::GuardVehEmit;

[[nodiscard]] uint32_t read_u32_le(const ByteBuffer& buf, size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, buf.data() + off, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// Total size + prologue + exception-code filter
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, TotalSizeMatchesHandlerLayout) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // 125 bytes of handler body — see guard_veh_emitter.cpp for
    // the byte-by-byte breakdown.
    EXPECT_EQ(e.size(), 125u);
}

TEST(GuardVehEmitter, PrologueSavesNonvolatiles) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // push rbx / push rsi / push rdi
    EXPECT_EQ(e.buf[0], 0x53u);
    EXPECT_EQ(e.buf[1], 0x56u);
    EXPECT_EQ(e.buf[2], 0x57u);
}

TEST(GuardVehEmitter, ExceptionCodeFilterUsesStatusBreakpoint) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // mov rax, [rcx]                48 8B 01           @3..5
    EXPECT_EQ(e.buf[3], 0x48u);
    EXPECT_EQ(e.buf[4], 0x8Bu);
    EXPECT_EQ(e.buf[5], 0x01u);
    // cmp dword [rax], 0x80000003   81 38 03 00 00 80  @6..11
    EXPECT_EQ(e.buf[6],  0x81u);
    EXPECT_EQ(e.buf[7],  0x38u);
    EXPECT_EQ(e.buf[8],  0x03u);
    EXPECT_EQ(e.buf[9],  0x00u);
    EXPECT_EQ(e.buf[10], 0x00u);
    EXPECT_EQ(e.buf[11], 0x80u);
    // jne rel8  75 ??                                   @12..13
    EXPECT_EQ(e.buf[12], 0x75u);
}

// ---------------------------------------------------------------------------
// Fault-address read + module-base computation
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, ReadsExceptionAddressIntoRdi) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // mov rdi, [rax + 0x10]         48 8B 78 10        @14..17
    EXPECT_EQ(e.buf[14], 0x48u);
    EXPECT_EQ(e.buf[15], 0x8Bu);
    EXPECT_EQ(e.buf[16], 0x78u);
    EXPECT_EQ(e.buf[17], 0x10u);
}

TEST(GuardVehEmitter, ModuleBaseLeaAndSubHaveExpectedEncoding) {
    RawEmitter e;
    const auto p = emit_guard_veh_handler(e);

    // lea rbx, [rip + 0]            48 8D 1D 00 00 00 00  @18..24
    EXPECT_EQ(e.buf[18], 0x48u);
    EXPECT_EQ(e.buf[19], 0x8Du);
    EXPECT_EQ(e.buf[20], 0x1Du);
    // The 4-byte zero rel32 lives at 21..24. Anchor is offset 25.
    EXPECT_EQ(read_u32_le(e.buf, 21), 0u);
    EXPECT_EQ(p.module_base_lea_anchor_offset, 25u);

    // sub rbx, imm32               48 81 EB imm32  @25..31
    EXPECT_EQ(e.buf[25], 0x48u);
    EXPECT_EQ(e.buf[26], 0x81u);
    EXPECT_EQ(e.buf[27], 0xEBu);
    // imm32 is a placeholder zero at 28..31; patched by GuardPass.
    EXPECT_EQ(read_u32_le(e.buf, 28), 0u);
    EXPECT_EQ(p.module_base_sub_imm32_offset, 28u);
}

TEST(GuardVehEmitter, SubRdiRbxConvertsFaultAddressToRva) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // sub rdi, rbx                 48 29 DF           @32..34
    EXPECT_EQ(e.buf[32], 0x48u);
    EXPECT_EQ(e.buf[33], 0x29u);
    EXPECT_EQ(e.buf[34], 0xDFu);
}

// ---------------------------------------------------------------------------
// Descriptor table load + count load
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, DescriptorTableAndCountLoadsHaveExpectedEncoding) {
    RawEmitter e;
    const auto p = emit_guard_veh_handler(e);

    // lea rsi, [rip + rel32]  48 8D 35 rel32  @35..41
    EXPECT_EQ(e.buf[35], 0x48u);
    EXPECT_EQ(e.buf[36], 0x8Du);
    EXPECT_EQ(e.buf[37], 0x35u);
    EXPECT_EQ(read_u32_le(e.buf, 38), 0u);
    EXPECT_EQ(p.descriptor_table_rel32_offset, 38u);
    EXPECT_EQ(p.descriptor_table_rel32_end_offset, 42u);

    // mov r8d, imm32          41 B8 imm32     @42..47
    EXPECT_EQ(e.buf[42], 0x41u);
    EXPECT_EQ(e.buf[43], 0xB8u);
    EXPECT_EQ(read_u32_le(e.buf, 44), 0u);
    EXPECT_EQ(p.descriptor_count_imm32_offset, 44u);
}

// ---------------------------------------------------------------------------
// Loop body shape
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, LoopBodyHasTestCmpAndAddRsi) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // .loop @48
    // test r8d, r8d           45 85 C0       @48..50
    EXPECT_EQ(e.buf[48], 0x45u);
    EXPECT_EQ(e.buf[49], 0x85u);
    EXPECT_EQ(e.buf[50], 0xC0u);
    // jz rel8                 74 ??          @51..52
    EXPECT_EQ(e.buf[51], 0x74u);
    // cmp [rsi], edi          39 3E          @53..54
    EXPECT_EQ(e.buf[53], 0x39u);
    EXPECT_EQ(e.buf[54], 0x3Eu);
    // je rel8                 74 ??          @55..56
    EXPECT_EQ(e.buf[55], 0x74u);
    // cmp [rsi+4], edi        39 7E 04       @57..59
    EXPECT_EQ(e.buf[57], 0x39u);
    EXPECT_EQ(e.buf[58], 0x7Eu);
    EXPECT_EQ(e.buf[59], 0x04u);
    // je rel8                 74 ??          @60..61
    EXPECT_EQ(e.buf[60], 0x74u);
    // add rsi, 16             48 83 C6 10    @62..65
    EXPECT_EQ(e.buf[62], 0x48u);
    EXPECT_EQ(e.buf[63], 0x83u);
    EXPECT_EQ(e.buf[64], 0xC6u);
    EXPECT_EQ(e.buf[65], 0x10u);
    // dec r8d                 41 FF C8       @66..68
    EXPECT_EQ(e.buf[66], 0x41u);
    EXPECT_EQ(e.buf[67], 0xFFu);
    EXPECT_EQ(e.buf[68], 0xC8u);
    // jmp .loop (EB rel8)     EB 00 (placeholder patched by emit)  @69..70
    EXPECT_EQ(e.buf[69], 0xEBu);
}

// ---------------------------------------------------------------------------
// Entry / exit / continue_search / done labels
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, EntryMatchBlockSetsRipToBodyStartVa) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // .entry_match @71
    // mov eax, [rsi + 8]      8B 46 08       @71..73
    EXPECT_EQ(e.buf[71], 0x8Bu);
    EXPECT_EQ(e.buf[72], 0x46u);
    EXPECT_EQ(e.buf[73], 0x08u);
    // add rax, rbx            48 01 D8       @74..76
    EXPECT_EQ(e.buf[74], 0x48u);
    EXPECT_EQ(e.buf[75], 0x01u);
    EXPECT_EQ(e.buf[76], 0xD8u);
    // mov rdx, [rcx + 8]      48 8B 51 08    @77..80
    EXPECT_EQ(e.buf[77], 0x48u);
    EXPECT_EQ(e.buf[78], 0x8Bu);
    EXPECT_EQ(e.buf[79], 0x51u);
    EXPECT_EQ(e.buf[80], 0x08u);
    // mov [rdx + 0xF8], rax   48 89 82 F8 00 00 00   @81..87
    EXPECT_EQ(e.buf[81], 0x48u);
    EXPECT_EQ(e.buf[82], 0x89u);
    EXPECT_EQ(e.buf[83], 0x82u);
    EXPECT_EQ(e.buf[84], 0xF8u);
    EXPECT_EQ(e.buf[85], 0x00u);
    EXPECT_EQ(e.buf[86], 0x00u);
    EXPECT_EQ(e.buf[87], 0x00u);
    // mov eax, -1             B8 FF FF FF FF @88..92
    EXPECT_EQ(e.buf[88], 0xB8u);
    EXPECT_EQ(e.buf[89], 0xFFu);
    EXPECT_EQ(e.buf[90], 0xFFu);
    EXPECT_EQ(e.buf[91], 0xFFu);
    EXPECT_EQ(e.buf[92], 0xFFu);
    // jmp rel8 .done          EB ??          @93..94
    EXPECT_EQ(e.buf[93], 0xEBu);
}

TEST(GuardVehEmitter, ExitMatchBlockSetsRipToReturnVa) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // .exit_match @95
    // mov eax, [rsi + 12]     8B 46 0C       @95..97
    EXPECT_EQ(e.buf[95], 0x8Bu);
    EXPECT_EQ(e.buf[96], 0x46u);
    EXPECT_EQ(e.buf[97], 0x0Cu);
    // add rax, rbx            48 01 D8       @98..100
    EXPECT_EQ(e.buf[98],  0x48u);
    EXPECT_EQ(e.buf[99],  0x01u);
    EXPECT_EQ(e.buf[100], 0xD8u);
    // mov rdx, [rcx + 8]      48 8B 51 08    @101..104
    EXPECT_EQ(e.buf[101], 0x48u);
    EXPECT_EQ(e.buf[102], 0x8Bu);
    EXPECT_EQ(e.buf[103], 0x51u);
    EXPECT_EQ(e.buf[104], 0x08u);
    // mov [rdx + 0xF8], rax   48 89 82 F8 00 00 00  @105..111
    EXPECT_EQ(e.buf[105], 0x48u);
    EXPECT_EQ(e.buf[106], 0x89u);
    EXPECT_EQ(e.buf[107], 0x82u);
    EXPECT_EQ(e.buf[108], 0xF8u);
    EXPECT_EQ(e.buf[109], 0x00u);
    EXPECT_EQ(e.buf[110], 0x00u);
    EXPECT_EQ(e.buf[111], 0x00u);
    // mov eax, -1             B8 FF FF FF FF @112..116
    EXPECT_EQ(e.buf[112], 0xB8u);
    EXPECT_EQ(e.buf[113], 0xFFu);
    EXPECT_EQ(e.buf[114], 0xFFu);
    EXPECT_EQ(e.buf[115], 0xFFu);
    EXPECT_EQ(e.buf[116], 0xFFu);
    // jmp rel8 .done          EB ??          @117..118
    EXPECT_EQ(e.buf[117], 0xEBu);
}

TEST(GuardVehEmitter, ContinueSearchAndDoneShapesMatchLayout) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // .continue_search @119
    // xor eax, eax            31 C0          @119..120
    EXPECT_EQ(e.buf[119], 0x31u);
    EXPECT_EQ(e.buf[120], 0xC0u);
    // .done @121
    // pop rdi                 5F             @121
    EXPECT_EQ(e.buf[121], 0x5Fu);
    // pop rsi                 5E             @122
    EXPECT_EQ(e.buf[122], 0x5Eu);
    // pop rbx                 5B             @123
    EXPECT_EQ(e.buf[123], 0x5Bu);
    // ret                     C3             @124
    EXPECT_EQ(e.buf[124], 0xC3u);
}

// ---------------------------------------------------------------------------
// Determinism + offset independence
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, DeterministicOutput) {
    RawEmitter a;
    RawEmitter b;
    (void)emit_guard_veh_handler(a);
    (void)emit_guard_veh_handler(b);
    EXPECT_EQ(a.buf, b.buf);
}

TEST(GuardVehEmitter, PatchOffsetsAreRelativeToHandlerStart) {
    // Emit at offset 0 and at offset 100 and verify the reported
    // patch slots are identical (they are offsets INSIDE the
    // handler body, not absolute positions).
    RawEmitter a;
    const auto pa = emit_guard_veh_handler(a);

    RawEmitter b;
    b.buf.resize(100, 0xCCu);  // pretend 100 bytes of junk precede the handler
    const auto pb = emit_guard_veh_handler(b);

    EXPECT_EQ(pa.module_base_sub_imm32_offset,
              pb.module_base_sub_imm32_offset);
    EXPECT_EQ(pa.module_base_lea_anchor_offset,
              pb.module_base_lea_anchor_offset);
    EXPECT_EQ(pa.descriptor_table_rel32_offset,
              pb.descriptor_table_rel32_offset);
    EXPECT_EQ(pa.descriptor_table_rel32_end_offset,
              pb.descriptor_table_rel32_end_offset);
    EXPECT_EQ(pa.descriptor_count_imm32_offset,
              pb.descriptor_count_imm32_offset);
}

} // namespace
