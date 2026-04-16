/**
 * @file guard_veh_emitter_test.cpp
 * @brief [TESTS] Unit tests for `mx::guard::emit_guard_veh_handler`
 *        in its Commit 3b shape (with LOCK XADD ref-counting and
 *        an embedded `.decrypt_body` XOR-cipher subroutine).
 *
 * The handler is 209 bytes of deterministic x64. Rather than pin
 * every single byte (which would be a high-churn test), the tests
 * below verify a few structural invariants that the runtime
 * depends on:
 *
 *   * Total handler size matches the documented envelope.
 *   * Prologue saves exactly rbx/rbp/rsi/rdi.
 *   * The bailout tail is reachable by a fall-through after the
 *     `cmp dword [rax], 0x80000003; je .proceed` filter.
 *   * `LOCK XADD` bytes appear twice (entry + exit refcount
 *     operations).
 *   * The `movzx eax, byte [rsi + r9 + 0x18]` opcode appears
 *     inside the handler (the per-guard key read is the defining
 *     shape of the decrypt loop).
 *   * Patch slots returned by the emitter point at zero-init
 *     placeholders.
 *   * Determinism: two emissions are byte-identical.
 *   * Offset-independence: placing the handler at a non-zero
 *     starting offset does not change the reported patch offsets.
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

/// Search for a multi-byte pattern in the handler body. Returns
/// `string::npos` if not found.
[[nodiscard]] size_t find_pattern(
    const ByteBuffer& buf,
    std::initializer_list<uint8_t> pattern)
{
    if (pattern.size() == 0 || pattern.size() > buf.size()) {
        return std::string::npos;
    }
    for (size_t i = 0; i + pattern.size() <= buf.size(); ++i) {
        bool match = true;
        size_t j = 0;
        for (auto b : pattern) {
            if (buf[i + j] != b) { match = false; break; }
            ++j;
        }
        if (match) return i;
    }
    return std::string::npos;
}

/// Count the number of distinct occurrences of a multi-byte pattern.
[[nodiscard]] int count_pattern(
    const ByteBuffer& buf,
    std::initializer_list<uint8_t> pattern)
{
    if (pattern.size() == 0 || pattern.size() > buf.size()) return 0;
    int count = 0;
    for (size_t i = 0; i + pattern.size() <= buf.size(); ++i) {
        bool match = true;
        size_t j = 0;
        for (auto b : pattern) {
            if (buf[i + j] != b) { match = false; break; }
            ++j;
        }
        if (match) { ++count; i += pattern.size() - 1; }
    }
    return count;
}

// ---------------------------------------------------------------------------
// Total size envelope.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, TotalSizeInExpectedEnvelope) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // Commit 3b base handler: 209 bytes.
    // Commit 4 adds 21 bytes of HW breakpoint sweep in entry_match
    // (mov+3×or+test+jnz) → 230 bytes.
    // Any resize outside this window triggers a re-audit — this
    // test is the tripwire for accidental size drift.
    EXPECT_GE(e.size(), 200u);
    EXPECT_LE(e.size(), 260u);
}

// ---------------------------------------------------------------------------
// Prologue saves rbx/rbp/rsi/rdi.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PrologueSavesFourNonvolatiles) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    EXPECT_EQ(e.buf[0], 0x53u);  // push rbx
    EXPECT_EQ(e.buf[1], 0x55u);  // push rbp
    EXPECT_EQ(e.buf[2], 0x56u);  // push rsi
    EXPECT_EQ(e.buf[3], 0x57u);  // push rdi
}

// ---------------------------------------------------------------------------
// Exception-code filter + je-proceed fall-through tail.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, ExceptionCodeFilterFallsThroughToBailout) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // mov rax, [rcx]                          48 8B 01  @4..6
    EXPECT_EQ(e.buf[4], 0x48u);
    EXPECT_EQ(e.buf[5], 0x8Bu);
    EXPECT_EQ(e.buf[6], 0x01u);
    // cmp dword [rax], 0x80000003             81 38 03 00 00 80  @7..12
    EXPECT_EQ(e.buf[7],  0x81u);
    EXPECT_EQ(e.buf[8],  0x38u);
    EXPECT_EQ(e.buf[9],  0x03u);
    EXPECT_EQ(e.buf[10], 0x00u);
    EXPECT_EQ(e.buf[11], 0x00u);
    EXPECT_EQ(e.buf[12], 0x80u);
    // je .proceed (rel8)                      74 ??              @13..14
    EXPECT_EQ(e.buf[13], 0x74u);
    // Fall-through bailout: xor eax, eax; pop rdi; pop rsi;
    // pop rbp; pop rbx; ret                    31 C0 5F 5E 5D 5B C3  @15..21
    EXPECT_EQ(e.buf[15], 0x31u);
    EXPECT_EQ(e.buf[16], 0xC0u);
    EXPECT_EQ(e.buf[17], 0x5Fu);
    EXPECT_EQ(e.buf[18], 0x5Eu);
    EXPECT_EQ(e.buf[19], 0x5Du);
    EXPECT_EQ(e.buf[20], 0x5Bu);
    EXPECT_EQ(e.buf[21], 0xC3u);
}

// ---------------------------------------------------------------------------
// LOCK XADD appears twice — once for entry count++, once for exit count--.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, LockXaddAppearsTwiceForRefCount) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // lock xadd [rsi + 0x14], eax  =  F0 0F C1 46 14
    const int count = count_pattern(
        e.buf, {0xF0, 0x0F, 0xC1, 0x46, 0x14});
    EXPECT_EQ(count, 2)
        << "Entry and exit must both emit LOCK XADD on the same count slot";
}

// ---------------------------------------------------------------------------
// The `.decrypt_body` subroutine's defining instruction is the per-
// guard key read.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, DecryptBodyLoopContainsKeyReadPattern) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // movzx eax, byte [rsi + r9 + 0x18]  =  42 0F B6 44 0E 18
    const size_t pos = find_pattern(
        e.buf, {0x42, 0x0F, 0xB6, 0x44, 0x0E, 0x18});
    EXPECT_NE(pos, std::string::npos)
        << "Decrypt loop's per-guard key read must be present";
}

// ---------------------------------------------------------------------------
// Descriptor stride was bumped from 16 to 64 in Commit 3b — the
// `add rsi, 64` instruction must be present (16 would be `48 83 C6 10`,
// 64 is `48 83 C6 40`).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Commit 4: HW breakpoint sweep in entry_match.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, HardwareBreakpointSweepReadsDr0ThroughDr3) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);

    // The sweep reads CONTEXT.Dr0 (offset 0x48) via
    // `mov rax, [rbp + 0x48]` = `48 8B 45 48`. That's the defining
    // instruction — look for it.
    const size_t dr0_read = find_pattern(
        e.buf, {0x48, 0x8B, 0x45, 0x48});
    ASSERT_NE(dr0_read, std::string::npos)
        << "Expected `mov rax, [rbp + 0x48]` (Dr0 read) somewhere in the "
           "handler";

    // Each subsequent `or rax, [rbp + disp]` is 4 bytes.
    // Dr1 at 0x50, Dr2 at 0x58, Dr3 at 0x60.
    EXPECT_EQ(e.buf[dr0_read + 4],  0x48u);
    EXPECT_EQ(e.buf[dr0_read + 5],  0x0Bu);  // or
    EXPECT_EQ(e.buf[dr0_read + 6],  0x45u);
    EXPECT_EQ(e.buf[dr0_read + 7],  0x50u);  // Dr1
    EXPECT_EQ(e.buf[dr0_read + 8],  0x48u);
    EXPECT_EQ(e.buf[dr0_read + 9],  0x0Bu);
    EXPECT_EQ(e.buf[dr0_read + 10], 0x45u);
    EXPECT_EQ(e.buf[dr0_read + 11], 0x58u);  // Dr2
    EXPECT_EQ(e.buf[dr0_read + 12], 0x48u);
    EXPECT_EQ(e.buf[dr0_read + 13], 0x0Bu);
    EXPECT_EQ(e.buf[dr0_read + 14], 0x45u);
    EXPECT_EQ(e.buf[dr0_read + 15], 0x60u);  // Dr3

    // Followed by `test rax, rax` (48 85 C0) and a `jnz rel8`.
    EXPECT_EQ(e.buf[dr0_read + 16], 0x48u);
    EXPECT_EQ(e.buf[dr0_read + 17], 0x85u);
    EXPECT_EQ(e.buf[dr0_read + 18], 0xC0u);
    EXPECT_EQ(e.buf[dr0_read + 19], 0x75u);  // jnz rel8 opcode
}

TEST(GuardVehEmitter, StrideAdvanceMatchesSixtyFourByteDescriptor) {
    RawEmitter e;
    (void)emit_guard_veh_handler(e);
    // add rsi, 64   =  48 83 C6 40
    const size_t pos = find_pattern(e.buf, {0x48, 0x83, 0xC6, 0x40});
    EXPECT_NE(pos, std::string::npos);
    // And the old 16-byte stride must NOT still be present.
    const size_t old_pos = find_pattern(e.buf, {0x48, 0x83, 0xC6, 0x10});
    EXPECT_EQ(old_pos, std::string::npos)
        << "Old 16-byte stride leaked into Commit 3b handler";
}

// ---------------------------------------------------------------------------
// Patch-slot offsets point at zero placeholders and match the bytes
// reported by the emitter.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PatchSlotsPointAtZeroPlaceholders) {
    RawEmitter e;
    const auto p = emit_guard_veh_handler(e);

    // module_base_sub_imm32 is the 4-byte imm32 of the `sub rbx,
    // imm32` — originally zero.
    EXPECT_EQ(read_u32_le(e.buf, p.module_base_sub_imm32_offset), 0u);

    // descriptor_table_rel32 is the 4-byte rel32 of the
    // `lea rsi, [rip + rel32]` — originally zero.
    EXPECT_EQ(read_u32_le(e.buf, p.descriptor_table_rel32_offset), 0u);

    // descriptor_count_imm32 is the 4-byte imm32 of
    // `mov r8d, imm32` — originally zero.
    EXPECT_EQ(read_u32_le(e.buf, p.descriptor_count_imm32_offset), 0u);

    // And the anchor/end offsets sanity-check against each other.
    EXPECT_EQ(p.descriptor_table_rel32_end_offset,
              p.descriptor_table_rel32_offset + 4);
    EXPECT_GT(p.module_base_lea_anchor_offset, 0u);
    EXPECT_GT(p.module_base_sub_imm32_offset,
              p.module_base_lea_anchor_offset);
}

// ---------------------------------------------------------------------------
// The module-base `lea rbx, [rip + 0]` must precede the `sub rbx`
// and the rel32 slot must be zero.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, ModuleBaseLeaAndSubShape) {
    RawEmitter e;
    const auto p = emit_guard_veh_handler(e);
    // lea opcode = 48 8D 1D. `module_base_lea_anchor_offset` is the
    // byte right after the lea's 4-byte rel32, so the opcode is at
    // `anchor - 7`, the rel32 slot at `anchor - 4`.
    const uint32_t lea_opcode_offset = p.module_base_lea_anchor_offset - 7;
    EXPECT_EQ(e.buf[lea_opcode_offset + 0], 0x48u);
    EXPECT_EQ(e.buf[lea_opcode_offset + 1], 0x8Du);
    EXPECT_EQ(e.buf[lea_opcode_offset + 2], 0x1Du);
    EXPECT_EQ(read_u32_le(e.buf, lea_opcode_offset + 3), 0u);

    // sub rbx, imm32: opcode 48 81 EB, imm32 at sub_imm32_offset.
    const uint32_t sub_opcode_offset = p.module_base_sub_imm32_offset - 3;
    EXPECT_EQ(e.buf[sub_opcode_offset + 0], 0x48u);
    EXPECT_EQ(e.buf[sub_opcode_offset + 1], 0x81u);
    EXPECT_EQ(e.buf[sub_opcode_offset + 2], 0xEBu);
}

// ---------------------------------------------------------------------------
// Determinism — two emissions produce identical bytes.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, DeterministicOutput) {
    RawEmitter a;
    RawEmitter b;
    (void)emit_guard_veh_handler(a);
    (void)emit_guard_veh_handler(b);
    EXPECT_EQ(a.buf, b.buf);
}

// ---------------------------------------------------------------------------
// Patch offsets are relative to handler start, NOT to emitter start.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PatchOffsetsAreRelativeToHandlerStart) {
    RawEmitter a;
    const auto pa = emit_guard_veh_handler(a);

    RawEmitter b;
    b.buf.resize(100, 0xCCu);
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
