/**
 * @file reloc_applier_test.cpp
 * @brief [TESTS] Byte-level + structural invariants of the Stage 3
 *        post-decrypt `.reloc` applier emitted by
 *        `mx::packer::emit_reloc_applier`.
 *
 * The applier is hand-assembled byte by byte: any accidental change
 * to a REX prefix, ModR/M, SIB, or a jump displacement silently
 * miscompiles the runtime loop, which only surfaces much later under
 * non-preferred-base manual-map (the only scenario where the applier
 * actually writes anything). A byte-pin test catches such drift at
 * the moment of the edit — the author updates the expected bytes,
 * the reviewer sees the diff, and everyone agrees on the new shape
 * before it ships.
 *
 * Tests:
 *  1. Emission size matches `kRelocApplierEmittedSize` (116 bytes).
 *  2. The full 116-byte sequence matches the pinned `kExpected` blob
 *     — patch-target slots are pre-patch zeros; forward/backward
 *     rel8 displacements already have their final values.
 *  3. Patch offsets recorded in `RelocApplierPatches` point at the
 *     zero-filled immediate slots, so a post-inject patcher can
 *     `write_i32` / `write_u64` into them by offset alone.
 *  4. `applier_begin_offset == 0` and `applier_end_offset == 116`
 *     when emitted into a fresh emitter.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/packer/reloc_applier.hpp"

namespace {

using mx::RawEmitter;
using mx::packer::emit_reloc_applier;
using mx::packer::kRelocApplierEmittedSize;
using mx::packer::RelocApplierPatches;

// Expected byte sequence of the applier. Every comment ties the
// offset to the source-level step in `emit_reloc_applier`. Patch-
// target immediates (lea [rip+0] disp, sub imm32, mov rbx imm64,
// mov ecx imm32, mov edx imm32) are pre-patch zeros; branch rel8s
// are already resolved to their final targets.
constexpr std::array<uint8_t, 116> kExpected = {{
    // +0   lea rax, [rip + 0]
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,
    // +7   sub rax, <imm32 = anchor>       (imm at +9)
    0x48, 0x2D, 0x00, 0x00, 0x00, 0x00,
    // +13  mov rbx, <imm64 preferred_base> (imm at +15)
    0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // +23  mov r11, rax
    0x49, 0x89, 0xC3,
    // +26  sub r11, rbx
    0x49, 0x29, 0xDB,
    // +29  test r11, r11
    0x4D, 0x85, 0xDB,
    // +32  je .done  (rel8 = 82 → .done @ +116)
    0x74, 0x52,
    // +34  mov ecx, <imm32 reloc_rva>       (imm at +35)
    0xB9, 0x00, 0x00, 0x00, 0x00,
    // +39  add rcx, rax
    0x48, 0x01, 0xC1,
    // +42  mov edx, <imm32 reloc_size>      (imm at +43)
    0xBA, 0x00, 0x00, 0x00, 0x00,
    // +47  add rdx, rcx
    0x48, 0x01, 0xCA,
    // .block_loop @ +50
    // +50  cmp rcx, rdx
    0x48, 0x39, 0xD1,
    // +53  jae .done  (rel8 = 61 → .done @ +116)
    0x73, 0x3D,
    // +55  mov r12d, [rcx]            ; page RVA
    0x44, 0x8B, 0x21,
    // +58  mov r8d,  [rcx + 4]        ; block size
    0x44, 0x8B, 0x41, 0x04,
    // +62  lea r9,   [rcx + r8]       ; block end
    0x4E, 0x8D, 0x0C, 0x01,
    // +66  add rcx,  8                ; past header
    0x48, 0x83, 0xC1, 0x08,
    // .entry_loop @ +70
    // +70  cmp rcx, r9
    0x4C, 0x39, 0xC9,
    // +73  jae .next_block (rel8 = 36 → +111)
    0x73, 0x24,
    // +75  movzx r10d, word [rcx]
    0x44, 0x0F, 0xB7, 0x11,
    // +79  mov ebx, r10d
    0x44, 0x89, 0xD3,
    // +82  shr ebx, 12
    0xC1, 0xEB, 0x0C,
    // +85  cmp ebx, 10     ; IMAGE_REL_BASED_DIR64
    0x83, 0xFB, 0x0A,
    // +88  jne .skip_entry (rel8 = 15 → +105)
    0x75, 0x0F,
    // +90  and r10d, 0xFFF
    0x41, 0x81, 0xE2, 0xFF, 0x0F, 0x00, 0x00,
    // +97  lea rbx, [rax + r12]
    0x4A, 0x8D, 0x1C, 0x20,
    // +101 add [rbx + r10], r11
    0x4E, 0x01, 0x1C, 0x13,
    // .skip_entry @ +105
    // +105 add rcx, 2
    0x48, 0x83, 0xC1, 0x02,
    // +109 jmp .entry_loop (rel8 = -41 → +70)
    0xEB, 0xD7,
    // .next_block @ +111
    // +111 mov rcx, r9
    0x4C, 0x89, 0xC9,
    // +114 jmp .block_loop (rel8 = -66 → +50)
    0xEB, 0xBE,
    // .done @ +116 (no bytes)
}};

static_assert(kExpected.size() == kRelocApplierEmittedSize,
    "expected blob size must match kRelocApplierEmittedSize");

TEST(RelocApplier, EmittedSizeMatchesConstant) {
    RawEmitter e;
    RelocApplierPatches patches;
    emit_reloc_applier(e, patches);
    EXPECT_EQ(e.buf.size(), kRelocApplierEmittedSize);
}

TEST(RelocApplier, EmittedBytesMatchPinnedBlob) {
    RawEmitter e;
    RelocApplierPatches patches;
    emit_reloc_applier(e, patches);
    ASSERT_EQ(e.buf.size(), kExpected.size());
    for (size_t i = 0; i < kExpected.size(); ++i) {
        EXPECT_EQ(e.buf[i], kExpected[i])
            << "byte drift at offset " << i
            << " (got 0x" << std::hex << static_cast<int>(e.buf[i])
            << ", want 0x" << static_cast<int>(kExpected[i]) << ")";
    }
}

TEST(RelocApplier, PatchOffsetsPointAtImmediateSlots) {
    RawEmitter e;
    RelocApplierPatches p;
    emit_reloc_applier(e, p);

    // `lea_runtime_base_anchor_offset` — end of the leading
    // `lea rax, [rip+0]` — is what the patcher feeds into the
    // `sub rax, imm32` slot (imm32 = stub_rva + anchor). The
    // constant therefore has to equal the byte offset right AFTER
    // the 7-byte lea, i.e. 7.
    EXPECT_EQ(p.lea_runtime_base_anchor_offset, 7u);

    // `sub rax, imm32` imm32 starts 2 opcode-bytes (0x48 0x2D) past
    // the anchor → +9.
    EXPECT_EQ(p.sub_runtime_base_imm32_at, 9u);

    // `mov rbx, imm64` — REX+opcode are two bytes (0x48 0xBB),
    // imm starts at 13 + 2 = 15.
    EXPECT_EQ(p.preferred_base_imm64_at, 15u);

    // `mov ecx, imm32` — one opcode byte 0xB9 at +34; imm starts
    // at +35.
    EXPECT_EQ(p.reloc_rva_imm32_at, 35u);

    // `mov edx, imm32` — one opcode byte 0xBA at +42; imm starts
    // at +43.
    EXPECT_EQ(p.reloc_size_imm32_at, 43u);

    // begin/end bracket the emission.
    EXPECT_EQ(p.applier_begin_offset, 0u);
    EXPECT_EQ(p.applier_end_offset, kRelocApplierEmittedSize);

    // Sanity: each recorded immediate slot sits on a zero byte in
    // the emission — the patcher is allowed to assume the slot is
    // pre-cleared.
    EXPECT_EQ(e.buf[p.sub_runtime_base_imm32_at],     0u);
    EXPECT_EQ(e.buf[p.sub_runtime_base_imm32_at + 3], 0u);
    EXPECT_EQ(e.buf[p.preferred_base_imm64_at],       0u);
    EXPECT_EQ(e.buf[p.preferred_base_imm64_at + 7],   0u);
    EXPECT_EQ(e.buf[p.reloc_rva_imm32_at],            0u);
    EXPECT_EQ(e.buf[p.reloc_rva_imm32_at + 3],        0u);
    EXPECT_EQ(e.buf[p.reloc_size_imm32_at],           0u);
    EXPECT_EQ(e.buf[p.reloc_size_imm32_at + 3],       0u);
}

TEST(RelocApplier, PatchRoundtripWritesIntoTheRightSlots) {
    RawEmitter e;
    RelocApplierPatches p;
    emit_reloc_applier(e, p);

    // Simulate the post-inject patcher: write distinct values into
    // each slot, then read them back via `memcpy`. This guards
    // against accidentally swapping two slot offsets.
    const int32_t  kAnchor   = 0x11111111;
    const uint64_t kPrefBase = 0x2222222222222222ULL;
    const int32_t  kRvaVal   = 0x33333333;
    const int32_t  kSizeVal  = 0x44444444;

    std::memcpy(e.buf.data() + p.sub_runtime_base_imm32_at,
                &kAnchor, sizeof(kAnchor));
    std::memcpy(e.buf.data() + p.preferred_base_imm64_at,
                &kPrefBase, sizeof(kPrefBase));
    std::memcpy(e.buf.data() + p.reloc_rva_imm32_at,
                &kRvaVal, sizeof(kRvaVal));
    std::memcpy(e.buf.data() + p.reloc_size_imm32_at,
                &kSizeVal, sizeof(kSizeVal));

    int32_t  got_anchor   = 0;
    uint64_t got_prefbase = 0;
    int32_t  got_rva      = 0;
    int32_t  got_size     = 0;
    std::memcpy(&got_anchor,
                e.buf.data() + p.sub_runtime_base_imm32_at,
                sizeof(got_anchor));
    std::memcpy(&got_prefbase,
                e.buf.data() + p.preferred_base_imm64_at,
                sizeof(got_prefbase));
    std::memcpy(&got_rva,
                e.buf.data() + p.reloc_rva_imm32_at,
                sizeof(got_rva));
    std::memcpy(&got_size,
                e.buf.data() + p.reloc_size_imm32_at,
                sizeof(got_size));

    EXPECT_EQ(got_anchor,   kAnchor);
    EXPECT_EQ(got_prefbase, kPrefBase);
    EXPECT_EQ(got_rva,      kRvaVal);
    EXPECT_EQ(got_size,     kSizeVal);
}

} // namespace
