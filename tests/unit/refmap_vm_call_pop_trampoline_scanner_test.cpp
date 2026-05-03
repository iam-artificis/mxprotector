/**
 * @file refmap_vm_call_pop_trampoline_scanner_test.cpp
 * @brief [TESTS] B.4.14 — `VmCallPopTrampolineScanner` contract.
 *
 * Five invariants:
 *   1. PE32 image → no-op.
 *   2. No code section → no-op.
 *   3. One trampoline → one reference whose target = call_after + imm32
 *      and whose encoding is `rel32_call_pop_anchored`.
 *   4. Two adjacent trampolines → two references; the cursor jumps
 *      past each match so neither overlaps the other.
 *   5. `imm32 == 0` (degenerate self-pointer) is filtered out.
 *
 * Plus one round-trip test that runs the patcher's encoder for the
 * new encoding and verifies the imm32 byte sequence.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/reference_patcher.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/refmap/vm_call_pop_trampoline_scanner.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferencePatcher;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;
using mx::pe::refmap::RvaRemapper;
using mx::pe::refmap::VmCallPopTrampolineScanner;

[[nodiscard]] PeImage make_pe32plus_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(0x140000000ULL);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_lfanew = 0x100;
    img.set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                          = 0x00004550;
    nt.FileHeader.Machine                 = 0x8664;
    nt.FileHeader.SizeOfOptionalHeader    = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic               = 0x20B;
    nt.OptionalHeader.NumberOfRvaAndSizes =
        mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    img.set_nt_headers(nt);
    return img;
}

/// One CallPop trampoline encoded as 14 bytes with the supplied imm32.
[[nodiscard]] std::vector<std::uint8_t> make_trampoline_bytes(
    std::int32_t imm32)
{
    std::vector<std::uint8_t> bytes{
        0xE8, 0x00, 0x00, 0x00, 0x00,        // call $+5
        0x48, 0x81, 0x04, 0x24,              // add qword [rsp], imm32
    };
    const auto* p = reinterpret_cast<const std::uint8_t*>(&imm32);
    bytes.insert(bytes.end(), p, p + 4);
    bytes.push_back(0xC3);                   // ret
    return bytes;
}

/// Add a `.text` section containing exactly the supplied bytes.
[[nodiscard]] Rva add_text_section(
    PeImage& img, const std::vector<std::uint8_t>& code)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{code.data(), code.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

// ---------------------------------------------------------------------------
// PE32 / no code → no-op
// ---------------------------------------------------------------------------

TEST(VmCallPopTrampolineScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    VmCallPopTrampolineScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(VmCallPopTrampolineScanner, NoOpWithoutCodeSection) {
    PeImage img = make_pe32plus_image();
    VmCallPopTrampolineScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single match → one reference with the right shape
// ---------------------------------------------------------------------------

TEST(VmCallPopTrampolineScanner, SingleTrampolineEmitsOneReference) {
    const std::int32_t imm = 0x100;
    const auto code = make_trampoline_bytes(imm);
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    VmCallPopTrampolineScanner s;
    ReferenceTable t;
    s.scan(img, t);

    ASSERT_EQ(t.size(), 1u);
    const auto& r = t.slots()[0];
    EXPECT_EQ(r.location_rva, text_rva + 9);
    EXPECT_EQ(r.target_rva,   text_rva + 5 + imm);
    EXPECT_EQ(r.width,        ReferenceWidth::byte4);
    EXPECT_EQ(r.encoding,     ReferenceEncoding::rel32_call_pop_anchored);
    EXPECT_EQ(r.origin,       ReferenceOrigin::vm_call_pop_trampoline);
}

// ---------------------------------------------------------------------------
// Two adjacent trampolines — both detected, no overlap
// ---------------------------------------------------------------------------

TEST(VmCallPopTrampolineScanner, TwoAdjacentTrampolinesEmitTwoReferences) {
    auto a = make_trampoline_bytes(0x80);
    auto b = make_trampoline_bytes(0x200);
    std::vector<std::uint8_t> code = a;
    code.insert(code.end(), b.begin(), b.end());
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, code);

    VmCallPopTrampolineScanner s;
    ReferenceTable t;
    s.scan(img, t);

    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t.slots()[0].location_rva, text_rva + 9);
    EXPECT_EQ(t.slots()[1].location_rva, text_rva + 14 + 9);
}

// ---------------------------------------------------------------------------
// Self-pointer is filtered
// ---------------------------------------------------------------------------

TEST(VmCallPopTrampolineScanner, ZeroImm32IsRejected) {
    const auto code = make_trampoline_bytes(0);
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, code);

    VmCallPopTrampolineScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Round-trip: scan → patch → verify the new imm32 honours the
// `slot - 4` anchor.
// ---------------------------------------------------------------------------

TEST(VmCallPopTrampolineScanner, EncoderRoundTripPreservesAnchor) {
    // Trampoline sits at text + 0; original target offset = +0x40.
    // After "moving" the trampoline by +0x100 and the target by
    // +0x300, the new imm32 must satisfy:
    //   new_target_rva - (new_call_after_rva)
    //   = (text + 0x40 + 0x300) - (text + 5 + 0x100)
    //   = (0x40 + 0x300) - (5 + 0x100)
    //   = 0x340 - 0x105
    //   = 0x23B
    const std::int32_t imm = 0x40 - 5;            // target = call_after + imm
    auto code = make_trampoline_bytes(imm);
    // Pad with NOPs so the section holds the trampoline's "new"
    // (post-remap) RVA range as well as the original.
    code.resize(0x200, 0x90);
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    VmCallPopTrampolineScanner s;
    ReferenceTable t;
    s.scan(img, t);
    ASSERT_EQ(t.size(), 1u);

    // Build a remapper that shifts the trampoline by +0x100 and the
    // target by +0x300. `RvaRemapper` operates on chunks, so register
    // the 14-byte trampoline and a 1-byte target marker as separate
    // chunks; bytes outside any chunk pass through unchanged.
    RvaRemapper remapper;
    const Rva trampoline_rva = text_rva;
    const Rva target_rva     = text_rva + 0x40;
    remapper.add_chunk(trampoline_rva, trampoline_rva + 0x100, 14);
    remapper.add_chunk(target_rva,     target_rva + 0x300,     1);
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher patcher;
    [[maybe_unused]] const auto stats = patcher.apply(img, t, remapper);

    // The patched imm32 lives at the trampoline's new RVA + 9, but
    // for verification it suffices to check the bytes at the
    // trampoline's *original* slot since we did not actually move
    // bytes — the remapper is a coordinate transform only.
    auto& sec = img.sections()[0];
    std::int32_t patched_imm = 0;
    std::memcpy(&patched_imm, sec.data.data() + 0x100 + 9, sizeof(patched_imm));

    const std::int32_t expected =
        static_cast<std::int32_t>(0x340) -
        static_cast<std::int32_t>(0x105);
    EXPECT_EQ(patched_imm, expected);
}

} // namespace
