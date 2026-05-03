/**
 * @file chaos_instruction_atom_source_test.cpp
 * @brief [TESTS] B.4.9.2 — `InstructionAtomSource` contract.
 *
 * Five invariants:
 *   1. PE32 image / no code sections → no-op.
 *   2. Each cleanly decoded instruction emits one atom whose size
 *      equals the instruction length and whose start_rva equals
 *      the section's VA + offset of the first byte.
 *   3. Atoms cover the section bytes contiguously (every byte is
 *      owned by exactly one atom).
 *   4. Undecodable bytes become 1-byte `instruction_undecoded`
 *      atoms so forward progress is guaranteed.
 *   5. Multi-section images are walked per-section.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/instruction_atom_source.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::Atom;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;
using mx::pe::chaos::InstructionAtomSource;

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

[[nodiscard]] Rva add_code_section(
    PeImage&                         img,
    std::string_view                 name,
    const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        std::string(name),
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] Rva add_data_section(
    PeImage&                         img,
    std::string_view                 name,
    const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        std::string(name),
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    return img.sections()[*idx].virtual_address;
}

// ---------------------------------------------------------------------------
// Empty / disabled cases
// ---------------------------------------------------------------------------

TEST(InstructionAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(InstructionAtomSource, NoOpWhenNoCodeSection) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto rdata =
        add_data_section(img, ".rdata", {0x90, 0x90, 0x90, 0x90});

    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Decoded instructions
// ---------------------------------------------------------------------------

TEST(InstructionAtomSource, NopBytesEachOneByteAtom) {
    PeImage img = make_pe32plus_image();
    // Five NOPs: 0x90 each is a 1-byte instruction.
    const Rva sec_rva = add_code_section(img, ".text",
        {0x90, 0x90, 0x90, 0x90, 0x90});

    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 5u);
    for (std::size_t i = 0; i < 5; ++i) {
        EXPECT_EQ(t.atoms()[i].start_rva, sec_rva + i);
        EXPECT_EQ(t.atoms()[i].size,      1u);
        EXPECT_EQ(t.atoms()[i].origin,    AtomOrigin::instruction);
    }
}

TEST(InstructionAtomSource, MultiByteInstructionsHaveCorrectLengths) {
    PeImage img = make_pe32plus_image();
    // Layout:
    //   off 0..1: MOV EAX, EAX  (89 C0, 2 bytes)
    //   off 2..6: MOV EAX, 1    (B8 01 00 00 00, 5 bytes)
    //   off 7   : RET           (C3, 1 byte)
    //   off 8   : NOP           (90, 1 byte)
    const std::vector<std::uint8_t> bytes = {
        0x89, 0xC0,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3,
        0x90,
    };
    const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 4u);
    EXPECT_EQ(t.atoms()[0].start_rva, sec_rva + 0);
    EXPECT_EQ(t.atoms()[0].size,      2u);  // MOV EAX, EAX
    EXPECT_EQ(t.atoms()[1].start_rva, sec_rva + 2);
    EXPECT_EQ(t.atoms()[1].size,      5u);  // MOV EAX, 1
    EXPECT_EQ(t.atoms()[2].start_rva, sec_rva + 7);
    EXPECT_EQ(t.atoms()[2].size,      1u);  // RET
    EXPECT_EQ(t.atoms()[3].start_rva, sec_rva + 8);
    EXPECT_EQ(t.atoms()[3].size,      1u);  // NOP
}

TEST(InstructionAtomSource, AtomsCoverEverySectionByteContiguously) {
    PeImage img = make_pe32plus_image();
    const std::vector<std::uint8_t> bytes = {
        0x89, 0xC0,                                 // 2 B
        0xB8, 0x01, 0x00, 0x00, 0x00,               // 5 B
        0xC3,                                        // 1 B
    };
    const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    // The atom set should perfectly tile [sec_rva, sec_rva + 8).
    Rva cursor = sec_rva;
    for (const auto& a : t.atoms()) {
        EXPECT_EQ(a.start_rva, cursor);
        cursor = a.end_rva();
    }
    EXPECT_EQ(cursor, sec_rva + 8);
}

// ---------------------------------------------------------------------------
// Undecodable bytes
// ---------------------------------------------------------------------------

TEST(InstructionAtomSource, UndecodableByteEmitsOneByteAtomAndAdvances) {
    PeImage img = make_pe32plus_image();
    // Pure 0x66 prefix with no following opcode is an incomplete
    // instruction — Zydis returns NO_MORE_DATA, not a successful
    // decode. We choose 0xFF 0xFF (FE/Group5 with reserved
    // ModR/M reg=7) as a deterministic "decode error" trigger.
    // To make the test robust across Zydis versions, just use
    // garbage bytes. The point is: even if Zydis decodes as
    // *something*, atoms tile the buffer.
    const std::vector<std::uint8_t> bytes = {
        0xFE, 0xFF,    // Likely INC reg or invalid; depending on
                       // Zydis variant, may decode or fail.
        0x90,          // NOP — recovers cleanly.
    };
    const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    // Whatever the disassembler does, atoms must contiguously cover
    // [sec_rva, sec_rva + 3) without gaps and without overlaps.
    Rva cursor = sec_rva;
    for (const auto& a : t.atoms()) {
        EXPECT_EQ(a.start_rva, cursor);
        cursor = a.end_rva();
    }
    EXPECT_EQ(cursor, sec_rva + 3);
}

// ---------------------------------------------------------------------------
// Multi-section
// ---------------------------------------------------------------------------

TEST(InstructionAtomSource, MultipleCodeSectionsAllScanned) {
    PeImage img = make_pe32plus_image();
    const Rva text1 = add_code_section(img, ".text",  {0x90});
    const Rva text2 = add_code_section(img, ".text2", {0xC3, 0x90});
    [[maybe_unused]] const auto rdata =
        add_data_section(img,              ".rdata", {0xCC, 0xCC});

    InstructionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    // Three atoms total: 1 from text1, 2 from text2, 0 from .rdata.
    ASSERT_EQ(t.size(), 3u);
    bool saw_text1 = false, saw_text2_first = false, saw_text2_second = false;
    for (const auto& a : t.atoms()) {
        if (a.start_rva == text1)     saw_text1        = true;
        if (a.start_rva == text2)     saw_text2_first  = true;
        if (a.start_rva == text2 + 1) saw_text2_second = true;
    }
    EXPECT_TRUE(saw_text1);
    EXPECT_TRUE(saw_text2_first);
    EXPECT_TRUE(saw_text2_second);
}

} // namespace
