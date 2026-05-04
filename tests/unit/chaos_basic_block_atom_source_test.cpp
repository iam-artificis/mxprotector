/**
 * @file chaos_basic_block_atom_source_test.cpp
 * @brief [TESTS] B.4.23 — `BasicBlockAtomSource` contract.
 *
 * Pins five invariants:
 *
 *   1. PE32 (non-x64) image → no-op (matches `FunctionAtomSource`).
 *   2. No `.pdata` directory → no-op.
 *   3. A function whose only terminator is the trailing `RET` emits
 *      exactly one atom — `BasicBlockAtomSource` is LSP-equivalent
 *      to `FunctionAtomSource` in that case.
 *   4. A function with an internal `RET` whose post-byte is
 *      4-aligned splits into two atoms; the two atoms cover the
 *      function exactly with no overlap.
 *   5. A function with an internal terminator whose post-byte is
 *      NOT 4-aligned does **not** split — the planner would pin a
 *      mis-aligned movable atom, defeating the shuffle.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/basic_block_atom_source.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;
using mx::pe::chaos::BasicBlockAtomSource;

constexpr std::uint64_t kImageBase = 0x140000000ULL;

[[nodiscard]] PeImage make_pe32plus_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(kImageBase);

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

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt_of(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

void append_u32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&x);
    v.insert(v.end(), p, p + sizeof(x));
}

/// Add a `.text` section pre-loaded with `bytes` so the source's
/// Zydis decoder walks real instruction streams.
[[nodiscard]] Rva add_text_with_bytes(
    PeImage& img, const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] Rva install_pdata(
    PeImage& img, const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".pdata",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    const Rva pdata_va = img.sections()[*idx].virtual_address;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = pdata_va;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size =
            static_cast<std::uint32_t>(bytes.size());
    return pdata_va;
}

// ---------------------------------------------------------------------------
// PE32 / no .pdata
// ---------------------------------------------------------------------------

TEST(BasicBlockAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    BasicBlockAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(BasicBlockAtomSource, NoOpWithoutPdata) {
    PeImage img = make_pe32plus_image();
    BasicBlockAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// LSP equivalence: function with only a trailing terminator → one atom.
// ---------------------------------------------------------------------------

TEST(BasicBlockAtomSource, SingleTerminatorYieldsOneAtom) {
    // .text starts at 0x1000 by section alignment. A single 12-byte
    // function body: 11 NOPs + RET. No internal terminator → one atom.
    std::vector<std::uint8_t> text;
    text.resize(0x10000, 0xCC);
    // Function f at offset 0x1000 (the .text RVA we'll install) is
    // implicit; we lay down: 11 × 0x90 (NOP) + 0xC3 (RET) at offset
    // 0x1000 in the .text bytes. But .text is added to the image
    // first, so the bytes at the section's chosen RVA ARE these bytes.
    for (std::size_t i = 0; i < 11; ++i) text[i] = 0x90;
    text[11] = 0xC3; // ret
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_with_bytes(img, text);

    std::vector<std::uint8_t> pdata;
    append_u32(pdata, text_rva);
    append_u32(pdata, text_rva + 12);
    append_u32(pdata, 0x9000);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, pdata);

    BasicBlockAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, text_rva);
    EXPECT_GE(t.atoms()[0].size, 12u);
    EXPECT_EQ(t.atoms()[0].origin, AtomOrigin::instruction);
}

// ---------------------------------------------------------------------------
// Internal RET with 4-aligned split point → two atoms.
// ---------------------------------------------------------------------------

TEST(BasicBlockAtomSource, InternalRetSplitsOnAlignedBoundary) {
    // Function body of 16 bytes: 7 × NOP + RET at offset 7
    // (post-RET RVA = text_rva + 8 — 4-aligned), then 7 × NOP + RET
    // at offset 15.
    std::vector<std::uint8_t> text;
    text.resize(0x10000, 0xCC);
    for (std::size_t i = 0; i < 7; ++i)  text[i]    = 0x90;
    text[7] = 0xC3; // first RET — internal terminator
    for (std::size_t i = 8; i < 15; ++i) text[i]    = 0x90;
    text[15] = 0xC3; // trailing RET

    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_with_bytes(img, text);

    std::vector<std::uint8_t> pdata;
    append_u32(pdata, text_rva);
    append_u32(pdata, text_rva + 16);
    append_u32(pdata, 0x9000);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, pdata);

    BasicBlockAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t.atoms()[0].start_rva, text_rva);
    EXPECT_EQ(t.atoms()[0].size,      8u);
    EXPECT_EQ(t.atoms()[1].start_rva, text_rva + 8);
    EXPECT_GE(t.atoms()[1].size,      8u);
    EXPECT_EQ(t.atoms()[0].end_rva(), t.atoms()[1].start_rva);
}

// ---------------------------------------------------------------------------
// Internal terminator on UN-aligned boundary → no split.
// ---------------------------------------------------------------------------

TEST(BasicBlockAtomSource, InternalRetOnUnalignedBoundaryIsSkipped) {
    // RET at offset 5 → post-RET RVA = text_rva + 6, NOT 4-aligned.
    // Source must not split there.
    std::vector<std::uint8_t> text;
    text.resize(0x10000, 0xCC);
    for (std::size_t i = 0; i < 5; ++i)  text[i]    = 0x90;
    text[5] = 0xC3; // internal RET (post-byte unaligned)
    for (std::size_t i = 6; i < 11; ++i) text[i]    = 0x90;
    text[11] = 0xC3;

    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_with_bytes(img, text);

    std::vector<std::uint8_t> pdata;
    append_u32(pdata, text_rva);
    append_u32(pdata, text_rva + 12);
    append_u32(pdata, 0x9000);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, pdata);

    BasicBlockAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, text_rva);
}

} // namespace
