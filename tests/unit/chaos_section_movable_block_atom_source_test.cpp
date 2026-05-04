/**
 * @file chaos_section_movable_block_atom_source_test.cpp
 * @brief [TESTS] B.4.21 Phase B — `SectionMovableBlockAtomSource`.
 *
 * Pins five invariants:
 *
 *   1. No registered movable blocks → no atoms.
 *   2. One block on one section → one atom whose RVA + size match.
 *   3. Multiple blocks on the same section → one atom per block,
 *      diagnostic origin `instruction`, alignment forwarded.
 *   4. Blocks on multiple sections → atoms emitted in section
 *      iteration order.
 *   5. Out-of-section blocks (caller bug) → silently dropped, never
 *      emitted as out-of-bounds atoms.
 */

#include <gtest/gtest.h>

#include <cstdint>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/section_movable_block_atom_source.hpp"
#include "mxprotector/pe/data_region.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::pe::DataRegionKind;
using mx::pe::MovableBlock;
using mx::pe::MovableBlockKind;
using mx::pe::SectionInfo;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;
using mx::pe::chaos::SectionMovableBlockAtomSource;

[[nodiscard]] PeImage make_min_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_image_base(0x140000000ULL);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_lfanew = 0x100;
    img.set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature = 0x00004550;
    nt.FileHeader.Machine = 0x8664;
    nt.FileHeader.SizeOfOptionalHeader =
        sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic = 0x20B;
    nt.OptionalHeader.NumberOfRvaAndSizes =
        mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] SectionInfo make_section(
    std::string name, Rva va, std::uint32_t size)
{
    SectionInfo s;
    s.name = std::move(name);
    s.virtual_address = va;
    s.virtual_size = size;
    s.raw_size = size;
    s.data.assign(size, std::uint8_t{0xCC});
    s.characteristics = 0;
    return s;
}

TEST(SectionMovableBlockAtomSource, NoBlocksProducesNoAtoms) {
    auto img = make_min_image();
    img.sections().push_back(make_section(".callstub", 0x10000, 0x1000));

    AtomTable out;
    SectionMovableBlockAtomSource{}.emit_atoms(img, out);
    EXPECT_EQ(out.size(), 0u);
}

TEST(SectionMovableBlockAtomSource, OneBlockOneAtom) {
    auto img = make_min_image();
    auto sec = make_section(".callstub", 0x10000, 0x1000);
    sec.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x10100,
        .size      = 26,
        .alignment = 1,
        .kind      = MovableBlockKind::indirect_call_stub,
    });
    img.sections().push_back(std::move(sec));

    AtomTable out;
    SectionMovableBlockAtomSource{}.emit_atoms(img, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out.atoms()[0].start_rva, 0x10100u);
    EXPECT_EQ(out.atoms()[0].size, 26u);
    EXPECT_EQ(out.atoms()[0].alignment, 1u);
    EXPECT_EQ(out.atoms()[0].origin, AtomOrigin::instruction);
}

TEST(SectionMovableBlockAtomSource, MultipleBlocksPreserveOrder) {
    auto img = make_min_image();
    auto sec = make_section(".callstub", 0x10000, 0x4000);
    sec.movable_blocks = {
        MovableBlock{0x10000, 26, 1, MovableBlockKind::indirect_call_stub},
        MovableBlock{0x1001A, 39, 1, MovableBlockKind::indirect_call_stub},
        MovableBlock{0x10041, 32, 1, MovableBlockKind::indirect_call_stub},
    };
    img.sections().push_back(std::move(sec));

    AtomTable out;
    SectionMovableBlockAtomSource{}.emit_atoms(img, out);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out.atoms()[0].start_rva, 0x10000u);
    EXPECT_EQ(out.atoms()[1].start_rva, 0x1001Au);
    EXPECT_EQ(out.atoms()[2].start_rva, 0x10041u);
}

TEST(SectionMovableBlockAtomSource, MultipleSections) {
    auto img = make_min_image();

    auto sec1 = make_section(".text",     0x01000, 0x1000);
    sec1.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x01100, .size = 100, .alignment = 1});

    auto sec2 = make_section(".callstub", 0x10000, 0x1000);
    sec2.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x10200, .size = 26, .alignment = 1});

    img.sections().push_back(std::move(sec1));
    img.sections().push_back(std::move(sec2));

    AtomTable out;
    SectionMovableBlockAtomSource{}.emit_atoms(img, out);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out.atoms()[0].start_rva, 0x01100u);
    EXPECT_EQ(out.atoms()[1].start_rva, 0x10200u);
}

TEST(SectionMovableBlockAtomSource, OutOfSectionBlockIsDropped) {
    auto img = make_min_image();
    auto sec = make_section(".callstub", 0x10000, 0x1000);
    // Block starts before section.
    sec.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x0F000, .size = 100, .alignment = 1});
    // Block extends past section end (begin valid, end invalid).
    sec.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x10F00, .size = 0x200, .alignment = 1});
    // Block fully inside — should be kept.
    sec.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x10500, .size = 32, .alignment = 1});
    img.sections().push_back(std::move(sec));

    AtomTable out;
    SectionMovableBlockAtomSource{}.emit_atoms(img, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out.atoms()[0].start_rva, 0x10500u);
}

TEST(SectionMovableBlockAtomSource, ZeroSizeBlockIsDropped) {
    auto img = make_min_image();
    auto sec = make_section(".callstub", 0x10000, 0x1000);
    sec.movable_blocks.push_back(MovableBlock{
        .begin_rva = 0x10100, .size = 0, .alignment = 1});
    img.sections().push_back(std::move(sec));

    AtomTable out;
    SectionMovableBlockAtomSource{}.emit_atoms(img, out);
    EXPECT_EQ(out.size(), 0u);
}

} // namespace
