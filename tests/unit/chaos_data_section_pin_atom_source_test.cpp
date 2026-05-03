/**
 * @file chaos_data_section_pin_atom_source_test.cpp
 * @brief [TESTS] B.4.11.1 — `DataSectionPinAtomSource` contract.
 *
 * Three invariants:
 *   1. Empty image → no atoms.
 *   2. Code section → no atom (this source skips code sections).
 *   3. Each non-code section → one atom covering the section's
 *      `[virtual_address, virtual_address + virtual_size)`, with
 *      origin `load_config_directory` so the policy floor pins it
 *      at alignment 8.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/data_section_pin_atom_source.hpp"
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
using mx::pe::chaos::DataSectionPinAtomSource;

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

[[nodiscard]] Rva add_named_section(
    PeImage&         img,
    std::string_view name,
    std::uint32_t    size,
    std::uint32_t    flags)
{
    SectionManager mgr{img};
    std::vector<std::uint8_t> bytes(size, 0);
    auto idx = mgr.add_section(
        std::string(name),
        mx::ByteView{bytes.data(), bytes.size()},
        flags);
    return img.sections()[*idx].virtual_address;
}

// ---------------------------------------------------------------------------
// Empty image
// ---------------------------------------------------------------------------

TEST(DataSectionPinAtomSource, EmptyImageEmitsNothing) {
    PeImage img = make_pe32plus_image();
    DataSectionPinAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Code section skipped
// ---------------------------------------------------------------------------

TEST(DataSectionPinAtomSource, CodeSectionIsSkipped) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto code = add_named_section(
        img, ".text", 256,
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);

    DataSectionPinAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u) << "code sections must not be pinned by this source";
}

// ---------------------------------------------------------------------------
// Data section pinned
// ---------------------------------------------------------------------------

TEST(DataSectionPinAtomSource, DataSectionsBecomeAtoms) {
    PeImage img = make_pe32plus_image();
    const auto rdata = add_named_section(
        img, ".rdata", 0x100,
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    const auto data = add_named_section(
        img, ".data", 0x200,
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_WRITE);

    DataSectionPinAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 2u);

    EXPECT_EQ(t.atoms()[0].start_rva, rdata);
    EXPECT_EQ(t.atoms()[0].size,      0x100u);
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::load_config_directory);

    EXPECT_EQ(t.atoms()[1].start_rva, data);
    EXPECT_EQ(t.atoms()[1].size,      0x200u);
    EXPECT_EQ(t.atoms()[1].origin,    AtomOrigin::load_config_directory);

    // After normalize, the policy floor raises alignment to 8 so the
    // atoms are pinned.
    t.normalize();
    for (const auto& a : t.atoms()) {
        EXPECT_EQ(a.alignment, 8u);
        EXPECT_TRUE(a.is_pinned());
    }
}

} // namespace
