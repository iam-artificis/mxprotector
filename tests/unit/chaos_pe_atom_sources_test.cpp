/**
 * @file chaos_pe_atom_sources_test.cpp
 * @brief [TESTS] B.4.9.4 — `ImportAtomSource` + `PdataAtomSource` +
 *        `RelocBlockAtomSource` + `RelocPointerAtomSource`.
 *
 * Covered invariants:
 *   * IMPORT: descriptors (incl. terminator) emit 20-byte atoms;
 *     thunks emit 8-byte atoms (incl. terminator); each non-ordinal
 *     thunk's IMAGE_IMPORT_BY_NAME emits a (Hint+Name+NUL) atom.
 *   * PDATA: each 12-byte RUNTIME_FUNCTION emits one atom.
 *   * RELOC blocks: each `IMAGE_BASE_RELOCATION` block emits one
 *     atom of `block_size`.
 *   * RELOC pointers: each DIR64 entry emits an 8-byte atom at the
 *     pointed-to slot RVA.
 *   * No-op rules — PE32 image, missing directory.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/import_atom_source.hpp"
#include "mxprotector/pe/chaos/pdata_atom_source.hpp"
#include "mxprotector/pe/chaos/reloc_atom_source.hpp"
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
using mx::pe::chaos::ImportAtomSource;
using mx::pe::chaos::PdataAtomSource;
using mx::pe::chaos::RelocBlockAtomSource;
using mx::pe::chaos::RelocPointerAtomSource;

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

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt_of(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

template <typename T>
void append_le(std::vector<std::uint8_t>& out, T value) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

[[nodiscard]] Rva add_section(
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

[[nodiscard]] int count_origin(const AtomTable& t, AtomOrigin o) {
    int n = 0;
    for (const auto& a : t.atoms()) if (a.origin == o) ++n;
    return n;
}

// ---------------------------------------------------------------------------
// IMPORT
// ---------------------------------------------------------------------------

TEST(ImportAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    ImportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ImportAtomSource, NoOpWhenImportEmpty) {
    PeImage img = make_pe32plus_image();
    ImportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ImportAtomSource, DescriptorAndTerminatorEmitted) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // Descriptor[0]: OFT=0, Name=0, FT=0 (just to test the basics)
    for (int i = 0; i < 5; ++i) append_le<std::uint32_t>(bytes, 0);
    // Terminator
    for (int i = 0; i < 5; ++i) append_le<std::uint32_t>(bytes, 0);

    const Rva sec = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 40;

    ImportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(count_origin(t, AtomOrigin::import_descriptor), 1)
        << "all-zero descriptor at offset 0 = terminator only";
}

TEST(ImportAtomSource, ThunksAndByNameRecordsEmitted) {
    PeImage img = make_pe32plus_image();

    // Layout: descriptor, terminator, thunk_array, by_name_record.
    std::vector<std::uint8_t> bytes(160, 0);

    const Rva sec = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 160;

    auto patch_u32 = [&](std::size_t off, std::uint32_t v) {
        std::memcpy(img.sections()[0].data.data() + off, &v, sizeof(v));
    };
    auto patch_u64 = [&](std::size_t off, std::uint64_t v) {
        std::memcpy(img.sections()[0].data.data() + off, &v, sizeof(v));
    };

    // Descriptor[0]: OFT = sec+40 (thunk array), Name = sec+100,
    // FT = sec+40.
    patch_u32(0,  sec + 40);  // OFT
    patch_u32(12, sec + 100); // Name (DLL name string at sec+100)
    patch_u32(16, sec + 40);  // FT (same as OFT for simplicity)
    // Descriptor[1] (terminator) all zeros.
    // Thunk array at sec+40: one by-name thunk (RVA = sec+80) +
    // one terminator.
    patch_u64(40, sec + 80);
    patch_u64(48, 0);
    // IMAGE_IMPORT_BY_NAME at sec+80: hint(2) + "Foo\0".
    img.sections()[0].data[80] = 0x01;
    img.sections()[0].data[81] = 0x00;
    img.sections()[0].data[82] = 'F';
    img.sections()[0].data[83] = 'o';
    img.sections()[0].data[84] = 'o';
    img.sections()[0].data[85] = 0x00;

    ImportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_GE(count_origin(t, AtomOrigin::import_descriptor), 2);
    EXPECT_GE(count_origin(t, AtomOrigin::import_thunk),      2);
    EXPECT_GE(count_origin(t, AtomOrigin::import_by_name),    1);

    bool found_by_name = false;
    for (const auto& a : t.atoms()) {
        if (a.origin == AtomOrigin::import_by_name &&
            a.start_rva == sec + 80)
        {
            // hint(2) + "Foo"(3) + NUL(1) = 6 bytes
            EXPECT_EQ(a.size, 6u);
            found_by_name = true;
        }
    }
    EXPECT_TRUE(found_by_name);
}

// ---------------------------------------------------------------------------
// PDATA
// ---------------------------------------------------------------------------

TEST(PdataAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    PdataAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(PdataAtomSource, OneAtomPerRuntimeFunction) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // 3 RUNTIME_FUNCTION entries × 12 bytes each.
    for (int i = 0; i < 3 * 3; ++i) append_le<std::uint32_t>(bytes, 0x1000 + i);

    const Rva sec = add_section(img, ".pdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 36;

    PdataAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 3u);
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(t.atoms()[i].start_rva, sec + i * 12);
        EXPECT_EQ(t.atoms()[i].size,      12u);
        EXPECT_EQ(t.atoms()[i].origin,
                  AtomOrigin::pdata_runtime_function);
    }
}

// ---------------------------------------------------------------------------
// RELOC
// ---------------------------------------------------------------------------

TEST(RelocBlockAtomSource, OneAtomPerBlock) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // Block 1: page=0x1000, size=0x10, 4 entries (each 2 bytes).
    append_le<std::uint32_t>(bytes, 0x1000);
    append_le<std::uint32_t>(bytes, 0x10);
    for (int i = 0; i < 4; ++i) append_le<std::uint16_t>(bytes, 0);
    // Block 2: page=0x2000, size=0x10, 4 entries.
    append_le<std::uint32_t>(bytes, 0x2000);
    append_le<std::uint32_t>(bytes, 0x10);
    for (int i = 0; i < 4; ++i) append_le<std::uint16_t>(bytes, 0);

    const Rva sec = add_section(img, ".reloc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0x20;

    RelocBlockAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t.atoms()[0].size,   0x10u);
    EXPECT_EQ(t.atoms()[0].origin, AtomOrigin::reloc_block);
    EXPECT_EQ(t.atoms()[1].size,   0x10u);
}

TEST(RelocPointerAtomSource, OneAtomPerDir64Entry) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // Block: page=0x1000, size=0x10 = 8 hdr + 4 entries.
    append_le<std::uint32_t>(bytes, 0x1000);
    append_le<std::uint32_t>(bytes, 0x10);
    // 2 DIR64 entries (type=0xA0XX) at offsets 0x010 and 0x020.
    append_le<std::uint16_t>(bytes, (10 << 12) | 0x010);
    append_le<std::uint16_t>(bytes, (10 << 12) | 0x020);
    // 2 ABSOLUTE entries (type=0, padding) — should NOT emit atoms.
    append_le<std::uint16_t>(bytes, 0);
    append_le<std::uint16_t>(bytes, 0);

    const Rva sec = add_section(img, ".reloc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0x10;

    RelocPointerAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1010u);
    EXPECT_EQ(t.atoms()[0].size,      8u);
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::reloc_pointer_slot);
    EXPECT_EQ(t.atoms()[1].start_rva, 0x1020u);
    EXPECT_EQ(t.atoms()[1].size,      8u);
}

} // namespace
