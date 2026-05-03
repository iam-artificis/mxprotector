/**
 * @file chaos_volatile_metadata_atom_source_test.cpp
 * @brief [TESTS] B.4.10.4 — `VolatileMetadataAtomSource` contract.
 *
 * Five invariants:
 *   1. PE32 image → no-op.
 *   2. No `LOAD_CONFIG` directory → no-op.
 *   3. `VolatileMetadataPointer == 0` → no-op.
 *   4. Valid pointer → one atom emitted at the metadata's RVA with
 *      `size == Size` field and origin `load_config_table` (so it
 *      gets `alignment == 4` after `AtomTable::normalize`).
 *   5. Malformed `Size` (zero or absurdly large) → no-op.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/volatile_metadata_atom_source.hpp"
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
using mx::pe::chaos::VolatileMetadataAtomSource;

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

void write_u32_at(std::vector<std::uint8_t>& bytes,
                  std::size_t offset, std::uint32_t v)
{
    if (offset + sizeof(v) > bytes.size()) bytes.resize(offset + sizeof(v));
    std::memcpy(bytes.data() + offset, &v, sizeof(v));
}

void write_u64_at(std::vector<std::uint8_t>& bytes,
                  std::size_t offset, std::uint64_t v)
{
    if (offset + sizeof(v) > bytes.size()) bytes.resize(offset + sizeof(v));
    std::memcpy(bytes.data() + offset, &v, sizeof(v));
}

/// Build a minimal `LOAD_CONFIG` directory + pointed-to volatile
/// metadata in a `.rdata` section. Returns the metadata's RVA.
struct Setup {
    PeImage img;
    Rva     metadata_rva = 0;
};

[[nodiscard]] Setup build_setup_with_volatile_metadata(
    std::uint32_t metadata_size_field)
{
    Setup s{make_pe32plus_image()};
    SectionManager mgr{s.img};

    // Section A: LOAD_CONFIG. 264-byte block (covers offset 256 +8B).
    std::vector<std::uint8_t> lcfg(264, 0);
    write_u32_at(lcfg, /*offset=Size@0=*/0, 264);
    // Volatile metadata pointer @ 256 — filled below once we know
    // the metadata RVA.
    auto idx_a = mgr.add_section(
        ".lcfg",
        mx::ByteView{lcfg.data(), lcfg.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    const Rva lcfg_va = s.img.sections()[*idx_a].virtual_address;
    nt_of(s.img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = lcfg_va;
    nt_of(s.img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size =
            static_cast<std::uint32_t>(lcfg.size());

    // Section B: volatile metadata block. 64 bytes (room for header
    // + a few extra fields).
    std::vector<std::uint8_t> meta(64, 0);
    write_u32_at(meta, 0, metadata_size_field);
    auto idx_b = mgr.add_section(
        ".vmeta",
        mx::ByteView{meta.data(), meta.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    s.metadata_rva = s.img.sections()[*idx_b].virtual_address;

    // Patch the LOAD_CONFIG pointer (at offset 256) with the
    // absolute VA of the metadata.
    auto& lcfg_sec = s.img.sections()[*idx_a];
    const auto va = static_cast<std::uint64_t>(kImageBase + s.metadata_rva);
    std::memcpy(lcfg_sec.data.data() + 256, &va, sizeof(va));

    return s;
}

// ---------------------------------------------------------------------------
// PE32 / no LOAD_CONFIG no-ops
// ---------------------------------------------------------------------------

TEST(VolatileMetadataAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    VolatileMetadataAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(VolatileMetadataAtomSource, NoOpWithoutLoadConfigDirectory) {
    PeImage img = make_pe32plus_image();
    VolatileMetadataAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Pointer == 0 — no-op
// ---------------------------------------------------------------------------

TEST(VolatileMetadataAtomSource, NoOpWhenPointerIsZero) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};

    std::vector<std::uint8_t> lcfg(264, 0);
    write_u32_at(lcfg, 0, 264);
    auto idx = mgr.add_section(
        ".lcfg", mx::ByteView{lcfg.data(), lcfg.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    const Rva lcfg_va = img.sections()[*idx].virtual_address;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = lcfg_va;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 264;

    VolatileMetadataAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

TEST(VolatileMetadataAtomSource, ValidPointerEmitsAtom) {
    auto s = build_setup_with_volatile_metadata(/*Size=*/40);

    VolatileMetadataAtomSource src;
    AtomTable t;
    src.emit_atoms(s.img, t);
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, s.metadata_rva);
    EXPECT_EQ(t.atoms()[0].size,      40u);
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::load_config_table);

    // After normalize the alignment policy floor kicks in →
    // load_config_table → alignment 4 → pinned.
    t.normalize();
    EXPECT_EQ(t.atoms()[0].alignment, 4u);
    EXPECT_TRUE(t.atoms()[0].is_pinned());
}

// ---------------------------------------------------------------------------
// Malformed Size — no-op
// ---------------------------------------------------------------------------

TEST(VolatileMetadataAtomSource, NoOpOnZeroSizeField) {
    auto s = build_setup_with_volatile_metadata(/*Size=*/0);

    VolatileMetadataAtomSource src;
    AtomTable t;
    src.emit_atoms(s.img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(VolatileMetadataAtomSource, NoOpOnAbsurdlyLargeSizeField) {
    auto s = build_setup_with_volatile_metadata(/*Size=*/0xFFFFFFFFu);

    VolatileMetadataAtomSource src;
    AtomTable t;
    src.emit_atoms(s.img, t);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
