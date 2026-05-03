/**
 * @file chaos_directory_atom_sources_test.cpp
 * @brief [TESTS] B.4.9.5 — smoke tests for the remaining
 *        directory-driven atom sources:
 *
 *   * `LoadConfigAtomSource` — directory atom + table atoms
 *   * `TlsAtomSource`        — directory atom + callback array
 *   * `ExportAtomSource`     — directory + EAT/Names/Ordinals
 *   * `ResourceAtomSource`   — recursive tree nodes + leaves
 *   * `DebugAtomSource`      — debug-entry array
 *   * `DelayImportAtomSource`— null-terminated descriptor array
 *
 * Each source's no-op cases (empty directory, x86 image) and one
 * "happy path" test that exercises the size + origin accounting.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/debug_atom_source.hpp"
#include "mxprotector/pe/chaos/delay_import_atom_source.hpp"
#include "mxprotector/pe/chaos/export_atom_source.hpp"
#include "mxprotector/pe/chaos/load_config_atom_source.hpp"
#include "mxprotector/pe/chaos/resource_atom_source.hpp"
#include "mxprotector/pe/chaos/tls_atom_source.hpp"
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

template <typename T>
void write_le(std::vector<std::uint8_t>& out, std::size_t off, T v) {
    if (off + sizeof(T) > out.size()) out.resize(off + sizeof(T), 0);
    std::memcpy(out.data() + off, &v, sizeof(T));
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
// LOAD_CONFIG
// ---------------------------------------------------------------------------

TEST(LoadConfigAtomSource, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    mx::pe::chaos::LoadConfigAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(LoadConfigAtomSource, EmitsDirectoryAtom) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes(320, 0);
    write_le<std::uint32_t>(bytes, 0, 320);                  // inner Size
    const Rva sec = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    mx::pe::chaos::LoadConfigAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(count_origin(t, AtomOrigin::load_config_directory), 1);
    bool found = false;
    for (const auto& a : t.atoms()) {
        if (a.origin == AtomOrigin::load_config_directory) {
            EXPECT_EQ(a.start_rva, sec);
            EXPECT_EQ(a.size,      320u);
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

TEST(TlsAtomSource, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    mx::pe::chaos::TlsAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(TlsAtomSource, EmitsDirectoryAtom) {
    PeImage img = make_pe32plus_image();
    // 40-byte TLS directory + a callback array right after at off 40.
    std::vector<std::uint8_t> bytes(64, 0);

    const Rva sec = add_section(img, ".rdata", bytes);
    // Patch AddressOfCallBacks to point at sec+40.
    const std::uint64_t cb_va = kImageBase + sec + 40;
    write_le<std::uint64_t>(img.sections()[0].data, 24, cb_va);

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].Size = 40;

    mx::pe::chaos::TlsAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_GE(count_origin(t, AtomOrigin::tls_directory), 1);
    EXPECT_GE(count_origin(t, AtomOrigin::tls_callback_array), 1);
}

// ---------------------------------------------------------------------------
// EXPORT
// ---------------------------------------------------------------------------

TEST(ExportAtomSource, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    mx::pe::chaos::ExportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ExportAtomSource, EmitsDirectoryAtom) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(40, 0);
    const Rva sec = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 40;

    mx::pe::chaos::ExportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(count_origin(t, AtomOrigin::export_directory), 1);
}

// ---------------------------------------------------------------------------
// RESOURCE
// ---------------------------------------------------------------------------

TEST(ResourceAtomSource, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    mx::pe::chaos::ResourceAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ResourceAtomSource, SingleNodeWithLeafEmitsBoth) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(64, 0);
    // Header at off 0: NumberOfNamedEntries=0, NumberOfIdEntries=1
    write_le<std::uint16_t>(bytes, 14, 1);
    // Entry: id=42, OffsetToData=24 (no subdir flag, so leaf)
    write_le<std::uint32_t>(bytes, 16, 42);
    write_le<std::uint32_t>(bytes, 20, 24);
    // Data entry at 24: OffsetToData=0x4000, Size=64
    write_le<std::uint32_t>(bytes, 24, 0x4000);
    write_le<std::uint32_t>(bytes, 28, 64);

    const Rva sec = add_section(img, ".rsrc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 64;

    mx::pe::chaos::ResourceAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(count_origin(t, AtomOrigin::resource_directory_node), 1);
    EXPECT_EQ(count_origin(t, AtomOrigin::resource_data_entry), 1);
}

// ---------------------------------------------------------------------------
// DEBUG
// ---------------------------------------------------------------------------

TEST(DebugAtomSource, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    mx::pe::chaos::DebugAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(DebugAtomSource, EmitsArrayAtom) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(56, 0);  // 2 × 28-byte entries
    const Rva sec = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 56;

    mx::pe::chaos::DebugAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].size, 56u) << "2 entries × 28 B";
}

// ---------------------------------------------------------------------------
// DELAY_IMPORT
// ---------------------------------------------------------------------------

TEST(DelayImportAtomSource, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    mx::pe::chaos::DelayImportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(DelayImportAtomSource, EmitsArrayAsSingleAtom) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(64, 0);
    // descriptor[0] at off 0: Attributes=1.
    write_le<std::uint32_t>(bytes, 0, 1);
    // descriptor[1] at off 32: all-zero terminator.

    const Rva sec = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 64;

    mx::pe::chaos::DelayImportAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].size, 64u)
        << "one populated descriptor + terminator = 2 × 32B";
}

} // namespace
