/**
 * @file chaos_function_atom_source_test.cpp
 * @brief [TESTS] B.4.11.2 — `FunctionAtomSource` contract.
 *
 * Five invariants:
 *   1. PE32 image → no-op.
 *   2. No `.pdata` directory → no-op.
 *   3. One valid `RUNTIME_FUNCTION` entry → one atom whose start
 *      is rounded DOWN to 8 and end rounded UP to 8.
 *   4. Multiple entries → one atom per entry, in `.pdata` order.
 *   5. Zero / sentinel terminator entries are filtered out.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/function_atom_source.hpp"
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
using mx::pe::chaos::FunctionAtomSource;

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

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

/// Add a `.text` placeholder so the image-size hint check inside
/// `FunctionAtomSource` does not reject otherwise-valid entries
/// pointing at code RVAs the test bakes in.
void add_placeholder_text(PeImage& img, std::uint32_t size) {
    SectionManager mgr{img};
    std::vector<std::uint8_t> bytes(size, 0);
    (void)mgr.add_section(
        ".text",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
}

[[nodiscard]] Rva install_pdata(
    PeImage& img,
    const std::vector<std::uint8_t>& bytes)
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
// PE32 / no .pdata no-ops
// ---------------------------------------------------------------------------

TEST(FunctionAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    FunctionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(FunctionAtomSource, NoOpWithoutPdataDirectory) {
    PeImage img = make_pe32plus_image();
    FunctionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// One entry → one atom with rounded boundaries
// ---------------------------------------------------------------------------

TEST(FunctionAtomSource, SingleEntryEmitsAlignedAtom) {
    PeImage img = make_pe32plus_image();
    add_placeholder_text(img, 0x10000);
    // One RUNTIME_FUNCTION: begin=0x1003, end=0x1037, unwind=0x9000.
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, 0x1003);
    append_u32(bytes, 0x1037);
    append_u32(bytes, 0x9000);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, bytes);

    FunctionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 1u);
    // begin 0x1003 → align_down(8) = 0x1000.
    // end   0x1037 → align_up(8)   = 0x1038.
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[0].size,      0x38u);
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::instruction);
}

// ---------------------------------------------------------------------------
// Multiple entries
// ---------------------------------------------------------------------------

TEST(FunctionAtomSource, MultipleEntriesProduceMultipleAtoms) {
    PeImage img = make_pe32plus_image();
    add_placeholder_text(img, 0x10000);
    std::vector<std::uint8_t> bytes;
    // Three RUNTIME_FUNCTION triples.
    append_u32(bytes, 0x1000); append_u32(bytes, 0x1100); append_u32(bytes, 0x9000);
    append_u32(bytes, 0x2000); append_u32(bytes, 0x2080); append_u32(bytes, 0x9100);
    append_u32(bytes, 0x3000); append_u32(bytes, 0x3050); append_u32(bytes, 0x9200);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, bytes);

    FunctionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 3u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[0].size,      0x100u);
    EXPECT_EQ(t.atoms()[1].start_rva, 0x2000u);
    EXPECT_EQ(t.atoms()[1].size,      0x80u);
    EXPECT_EQ(t.atoms()[2].start_rva, 0x3000u);
    EXPECT_EQ(t.atoms()[2].size,      0x50u);
}

// ---------------------------------------------------------------------------
// Sentinel / zero entries skipped
// ---------------------------------------------------------------------------

TEST(FunctionAtomSource, ZeroSentinelEntryIsSkipped) {
    PeImage img = make_pe32plus_image();
    add_placeholder_text(img, 0x10000);
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, 0x1000); append_u32(bytes, 0x1100); append_u32(bytes, 0x9000);
    // Zero terminator entry — must NOT produce an atom.
    append_u32(bytes, 0); append_u32(bytes, 0); append_u32(bytes, 0);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, bytes);

    FunctionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
}

TEST(FunctionAtomSource, EndBeforeBeginEntryIsRejected) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    // Malformed: end < begin.
    append_u32(bytes, 0x2000); append_u32(bytes, 0x1000); append_u32(bytes, 0x9000);
    [[maybe_unused]] const auto pdata_rva = install_pdata(img, bytes);

    FunctionAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
