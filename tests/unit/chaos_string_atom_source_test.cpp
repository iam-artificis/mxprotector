/**
 * @file chaos_string_atom_source_test.cpp
 * @brief [TESTS] B.4.9.3 — `AsciiStringAtomSource` +
 *        `Utf16StringAtomSource` contract.
 *
 * Six invariants:
 *   1. PE32 / no non-code sections → no-op.
 *   2. ASCIIZ runs ≥ min_chars + NUL emit one atom each (size =
 *      visible_chars + 1).
 *   3. ASCII runs without NUL or shorter than min_chars are ignored.
 *   4. UTF-16 LE runs ≥ min_chars + 16-bit terminator emit one atom
 *      each (size = (visible+1) * 2 bytes).
 *   5. Code sections are skipped (no double-claim with
 *      InstructionAtomSource).
 *   6. Multi-string sections produce multiple atoms.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/string_atom_source.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::AsciiStringAtomSource;
using mx::pe::chaos::Atom;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;
using mx::pe::chaos::Utf16StringAtomSource;

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

/// Build an ASCIIZ pattern like "name\0".
void append_asciiz(
    std::vector<std::uint8_t>& out,
    std::string_view           text)
{
    out.insert(out.end(), text.begin(), text.end());
    out.push_back(0x00);
}

/// Build a UTF-16 LE asciiz pattern (each char low byte, high byte
/// 0; final 16-bit terminator).
void append_utf16(
    std::vector<std::uint8_t>& out,
    std::string_view           text)
{
    for (char c : text) {
        out.push_back(static_cast<std::uint8_t>(c));
        out.push_back(0x00);
    }
    out.push_back(0x00);
    out.push_back(0x00);
}

// ---------------------------------------------------------------------------
// ASCII
// ---------------------------------------------------------------------------

TEST(AsciiStringAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    AsciiStringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(AsciiStringAtomSource, SingleStringDetected) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_asciiz(bytes, "kernel32.dll");

    const Rva sec = add_data_section(img, ".rdata", bytes);

    AsciiStringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, sec);
    EXPECT_EQ(t.atoms()[0].size,      13u) << "12 chars + NUL";
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::ascii_string);
}

TEST(AsciiStringAtomSource, ShortRunBelowThresholdIgnored) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_asciiz(bytes, "ab");        // 2 chars, < 4
    append_asciiz(bytes, "kernel32");  // 8 chars, kept

    [[maybe_unused]] const auto sec = add_data_section(img, ".rdata", bytes);

    AsciiStringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].size, 9u) << "kernel32 + NUL";
}

TEST(AsciiStringAtomSource, RunWithoutNulTerminatorIgnored) {
    PeImage img = make_pe32plus_image();
    // Long run of printable bytes with no NUL terminator after.
    // Then a non-printable byte ends the run without terminating it.
    std::vector<std::uint8_t> bytes;
    bytes.insert(bytes.end(),
                 {'k', 'e', 'r', 'n', 'e', 'l', 0xFF, 0xFF});

    [[maybe_unused]] const auto sec = add_data_section(img, ".rdata", bytes);

    AsciiStringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(t.size(), 0u) << "no NUL → not a string";
}

TEST(AsciiStringAtomSource, MultipleStringsOneSection) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_asciiz(bytes, "kernel32.dll");
    append_asciiz(bytes, "WriteFile");
    append_asciiz(bytes, "ReadFile");

    [[maybe_unused]] const auto sec = add_data_section(img, ".rdata", bytes);

    AsciiStringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 3u);
}

TEST(AsciiStringAtomSource, CodeSectionsSkipped) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_asciiz(bytes, "kernel32.dll");

    [[maybe_unused]] const auto sec = add_code_section(img, ".text", bytes);

    AsciiStringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(t.size(), 0u)
        << "InstructionAtomSource owns code-section bytes";
}

TEST(AsciiStringAtomSource, ConfigurableThreshold) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_asciiz(bytes, "ab");        // 2 chars
    append_asciiz(bytes, "abc");       // 3 chars

    [[maybe_unused]] const auto sec = add_data_section(img, ".rdata", bytes);

    AsciiStringAtomSource s{/*min_chars=*/2};
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(t.size(), 2u) << "threshold=2 admits both runs";
}

// ---------------------------------------------------------------------------
// UTF-16
// ---------------------------------------------------------------------------

TEST(Utf16StringAtomSource, SingleStringDetected) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_utf16(bytes, "Kernel32");

    const Rva sec = add_data_section(img, ".rdata", bytes);

    Utf16StringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, sec);
    EXPECT_EQ(t.atoms()[0].size,      18u) << "(8 chars + NUL) * 2 = 18";
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::utf16_string);
}

TEST(Utf16StringAtomSource, ShortRunBelowThresholdIgnored) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes;
    append_utf16(bytes, "ab");          // 2 chars, < 4
    append_utf16(bytes, "WriteFile");   // 9 chars, kept

    [[maybe_unused]] const auto sec = add_data_section(img, ".rdata", bytes);

    Utf16StringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].size, 20u) << "(9 + 1) * 2 = 20";
}

TEST(Utf16StringAtomSource, AsciiBytesNotAccidentallyDetected) {
    PeImage img = make_pe32plus_image();
    // Pure ASCIIZ string — every other byte is printable, but the
    // bytes between are NOT zero, so utf16_unit_is_printable returns
    // false. UTF-16 source must NOT pin this.
    std::vector<std::uint8_t> bytes;
    append_asciiz(bytes, "kernel32.dll");

    [[maybe_unused]] const auto sec = add_data_section(img, ".rdata", bytes);

    Utf16StringAtomSource s;
    AtomTable t;
    s.emit_atoms(img, t);

    EXPECT_EQ(t.size(), 0u)
        << "ASCII bytes must not match UTF-16 detection";
}

} // namespace
