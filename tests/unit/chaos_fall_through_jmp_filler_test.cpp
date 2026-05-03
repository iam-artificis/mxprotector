/**
 * @file chaos_fall_through_jmp_filler_test.cpp
 * @brief [TESTS] B.4.18 — `FallThroughJmpFiller` contract.
 *
 * Three invariants:
 *   1. Atom with `fall_through_to == 0` is skipped (slack untouched).
 *   2. Atom whose remapped successor abuts its slack gets 5 `0x90`
 *      (NOP) bytes — disassembly stays clean even when no branch is
 *      needed.
 *   3. Atom whose remapped successor sits elsewhere gets a 5-byte
 *      `JMP rel32` whose displacement targets the new successor RVA.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/fall_through_jmp_filler.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::Atom;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::FallThroughJmpFiller;
using mx::pe::refmap::RvaRemapper;

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

[[nodiscard]] Rva add_text(PeImage& img, std::size_t size) {
    std::vector<std::uint8_t> bytes(size, 0xCC); // INT3 placeholder
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] std::vector<std::uint8_t> read_bytes(
    const PeImage& img, std::size_t section_idx, std::size_t off,
    std::size_t count)
{
    const auto& sec = img.sections()[section_idx];
    return std::vector<std::uint8_t>(
        sec.data.begin() + off, sec.data.begin() + off + count);
}

// ---------------------------------------------------------------------------
// fall_through_to == 0 — skip
// ---------------------------------------------------------------------------

TEST(FallThroughJmpFiller, AtomWithoutFallThroughIsSkipped) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text(img, 0x100);

    Atom a{};
    a.start_rva       = text_rva;
    a.size            = 0x10;
    a.slack_after     = 5;
    a.fall_through_to = 0; // no successor

    RvaRemapper rm;
    rm.add_chunk(text_rva, text_rva, 0x10 + 5);
    ASSERT_TRUE(rm.finalize());

    FallThroughJmpFiller f;
    EXPECT_EQ(f.fill(img, std::span<const Atom>{&a, 1}, rm), 0u);

    // Slack bytes untouched: still the 0xCC placeholder we filled
    // the section with.
    const auto slack = read_bytes(img, 0, 0x10, 5);
    EXPECT_EQ(slack, (std::vector<std::uint8_t>(5, 0xCC)));
}

// ---------------------------------------------------------------------------
// Adjacent successor — slack filled with 5 NOPs
// ---------------------------------------------------------------------------

TEST(FallThroughJmpFiller, AdjacentSuccessorYieldsFiveNops) {
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text(img, 0x100);

    // Atom at [text_rva, text_rva + 0x10), slack at [+0x10, +0x15).
    // Successor at text_rva + 0x15 (= slack_end). Remapper is
    // identity on both; adjacency holds.
    Atom a{};
    a.start_rva       = text_rva;
    a.size            = 0x10;
    a.slack_after     = 5;
    a.fall_through_to = static_cast<Rva>(text_rva + 0x15);

    RvaRemapper rm;
    rm.add_chunk(text_rva, text_rva, 0x10 + 5);
    rm.add_chunk(static_cast<Rva>(text_rva + 0x15),
                 static_cast<Rva>(text_rva + 0x15), 1);
    ASSERT_TRUE(rm.finalize());

    FallThroughJmpFiller f;
    EXPECT_EQ(f.fill(img, std::span<const Atom>{&a, 1}, rm), 1u);

    const auto slack = read_bytes(img, 0, 0x10, 5);
    EXPECT_EQ(slack, (std::vector<std::uint8_t>{0x90, 0x90, 0x90, 0x90, 0x90}));
}

// ---------------------------------------------------------------------------
// Non-adjacent successor — slack filled with `JMP rel32`
// ---------------------------------------------------------------------------

TEST(FallThroughJmpFiller, NonAdjacentSuccessorYieldsJmpRel32) {
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text(img, 0x200);

    // Atom moved by the planner to NEW [text_rva + 0x80, +0x90),
    // slack at [+0x90, +0x95). Successor's NEW position: +0x100.
    // After the atom's slack the next byte is +0x95, which is NOT
    // +0x100, so the filler must emit a JMP rel32 with displacement
    // (+0x100) - (+0x95) = +0x6B.
    Atom a{};
    a.start_rva       = static_cast<Rva>(text_rva + 0x10);
    a.size            = 0x10;
    a.slack_after     = 5;
    a.fall_through_to = static_cast<Rva>(text_rva + 0x40);

    RvaRemapper rm;
    rm.add_chunk(static_cast<Rva>(text_rva + 0x10),
                 static_cast<Rva>(text_rva + 0x80),
                 0x10 + 5);
    rm.add_chunk(static_cast<Rva>(text_rva + 0x40),
                 static_cast<Rva>(text_rva + 0x100),
                 1);
    ASSERT_TRUE(rm.finalize());

    FallThroughJmpFiller f;
    EXPECT_EQ(f.fill(img, std::span<const Atom>{&a, 1}, rm), 1u);

    // Slack at NEW RVA text_rva + 0x90 → file offset 0x90.
    const auto slack = read_bytes(img, 0, 0x90, 5);
    EXPECT_EQ(slack[0], 0xE9u);
    std::int32_t disp = 0;
    std::memcpy(&disp, slack.data() + 1, sizeof(disp));
    // expected = (text_rva + 0x100) - (text_rva + 0x90 + 5) = 0x6B
    EXPECT_EQ(disp, 0x6B);
}

} // namespace
