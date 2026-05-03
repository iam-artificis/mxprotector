/**
 * @file chaos_self_crc_refinalizer_test.cpp
 * @brief [TESTS] B.4.15 — `SelfCrcRefinalizer` contract.
 *
 * Four invariants:
 *   1. PE32 image → no-op.
 *   2. Section without the pattern → no-op (returns 0).
 *   3. One CRC pattern → placeholder is filled with the CRC32C of
 *      the covered byte range; subsequent reads of the placeholder
 *      slot match a software CRC32C reference.
 *   4. Two adjacent patterns → both refinalised; cursor jumps past
 *      each match.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/self_crc_refinalizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::SelfCrcRefinalizer;

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

/// Software CRC32C reference for the range `[start, start + len)`
/// inside `bytes`. Standard `init = 0xFFFFFFFF, final XOR =
/// 0xFFFFFFFF` Castagnoli convention.
[[nodiscard]] std::uint32_t sw_crc32c(
    const std::vector<std::uint8_t>& bytes,
    std::size_t                      start,
    std::size_t                      len)
{
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= bytes[start + i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0x82F63B78u : 0u);
        }
    }
    return ~crc;
}

/// Build a 36-byte self-CRC pattern that covers `length` bytes
/// starting `range_start_offset_from_lea_anchor` bytes after the
/// LEA's RIP anchor. Caller-supplied `placeholder_value` ends up at
/// the cmp imm32 slot.
[[nodiscard]] std::vector<std::uint8_t> make_crc_pattern(
    std::int32_t  rel32,
    std::uint32_t length,
    std::uint32_t placeholder_value)
{
    std::vector<std::uint8_t> b{
        0x48, 0x8D, 0x35,                             // lea rsi, [rip+rel32]
    };
    const auto* r = reinterpret_cast<const std::uint8_t*>(&rel32);
    b.insert(b.end(), r, r + 4);                      // rel32
    b.push_back(0xB9);                                // mov ecx, len32
    const auto* l = reinterpret_cast<const std::uint8_t*>(&length);
    b.insert(b.end(), l, l + 4);                      // len32
    b.insert(b.end(), {
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                 // mov eax, 0xFFFFFFFF
        0xF2, 0x0F, 0x38, 0xF0, 0x06,                 // crc32 eax, [rsi]
        0x48, 0xFF, 0xC6,                             // inc rsi
        0xFF, 0xC9,                                   // dec ecx
        0x75, 0xF4,                                   // jnz -12
        0xF7, 0xD0,                                   // not eax
        0x3D,                                         // cmp eax, imm32
    });
    const auto* p = reinterpret_cast<const std::uint8_t*>(&placeholder_value);
    b.insert(b.end(), p, p + 4);                      // imm32 placeholder
    return b;
}

/// Add a `.text` section containing exactly the supplied bytes.
[[nodiscard]] Rva add_text_section(
    PeImage& img, const std::vector<std::uint8_t>& code)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{code.data(), code.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] std::uint32_t read_placeholder(
    const PeImage& img, std::size_t offset)
{
    std::uint32_t v = 0;
    std::memcpy(&v, img.sections()[0].data.data() + offset + 32, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// PE32 / no pattern → no-op
// ---------------------------------------------------------------------------

TEST(SelfCrcRefinalizer, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    SelfCrcRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 0u);
}

TEST(SelfCrcRefinalizer, NoOpOnSectionWithoutPattern) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(0x200, 0x90); // pure NOPs
    [[maybe_unused]] const Rva text_rva = add_text_section(img, bytes);

    SelfCrcRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 0u);
}

// ---------------------------------------------------------------------------
// Single pattern is refinalised
// ---------------------------------------------------------------------------

TEST(SelfCrcRefinalizer, SinglePatternFillsPlaceholder) {
    // Lay out: at section offset 0..15, sixteen distinguishing bytes
    // (the CRC range). Pattern starts at offset 16, covers 16 bytes
    // back at offset 0 (rel32 = -23).
    //
    //   range_start = lea_anchor + rel32 = (16 + 7) + (-23) = 0  ✓
    std::vector<std::uint8_t> bytes(16);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    auto pattern = make_crc_pattern(/*rel32=*/-23,
                                     /*length=*/16,
                                     /*placeholder=*/0xDEADBEEFu);
    bytes.insert(bytes.end(), pattern.begin(), pattern.end());

    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, bytes);

    SelfCrcRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 1u);

    const std::uint32_t expected_crc = sw_crc32c(bytes, 0, 16);
    EXPECT_EQ(read_placeholder(img, /*pattern_offset=*/16), expected_crc);
}

// ---------------------------------------------------------------------------
// Two patterns in one section → both refinalised
// ---------------------------------------------------------------------------

TEST(SelfCrcRefinalizer, TwoAdjacentPatternsBothRefinalised) {
    // Two ranges of 8 bytes each, then two patterns back-to-back.
    std::vector<std::uint8_t> bytes(16);
    for (std::size_t i = 0; i < 16; ++i) {
        bytes[i] = static_cast<std::uint8_t>(0x10 + i);
    }
    // First pattern at offset 16 covers bytes [0, 8): rel32 = (0 - 23) = -23.
    auto p1 = make_crc_pattern(/*rel32=*/-23, /*length=*/8, /*placeholder=*/0u);
    bytes.insert(bytes.end(), p1.begin(), p1.end());
    // Second pattern at offset 16 + 36 = 52 covers bytes [8, 16):
    //   range_start = 52 + 7 + rel32 = 8  →  rel32 = -51
    auto p2 = make_crc_pattern(/*rel32=*/-51, /*length=*/8, /*placeholder=*/0u);
    bytes.insert(bytes.end(), p2.begin(), p2.end());

    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, bytes);

    SelfCrcRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 2u);

    EXPECT_EQ(read_placeholder(img, 16), sw_crc32c(bytes, 0, 8));
    EXPECT_EQ(read_placeholder(img, 16 + 36), sw_crc32c(bytes, 8, 8));
}

} // namespace
