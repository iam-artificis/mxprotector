/**
 * @file chaos_handler_table_integrity_refinalizer_test.cpp
 * @brief [TESTS] B.4.16.1 — `HandlerTableIntegrityRefinalizer` contract.
 *
 * Four invariants:
 *   1. PE32 image → no-op.
 *   2. Section without the pattern → no-op.
 *   3. One pattern → placeholder fills with `XOR(entry_0..N-1)`
 *      computed over the actual table bytes.
 *   4. Two adjacent patterns referencing different tables → both
 *      refinalised correctly.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/handler_table_integrity_refinalizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::HandlerTableIntegrityRefinalizer;

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

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

/// Build the 32-byte integrity-check signature with the given
/// `lea_rel32`, `total_handlers`, and `placeholder` (the imm32
/// inside `xor edx, imm32` — the refinaliser overwrites this).
[[nodiscard]] std::vector<std::uint8_t> make_integrity_check(
    std::int32_t  lea_rel32,
    std::uint32_t total_handlers,
    std::uint32_t placeholder)
{
    std::vector<std::uint8_t> b{
        0x48, 0x8D, 0x1D,                             // lea rbx, [rip+rel32]
    };
    append_u32(b, static_cast<std::uint32_t>(lea_rel32));
    b.push_back(0xB9);                                // mov ecx, total_handlers
    append_u32(b, total_handlers);
    b.insert(b.end(), {
        0x31, 0xD2,                                   // xor edx, edx
        0x33, 0x13,                                   // xor edx, [rbx]
        0x48, 0x83, 0xC3, 0x04,                       // add rbx, 4
        0xFF, 0xC9,                                   // dec ecx
        0x75, 0xF4,                                   // jnz -12
        0x81, 0xF2,                                   // xor edx, imm32
    });
    append_u32(b, placeholder);
    b.insert(b.end(), { 0x31, 0xD0 });                // xor eax, edx
    return b;
}

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
    const PeImage& img, std::size_t section_idx, std::size_t pattern_offset)
{
    std::uint32_t v = 0;
    std::memcpy(&v,
                img.sections()[section_idx].data.data() +
                    pattern_offset + 26,
                sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// PE32 / no pattern → no-op
// ---------------------------------------------------------------------------

TEST(HandlerTableIntegrityRefinalizer, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    HandlerTableIntegrityRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 0u);
}

TEST(HandlerTableIntegrityRefinalizer, NoOpOnSectionWithoutPattern) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(0x200, 0x90); // pure NOPs
    [[maybe_unused]] const Rva text_rva = add_text_section(img, bytes);

    HandlerTableIntegrityRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 0u);
}

// ---------------------------------------------------------------------------
// Single pattern fills with XOR sum of the table contents
// ---------------------------------------------------------------------------

TEST(HandlerTableIntegrityRefinalizer, SinglePatternFillsXorSum) {
    // Layout: 32-byte handler table at offset 0 with N=4 entries,
    // then the 32-byte integrity-check pattern at offset 32 whose
    // `lea rbx, [rip+rel32]` resolves to offset 0.
    //
    //   range_start = lea_anchor + rel32 = (32 + 7) + (-39) = 0  ✓
    constexpr std::uint32_t kEntries[] = {0xDEADBEEF, 0x12345678,
                                          0xCAFEBABE, 0xBADC0FFE};
    std::vector<std::uint8_t> bytes;
    for (auto v : kEntries) append_u32(bytes, v);  // 16 bytes
    // Pad to 32 bytes so the pattern starts cleanly at +32.
    while (bytes.size() < 32) bytes.push_back(0x00);

    auto pattern = make_integrity_check(/*lea_rel32=*/-39,
                                         /*total_handlers=*/4,
                                         /*placeholder=*/0xFFFFFFFFu);
    bytes.insert(bytes.end(), pattern.begin(), pattern.end());

    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, bytes);

    HandlerTableIntegrityRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 1u);

    std::uint32_t expected = 0;
    for (auto v : kEntries) expected ^= v;
    EXPECT_EQ(read_placeholder(img, /*section_idx=*/0,
                                /*pattern_offset=*/32),
              expected);
}

// ---------------------------------------------------------------------------
// Two adjacent patterns → both refinalised
// ---------------------------------------------------------------------------

TEST(HandlerTableIntegrityRefinalizer, TwoPatternsBothRefinalised) {
    // Table A (4 entries) at 0..15, pattern A at 32..63, table B
    // (3 entries) at 64..75, pattern B at 96..127. Pad table A to
    // 32 bytes and table B to 32 bytes so each pattern starts at
    // an offset divisible by 32.
    constexpr std::uint32_t kA[] = {0x11111111, 0x22222222,
                                    0x33333333, 0x44444444};
    constexpr std::uint32_t kB[] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC};

    std::vector<std::uint8_t> bytes;
    for (auto v : kA) append_u32(bytes, v);
    while (bytes.size() < 32) bytes.push_back(0x00);
    auto pattA = make_integrity_check(-39, 4, 0xFFFFFFFFu);
    bytes.insert(bytes.end(), pattA.begin(), pattA.end());

    while (bytes.size() < 96) bytes.push_back(0x00);
    // Table B starts at offset 64. We rewrite the bytes there.
    for (std::size_t i = 0; i < std::size(kB); ++i) {
        std::memcpy(bytes.data() + 64 + i * 4, &kB[i], sizeof(kB[i]));
    }
    // Pattern B at offset 96 — lea anchor = 96+7=103, range_start=64
    // → rel32 = 64 - 103 = -39.
    auto pattB = make_integrity_check(-39, 3, 0x00000000u);
    bytes.insert(bytes.end(), pattB.begin(), pattB.end());

    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, bytes);

    HandlerTableIntegrityRefinalizer r;
    EXPECT_EQ(r.refinalize(img), 2u);

    std::uint32_t expA = 0;
    for (auto v : kA) expA ^= v;
    std::uint32_t expB = 0;
    for (auto v : kB) expB ^= v;
    EXPECT_EQ(read_placeholder(img, 0, 32), expA);
    EXPECT_EQ(read_placeholder(img, 0, 96), expB);
}

} // namespace
