/**
 * @file refmap_switch_jump_table_scanner_test.cpp
 * @brief [TESTS] B.4.13 — `SwitchJumpTableScanner` contract.
 *
 * Six invariants:
 *   1. PE32 image → no-op.
 *   2. No code section → no-op (no dispatcher to detect).
 *   3. One dispatcher with valid JT → one reference per entry while
 *      the entry value is a code RVA.
 *   4. Dispatcher pointing at JT whose first entry is non-code →
 *      zero references emitted (walk stops immediately).
 *   5. Two dispatchers with adjacent JTs → walk for the first JT
 *      stops at the second JT's base.
 *   6. Pattern using `movsxd r64, [...]` is recognised the same way
 *      as the `mov r32, [...]` form.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/switch_jump_table_scanner.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;
using mx::pe::refmap::SwitchJumpTableScanner;

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

/// Encoded `mov r11d, dword ptr [r10 + r11*4 + disp32]` (8 bytes) +
/// `add r11, r10` (3 bytes) + `jmp r11` (3 bytes) = 14-byte dispatcher.
[[nodiscard]] std::vector<std::uint8_t> make_dispatcher_bytes(
    std::uint32_t disp32)
{
    std::vector<std::uint8_t> bytes{
        0x47, 0x8B, 0x9C, 0x9A, // mov r11d, [r10 + r11*4 + disp32]
    };
    append_u32(bytes, disp32);
    // add r11, r10
    bytes.push_back(0x4D);
    bytes.push_back(0x03);
    bytes.push_back(0xDA);
    // jmp r11
    bytes.push_back(0x41);
    bytes.push_back(0xFF);
    bytes.push_back(0xE3);
    return bytes;
}

/// `movsxd r11, dword ptr [r10 + r11*4 + disp32]` (8 bytes) +
/// `add r11, r10` (3 bytes) + `jmp r11` (3 bytes).
[[nodiscard]] std::vector<std::uint8_t> make_dispatcher_movsxd(
    std::uint32_t disp32)
{
    std::vector<std::uint8_t> bytes{
        0x4F, 0x63, 0x9C, 0x9A, // movsxd r11, [r10 + r11*4 + disp32]
    };
    append_u32(bytes, disp32);
    bytes.push_back(0x4D);
    bytes.push_back(0x03);
    bytes.push_back(0xDA);
    bytes.push_back(0x41);
    bytes.push_back(0xFF);
    bytes.push_back(0xE3);
    return bytes;
}

/// Pad `code` with `0x90` (NOP) so the resulting section covers
/// at least `min_size` bytes — JT entry validation checks
/// `target_rva ∈ [virtual_address, virtual_address + virtual_size)`,
/// which `SectionManager::add_section` derives from `data.size()`.
[[nodiscard]] std::vector<std::uint8_t> pad_code(
    std::vector<std::uint8_t> code, std::size_t min_size)
{
    if (code.size() < min_size) code.resize(min_size, 0x90);
    return code;
}

/// Add a `.text` section containing `code` (padded to ≥ 0x1000 bytes
/// so synthetic JT targets at `text_rva + offset` land inside the
/// section). Returns its RVA.
[[nodiscard]] Rva add_text_section(
    PeImage& img, const std::vector<std::uint8_t>& code)
{
    const auto padded = pad_code(code, 0x1000);
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{padded.data(), padded.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

/// Add an `.rdata` section containing `bytes`. Returns its RVA.
[[nodiscard]] Rva add_rdata_section(
    PeImage& img, const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".rdata",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] std::uint32_t count_jt_refs(const ReferenceTable& t) {
    std::uint32_t n = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::switch_jump_table_entry) ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// PE32 / no code → no-op
// ---------------------------------------------------------------------------

TEST(SwitchJumpTableScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    SwitchJumpTableScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(SwitchJumpTableScanner, NoOpWithoutCodeSection) {
    PeImage img = make_pe32plus_image();
    SwitchJumpTableScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single dispatcher → entries emitted while values are code RVAs
// ---------------------------------------------------------------------------

TEST(SwitchJumpTableScanner, EmitsOneRefPerCodeRvaEntry) {
    PeImage img = make_pe32plus_image();
    // Place dispatcher in `.text`. Use a placeholder JT offset of
    // 0xDEADBEEF — overwrite it once we know the `.rdata` RVA.
    auto code = make_dispatcher_bytes(0xDEADBEEF);
    const Rva text_rva = add_text_section(img, code);

    // Five JT entries: three valid `.text` RVAs, then a value that is
    // outside any code section (walk must stop there).
    std::vector<std::uint8_t> rdata;
    append_u32(rdata, text_rva + 0x100); // valid — into .text
    append_u32(rdata, text_rva + 0x200); // valid
    append_u32(rdata, text_rva + 0x300); // valid
    append_u32(rdata, 0x99999999);       // invalid — out of any section
    append_u32(rdata, text_rva + 0x400); // would be valid but already stopped
    const Rva rdata_rva = add_rdata_section(img, rdata);

    // Patch the dispatcher's disp32 to point at the JT base.
    auto& text = img.sections()[0];
    std::memcpy(text.data.data() + 4, &rdata_rva, sizeof(rdata_rva));

    SwitchJumpTableScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_jt_refs(t), 3u);
    ASSERT_GE(t.size(), 3u);
    EXPECT_EQ(t.slots()[0].location_rva, rdata_rva);
    EXPECT_EQ(t.slots()[0].target_rva,   text_rva + 0x100);
    EXPECT_EQ(t.slots()[0].width,        ReferenceWidth::byte4);
    EXPECT_EQ(t.slots()[0].encoding,     ReferenceEncoding::rva);
    EXPECT_EQ(t.slots()[1].location_rva, rdata_rva + 4);
    EXPECT_EQ(t.slots()[2].location_rva, rdata_rva + 8);
}

// ---------------------------------------------------------------------------
// Walk stops on the first non-code entry
// ---------------------------------------------------------------------------

TEST(SwitchJumpTableScanner, WalkStopsOnFirstNonCodeEntry) {
    PeImage img = make_pe32plus_image();
    auto code = make_dispatcher_bytes(0xDEADBEEF);
    [[maybe_unused]] const Rva text_rva = add_text_section(img, code);

    std::vector<std::uint8_t> rdata;
    append_u32(rdata, 0u);            // zero — invalid (not a code RVA)
    append_u32(rdata, text_rva + 4);  // would be valid
    const Rva rdata_rva = add_rdata_section(img, rdata);

    auto& text = img.sections()[0];
    std::memcpy(text.data.data() + 4, &rdata_rva, sizeof(rdata_rva));

    SwitchJumpTableScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_jt_refs(t), 0u);
}

// ---------------------------------------------------------------------------
// Two dispatchers → second JT bounds the first walk
// ---------------------------------------------------------------------------

TEST(SwitchJumpTableScanner, SecondDispatcherCapsFirstWalk) {
    PeImage img = make_pe32plus_image();

    // Two dispatchers concatenated, JT bases set later.
    auto code1 = make_dispatcher_bytes(0xDEADBEEF);
    auto code2 = make_dispatcher_bytes(0xCAFEBABE);
    std::vector<std::uint8_t> code = code1;
    code.insert(code.end(), code2.begin(), code2.end());
    const Rva text_rva = add_text_section(img, code);

    // 8 entries at JT_A (all valid), then JT_B at +32 with 1 entry.
    std::vector<std::uint8_t> rdata(64, 0);
    for (int i = 0; i < 8; ++i) {
        const std::uint32_t v = text_rva + 0x100 + 16 * i;
        std::memcpy(rdata.data() + i * 4, &v, sizeof(v));
    }
    // JT_B at offset 32.
    const std::uint32_t jt_b_entry = text_rva + 0x500;
    std::memcpy(rdata.data() + 32, &jt_b_entry, sizeof(jt_b_entry));
    const Rva rdata_rva = add_rdata_section(img, rdata);

    auto& text = img.sections()[0];
    const std::uint32_t jt_a_rva = rdata_rva;
    const std::uint32_t jt_b_rva = rdata_rva + 32;
    std::memcpy(text.data.data() + 4,  &jt_a_rva, sizeof(jt_a_rva));
    std::memcpy(text.data.data() + 14 + 4, &jt_b_rva, sizeof(jt_b_rva));

    SwitchJumpTableScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // 8 entries from JT_A + 1 from JT_B = 9 references.
    EXPECT_EQ(count_jt_refs(t), 9u);
}

// ---------------------------------------------------------------------------
// `movsxd` variant must also be detected
// ---------------------------------------------------------------------------

TEST(SwitchJumpTableScanner, MovsxdVariantIsRecognised) {
    PeImage img = make_pe32plus_image();
    auto code = make_dispatcher_movsxd(0xDEADBEEF);
    const Rva text_rva = add_text_section(img, code);

    std::vector<std::uint8_t> rdata;
    append_u32(rdata, text_rva + 0x100);
    append_u32(rdata, 0u); // sentinel
    const Rva rdata_rva = add_rdata_section(img, rdata);

    auto& text = img.sections()[0];
    std::memcpy(text.data.data() + 4, &rdata_rva, sizeof(rdata_rva));

    SwitchJumpTableScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_jt_refs(t), 1u);
}

} // namespace
