/**
 * @file refmap_obfuscated_jt_scanner_test.cpp
 * @brief [TESTS] B.4.16 — `ObfuscatedJtScanner` contract.
 *
 * Six invariants:
 *   1. PE32 image → no-op.
 *   2. No code section → no-op.
 *   3. Single dispatcher with valid encrypted JT → one reference per
 *      entry whose decoded target is a code RVA, with target_rva
 *      and aux populated correctly.
 *   4. Walk stops on the first entry whose decrypted target falls
 *      outside any code section.
 *   5. Stack-key variant (`xor eax, [rsp+disp8]`) is rejected.
 *   6. Round-trip: scan → patch → on-disk slot holds
 *      `(new_target - jt_base) XOR KEY`.
 *
 * Plus a check that two adjacent dispatchers are both detected and
 * that the second's JT base bounds the first's walk.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/obfuscated_jt_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/reference_patcher.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::ObfuscatedJtScanner;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferencePatcher;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;
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

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

/// 21-byte dispatcher with `r13` as base, `xor eax, KEY` (imm32),
/// `push r13; ret` as tail. The `lea r13, [rip+0]` placeholder is
/// patched by the caller to point at the actual JT base.
[[nodiscard]] std::vector<std::uint8_t> make_dispatcher_r13_pushret(
    std::uint32_t key)
{
    std::vector<std::uint8_t> b{
        0x4C, 0x8D, 0x2D,                             // lea r13, [rip+rel32]
        0x00, 0x00, 0x00, 0x00,                       //   placeholder rel32
        0x41, 0x8B, 0x44, 0x85, 0x00,                 // mov eax, [r13+rax*4]
        0x35,                                         // xor eax, imm32
    };
    append_u32(b, key);
    b.insert(b.end(), {
        0x48, 0x63, 0xC0,                             // movsxd rax, eax
        0x49, 0x01, 0xC5,                             // add r13, rax (REX.WB + 01 + ModRM C5)
        0x41, 0x55,                                   // push r13
        0xC3,                                         // ret
    });
    return b;
}

/// Same shape but with `jmp r13` tail instead of `push;ret`.
[[nodiscard]] std::vector<std::uint8_t> make_dispatcher_r13_jmp(
    std::uint32_t key)
{
    std::vector<std::uint8_t> b{
        0x4C, 0x8D, 0x2D,                             // lea r13, [rip+rel32]
        0x00, 0x00, 0x00, 0x00,
        0x41, 0x8B, 0x44, 0x85, 0x00,                 // mov eax, [r13+rax*4]
        0x35,
    };
    append_u32(b, key);
    b.insert(b.end(), {
        0x48, 0x63, 0xC0,                             // movsxd rax, eax
        0x49, 0x01, 0xC5,                             // add r13, rax
        0x41, 0xFF, 0xE5,                             // jmp r13
    });
    return b;
}

/// Stack-key variant — `xor eax, [rsp+0]` instead of `xor eax, imm32`.
/// Scanner must skip these.
[[nodiscard]] std::vector<std::uint8_t> make_dispatcher_stack_key() {
    return std::vector<std::uint8_t>{
        0x4C, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00,     // lea r13, [rip+0]
        0x41, 0x8B, 0x44, 0x85, 0x00,                 // mov eax, [r13+rax*4]
        0x33, 0x44, 0x24, 0x00,                       // xor eax, [rsp+0]
        0x48, 0x63, 0xC0,                             // movsxd rax, eax
        0x49, 0x01, 0xC5,                             // add r13, rax
        0x41, 0xFF, 0xE5,                             // jmp r13
    };
}

/// Patch the LEA's rel32 (offset 3 inside the dispatcher) so the
/// instruction's RIP-relative target equals `target_rva`.
void patch_lea_rel32(std::vector<std::uint8_t>& code,
                     std::size_t                lea_offset,
                     Rva                        lea_rva,
                     Rva                        target_rva)
{
    const std::int32_t rel32 = static_cast<std::int32_t>(target_rva) -
                               static_cast<std::int32_t>(lea_rva + 7);
    std::memcpy(code.data() + lea_offset + 3, &rel32, sizeof(rel32));
}

/// Pad `code` with NOPs so the section's virtual range covers
/// arbitrary code RVAs the test pretends to dispatch into.
[[nodiscard]] std::vector<std::uint8_t> pad_code(
    std::vector<std::uint8_t> code, std::size_t min_size)
{
    if (code.size() < min_size) code.resize(min_size, 0x90);
    return code;
}

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

[[nodiscard]] std::uint32_t count_obf_refs(const ReferenceTable& t) {
    std::uint32_t n = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::obfuscated_jt_entry) ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// PE32 / no code → no-op
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ObfuscatedJtScanner, NoOpWithoutCodeSection) {
    PeImage img = make_pe32plus_image();
    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single dispatcher — every JT entry resolves correctly
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, SingleDispatcherEmitsOneReferencePerCodeEntry) {
    constexpr std::uint32_t kKey = 0x7FADFD3Fu;
    auto code = make_dispatcher_r13_pushret(kKey);
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    // Three encrypted entries pointing at code RVAs `text+0x100/200/300`,
    // followed by a sentinel decoded outside any code section.
    const std::uint32_t target_offsets[] = {0x100, 0x200, 0x300};
    // jt_base sits in `.rdata`; we'll know it AFTER `add_rdata_section`,
    // so reserve space first and back-fill once we know the RVA.
    std::vector<std::uint8_t> rdata(20, 0);
    const Rva rdata_rva = add_rdata_section(img, rdata);

    // Now we know `rdata_rva`. Compute deltas relative to `rdata_rva`,
    // encrypt with KEY, and write back into the rdata section.
    auto& rdata_sec = img.sections()[1];
    for (std::size_t i = 0; i < 3; ++i) {
        const std::int32_t delta =
            static_cast<std::int32_t>(text_rva + target_offsets[i]) -
            static_cast<std::int32_t>(rdata_rva);
        const std::uint32_t enc =
            static_cast<std::uint32_t>(delta) ^ kKey;
        std::memcpy(rdata_sec.data.data() + i * 4, &enc, sizeof(enc));
    }
    const std::uint32_t sentinel_enc = 0x99999999u ^ kKey;
    std::memcpy(rdata_sec.data.data() + 12, &sentinel_enc, sizeof(sentinel_enc));

    // Patch the dispatcher's LEA rel32 to point at the JT base.
    auto& text = img.sections()[0];
    patch_lea_rel32(text.data, /*lea_offset=*/0,
                    /*lea_rva=*/text_rva, /*target=*/rdata_rva);

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_obf_refs(t), 3u);
    ASSERT_GE(t.size(), 3u);

    for (std::size_t i = 0; i < 3; ++i) {
        const auto& r = t.slots()[i];
        EXPECT_EQ(r.location_rva, rdata_rva + i * 4);
        EXPECT_EQ(r.target_rva,   text_rva + target_offsets[i]);
        EXPECT_EQ(r.width,        ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding,     ReferenceEncoding::xor_encoded_signed_delta_imm32);
        EXPECT_EQ(r.origin,       ReferenceOrigin::obfuscated_jt_entry);
        EXPECT_EQ(Reference::unpack_xor_jt_base(r.aux), rdata_rva);
        EXPECT_EQ(Reference::unpack_xor_key(r.aux),     kKey);
    }
}

// ---------------------------------------------------------------------------
// `jmp reg` tail variant — also recognised
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, JmpRegTailIsRecognised) {
    constexpr std::uint32_t kKey = 0xDEADBEEFu;
    auto code = make_dispatcher_r13_jmp(kKey);
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    std::vector<std::uint8_t> rdata(8, 0);
    const Rva rdata_rva = add_rdata_section(img, rdata);

    auto& rdata_sec = img.sections()[1];
    const std::int32_t delta =
        static_cast<std::int32_t>(text_rva + 0x80) -
        static_cast<std::int32_t>(rdata_rva);
    const std::uint32_t enc = static_cast<std::uint32_t>(delta) ^ kKey;
    std::memcpy(rdata_sec.data.data(), &enc, sizeof(enc));
    const std::uint32_t sentinel = 0xCCCCCCCCu;
    std::memcpy(rdata_sec.data.data() + 4, &sentinel, sizeof(sentinel));

    auto& text = img.sections()[0];
    patch_lea_rel32(text.data, 0, text_rva, rdata_rva);

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_obf_refs(t), 1u);
}

// ---------------------------------------------------------------------------
// Stack-key variant skipped
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, StackKeyDispatcherIsSkipped) {
    auto code = make_dispatcher_stack_key();
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const Rva text_rva = add_text_section(img, code);

    std::vector<std::uint8_t> rdata(64, 0);
    [[maybe_unused]] const Rva rdata_rva = add_rdata_section(img, rdata);

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_obf_refs(t), 0u);
}

// ---------------------------------------------------------------------------
// Walk stops on first decoded target outside any code section
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, WalkStopsOnFirstNonCodeDecodedTarget) {
    constexpr std::uint32_t kKey = 0x12345678u;
    auto code = make_dispatcher_r13_pushret(kKey);
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    std::vector<std::uint8_t> rdata;
    append_u32(rdata, 0xDEADBEEFu ^ kKey);  // decoded target way out of range
    append_u32(rdata, static_cast<std::uint32_t>(0x100) ^ kKey); // valid but unreached
    const Rva rdata_rva = add_rdata_section(img, rdata);

    auto& text = img.sections()[0];
    patch_lea_rel32(text.data, 0, text_rva, rdata_rva);

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_obf_refs(t), 0u);
}

// ---------------------------------------------------------------------------
// Round-trip: scan → patch → re-encrypted slot value matches expectation
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, EncoderRoundTripReencryptsCorrectly) {
    constexpr std::uint32_t kKey = 0x7FADFD3Fu;
    auto code = make_dispatcher_r13_pushret(kKey);
    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    std::vector<std::uint8_t> rdata(8, 0);
    const Rva rdata_rva = add_rdata_section(img, rdata);

    // Old target: `text_rva + 0x100` (in code section).
    const Rva old_target = static_cast<Rva>(text_rva + 0x100);
    auto& rdata_sec = img.sections()[1];
    const std::int32_t old_delta =
        static_cast<std::int32_t>(old_target) -
        static_cast<std::int32_t>(rdata_rva);
    const std::uint32_t enc =
        static_cast<std::uint32_t>(old_delta) ^ kKey;
    std::memcpy(rdata_sec.data.data(), &enc, sizeof(enc));
    const std::uint32_t sentinel = 0xCCCCCCCCu;
    std::memcpy(rdata_sec.data.data() + 4, &sentinel, sizeof(sentinel));

    auto& text = img.sections()[0];
    patch_lea_rel32(text.data, 0, text_rva, rdata_rva);

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);
    ASSERT_EQ(count_obf_refs(t), 1u);

    // Build a remapper that moves `old_target` to `text_rva + 0x500`.
    // Patcher must rewrite the JT slot to encode the new delta.
    const Rva new_target = static_cast<Rva>(text_rva + 0x500);
    RvaRemapper remapper;
    remapper.add_chunk(old_target, new_target, /*size=*/1);
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher patcher;
    [[maybe_unused]] const auto stats = patcher.apply(img, t, remapper);

    std::uint32_t encoded = 0;
    std::memcpy(&encoded, rdata_sec.data.data(), sizeof(encoded));
    const std::int32_t expected_delta =
        static_cast<std::int32_t>(new_target) -
        static_cast<std::int32_t>(rdata_rva);
    const std::uint32_t expected_encoded =
        static_cast<std::uint32_t>(expected_delta) ^ kKey;
    EXPECT_EQ(encoded, expected_encoded);
}

// ---------------------------------------------------------------------------
// Two adjacent dispatchers — both detected
// ---------------------------------------------------------------------------

TEST(ObfuscatedJtScanner, TwoAdjacentDispatchersBothDetected) {
    constexpr std::uint32_t kKeyA = 0x11111111u;
    constexpr std::uint32_t kKeyB = 0x22222222u;
    auto a = make_dispatcher_r13_pushret(kKeyA);
    auto b = make_dispatcher_r13_pushret(kKeyB);

    std::vector<std::uint8_t> code = a;
    code.insert(code.end(), b.begin(), b.end());

    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_section(img, code);

    // Reserve space for two back-to-back JTs (each: 1 entry + sentinel).
    std::vector<std::uint8_t> rdata(16, 0);
    const Rva rdata_rva = add_rdata_section(img, rdata);
    auto& rdata_sec = img.sections()[1];

    // JT_A at offset 0 — entry → text_rva + 0x100.
    {
        const std::int32_t delta =
            static_cast<std::int32_t>(text_rva + 0x100) -
            static_cast<std::int32_t>(rdata_rva);
        const std::uint32_t enc =
            static_cast<std::uint32_t>(delta) ^ kKeyA;
        std::memcpy(rdata_sec.data.data() + 0, &enc, sizeof(enc));
        const std::uint32_t sentinel = 0xCCCCCCCCu;
        std::memcpy(rdata_sec.data.data() + 4, &sentinel, sizeof(sentinel));
    }
    // JT_B at offset 8 — entry → text_rva + 0x200.
    const std::size_t jt_b_offset = 8;
    {
        const Rva jt_b_rva = static_cast<Rva>(rdata_rva + jt_b_offset);
        const std::int32_t delta =
            static_cast<std::int32_t>(text_rva + 0x200) -
            static_cast<std::int32_t>(jt_b_rva);
        const std::uint32_t enc =
            static_cast<std::uint32_t>(delta) ^ kKeyB;
        std::memcpy(rdata_sec.data.data() + jt_b_offset + 0,
                    &enc, sizeof(enc));
        const std::uint32_t sentinel = 0xCCCCCCCCu;
        std::memcpy(rdata_sec.data.data() + jt_b_offset + 4,
                    &sentinel, sizeof(sentinel));
    }

    auto& text = img.sections()[0];
    patch_lea_rel32(text.data, /*lea_offset=*/0,
                    /*lea_rva=*/text_rva,
                    /*target=*/rdata_rva);
    patch_lea_rel32(text.data, /*lea_offset=*/a.size(),
                    /*lea_rva=*/static_cast<Rva>(text_rva + a.size()),
                    /*target=*/static_cast<Rva>(rdata_rva + jt_b_offset));

    ObfuscatedJtScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_obf_refs(t), 2u);
}

} // namespace
