/**
 * @file string_protection_pass_test.cpp
 * @brief [TESTS] Unit tests for the S2 StringProtectionPass orchestrator.
 *
 * These tests build a synthetic `PeImage` fixture in memory (no real
 * PE file on disk) and run the pass end-to-end. The fixture has three
 * sections:
 *
 *   `.text`  — one or two hand-assembled `LEA reg, [rip+disp32]`
 *              instructions whose disp32 resolves to a string inside
 *              `.rdata`. Surrounded by 0xCC padding so the xref finder
 *              has room to scan.
 *   `.rdata` — a buffer containing the string plaintext (NUL-terminated)
 *              plus filler bytes.
 *   `.data`  — writable; used to verify the scanner ignores
 *              non-rodata sections.
 *
 * After running the pass we verify:
 *
 *   - A new section was added (name matches `section_names().str`).
 *   - The new section is executable + readable (decryptor lives there).
 *   - The LEA at the known offset was overwritten with a `call rel32`
 *     opcode (0xE8) followed by NOP padding.
 *   - The call rel32 points to a location *inside* the new section
 *     (the trampoline region).
 *   - The plaintext bytes in `.rdata` were zeroed.
 *   - The pass is a no-op when `string_protection` is `disabled`.
 *   - The pass is a no-op when no xrefs are found (string not used).
 *   - The pass excludes strings whose bytes are hit by a base relocation.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/string/string_protection_pass.hpp"

namespace {

using mx::ProtectionConfig;
using mx::ProtectionContext;
using mx::Rva;
using mx::SectionNameMap;
using mx::StringProtectionMode;
using mx::StringProtectionPass;

/// Construct an empty but minimally-valid PeImage with PE32+ NT headers,
/// page-aligned sections, and a 64-bit preferred ImageBase. Sections are
/// added via the image's own `add_section` method so the RVA / raw_offset
/// layout logic is exercised.
std::unique_ptr<mx::PeImage> make_minimal_pe() {
    auto img = std::make_unique<mx::PeImage>();
    img->set_architecture(mx::Architecture::x64);
    img->set_pe_type(mx::PeType::executable);
    img->set_image_base(static_cast<mx::Va>(0x140000000ULL));
    img->set_file_alignment(0x200);
    img->set_section_alignment(0x1000);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_magic = mx::pe::IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    img->set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                            = mx::pe::IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine                   = mx::pe::IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections          = 0;
    nt.FileHeader.SizeOfOptionalHeader      = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics           = mx::pe::IMAGE_FILE_EXECUTABLE_IMAGE;
    nt.OptionalHeader.Magic                 = mx::pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.ImageBase             = static_cast<uint64_t>(img->image_base());
    nt.OptionalHeader.SectionAlignment      = img->section_alignment();
    nt.OptionalHeader.FileAlignment         = img->file_alignment();
    nt.OptionalHeader.NumberOfRvaAndSizes   = mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    img->set_nt_headers(nt);

    return img;
}

/// Encode a `LEA reg, [rip+disp32]` into a 7-byte buffer.
///
/// Low-GPR encoding (rax..rdi): REX.W = 0x48, opcode = 0x8D,
/// ModRM = (reg_low3 << 3) | 0b101 — the 0b101 rm value selects
/// rip-relative in AMD64 long mode.
std::array<uint8_t, 7> encode_lea_rip(uint8_t dest_reg_low3, int32_t disp32) {
    std::array<uint8_t, 7> out{};
    out[0] = 0x48;  // REX.W
    out[1] = 0x8D;  // LEA opcode
    out[2] = static_cast<uint8_t>((dest_reg_low3 << 3) | 0x05);  // rip+disp32
    std::memcpy(out.data() + 3, &disp32, 4);
    return out;
}

/// Append a code section to the PE. Returns the assigned RVA.
Rva add_code_section(mx::PeImage& img, std::string name, mx::ByteBuffer data) {
    mx::pe::SectionInfo sec;
    sec.name = std::move(name);
    sec.characteristics =
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_EXECUTE |
        mx::pe::IMAGE_SCN_MEM_READ;
    sec.data = std::move(data);
    sec.virtual_size = static_cast<uint32_t>(sec.data.size());
    auto r = img.add_section(std::move(sec));
    EXPECT_TRUE(r.has_value());
    return img.sections()[*r].virtual_address;
}

Rva add_rodata_section(mx::PeImage& img, std::string name, mx::ByteBuffer data) {
    mx::pe::SectionInfo sec;
    sec.name = std::move(name);
    sec.characteristics =
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ;
    sec.data = std::move(data);
    sec.virtual_size = static_cast<uint32_t>(sec.data.size());
    auto r = img.add_section(std::move(sec));
    EXPECT_TRUE(r.has_value());
    return img.sections()[*r].virtual_address;
}

/// Build a ProtectionContext around `img` with string protection in stub
/// mode and a fixed debug section name so assertions can compare by name.
ProtectionContext make_ctx(std::unique_ptr<mx::PeImage> img,
                            StringProtectionMode mode = StringProtectionMode::stub)
{
    ProtectionConfig cfg;
    cfg.string_protection = mode;
    cfg.debug_section_names = true;

    // StringProtectionPass does not touch the disassembler — a null
    // shared_ptr satisfies the context constructor.
    std::shared_ptr<mx::analysis::IDisassembler> disasm;
    ProtectionContext ctx(std::move(img), std::move(cfg), std::move(disasm));
    // Runtime decider for `.mxstr` section name.
    ctx.set_section_names(SectionNameMap{
        .vm     = ".mxvm",
        .cff    = ".mxprot1",
        .packer = ".mxpack",
        .str    = ".mxstr",
    });
    // Target is already Windows PE x64 by default.
    return ctx;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(StringProtectionPassTest, NoOpWhenDisabled) {
    auto img = make_minimal_pe();

    // .rdata: "hello_world\0" filler
    mx::ByteBuffer rdata(64, 0);
    const char kStr[] = "hello_world";
    std::memcpy(rdata.data(), kStr, sizeof(kStr));
    add_rodata_section(*img, ".rdata", std::move(rdata));

    // .text with no references
    mx::ByteBuffer text(64, 0xCC);
    add_code_section(*img, ".text", std::move(text));

    const size_t section_count_before = img->sections().size();
    auto ctx = make_ctx(std::move(img), StringProtectionMode::disabled);

    StringProtectionPass pass;
    ASSERT_FALSE(pass.is_applicable(ctx));

    // Even if we call execute directly, disabled mode should be a pure
    // skip (no new sections).
    const auto status = pass.execute(ctx);
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(ctx.pe_image().sections().size(), section_count_before);
}

TEST(StringProtectionPassTest, NoOpWhenStringHasNoXref) {
    auto img = make_minimal_pe();

    mx::ByteBuffer rdata(64, 0);
    const char kStr[] = "hello_world";
    std::memcpy(rdata.data(), kStr, sizeof(kStr));
    add_rodata_section(*img, ".rdata", std::move(rdata));

    // .text: all 0xCC → no LEA, no xrefs.
    mx::ByteBuffer text(64, 0xCC);
    add_code_section(*img, ".text", std::move(text));

    const size_t section_count_before = img->sections().size();
    auto ctx = make_ctx(std::move(img));

    StringProtectionPass pass;
    ASSERT_TRUE(pass.is_applicable(ctx));
    const auto status = pass.execute(ctx);
    ASSERT_TRUE(status.has_value());

    // No xrefs → pass should not add a section.
    EXPECT_EQ(ctx.pe_image().sections().size(), section_count_before);
}

TEST(StringProtectionPassTest, RewritesLeaAndWipesPlaintext) {
    auto img = make_minimal_pe();

    // .rdata: "protect_me\0" at offset 0, padded with zeros.
    constexpr size_t kStringOffset = 0;
    const char kStr[] = "protect_me";
    constexpr uint32_t kStringLen = sizeof(kStr) - 1;  // no NUL

    mx::ByteBuffer rdata(128, 0);
    std::memcpy(rdata.data() + kStringOffset, kStr, kStringLen);
    const Rva rdata_rva = add_rodata_section(*img, ".rdata", std::move(rdata));
    const Rva string_rva = rdata_rva + static_cast<Rva>(kStringOffset);

    // .text: a few 0xCC padding bytes, then LEA rcx, [rip + disp32]
    // targeting the string, then more padding.
    constexpr size_t kLeaOffset = 8;
    mx::ByteBuffer text(128, 0xCC);

    // `text_rva` is the virtual address the image assigned to the .text
    // section. Since we add .rdata first and .text second with 0x1000
    // section alignment, we can't precompute it — we use the assigned value.
    const Rva text_rva = add_code_section(*img, ".text", std::move(text));
    const Rva lea_rva = text_rva + static_cast<Rva>(kLeaOffset);
    const int32_t disp32 =
        static_cast<int32_t>(string_rva) - (static_cast<int32_t>(lea_rva) + 7);

    // Encode LEA rcx, [rip+disp32]: REX.W 8D 0D <disp32>, ModRM=0x0D
    // (reg=rcx=1, rm=0b101=rip)
    const auto lea_bytes = encode_lea_rip(/*dest_reg_low3=*/1, disp32);

    {
        auto& text_sec = *const_cast<mx::pe::SectionInfo*>(
            img->section_by_rva(lea_rva));
        std::memcpy(text_sec.data.data() + kLeaOffset,
                    lea_bytes.data(), lea_bytes.size());
    }

    const size_t section_count_before = img->sections().size();
    auto ctx = make_ctx(std::move(img));

    StringProtectionPass pass;
    ASSERT_TRUE(pass.is_applicable(ctx));
    const auto status = pass.execute(ctx);
    ASSERT_TRUE(status.has_value())
        << "execute failed: " << status.error().message();

    // New `.mxstr` section was added.
    ASSERT_EQ(ctx.pe_image().sections().size(), section_count_before + 1);
    const auto* mxstr_sec = ctx.pe_image().section_by_name(".mxstr");
    ASSERT_NE(mxstr_sec, nullptr);
    EXPECT_TRUE(mxstr_sec->is_executable());
    // Writable: the decryptor does an in-place XOR over the data pool
    // and flips a sticky flag inside the descriptor table.
    EXPECT_TRUE(mxstr_sec->is_writable());
    // The `mx_str_get` decryptor alone is ~66 bytes; with at least one
    // trampoline, a descriptor, and the ciphertext, the section is well
    // over 100 bytes.
    EXPECT_GE(mxstr_sec->data.size(), static_cast<size_t>(100));

    // LEA site was overwritten: E8 <rel32> 90 90 (call rel32 + 2× NOP).
    const auto* text_sec = ctx.pe_image().section_by_name(".text");
    ASSERT_NE(text_sec, nullptr);
    ASSERT_EQ(text_sec->data[kLeaOffset],     0xE8);
    EXPECT_EQ(text_sec->data[kLeaOffset + 5], 0x90);
    EXPECT_EQ(text_sec->data[kLeaOffset + 6], 0x90);

    // The call rel32 points at a byte inside the new `.mxstr` section.
    int32_t call_rel = 0;
    std::memcpy(&call_rel, text_sec->data.data() + kLeaOffset + 1, 4);
    const int64_t call_target =
        static_cast<int64_t>(lea_rva) + 5 + call_rel;
    EXPECT_GE(call_target, static_cast<int64_t>(mxstr_sec->virtual_address));
    EXPECT_LT(call_target,
              static_cast<int64_t>(mxstr_sec->virtual_address + mxstr_sec->data.size()));

    // Plaintext bytes in `.rdata` were wiped.
    const auto* rdata_sec = ctx.pe_image().section_by_name(".rdata");
    ASSERT_NE(rdata_sec, nullptr);
    for (uint32_t i = 0; i < kStringLen; ++i) {
        EXPECT_EQ(rdata_sec->data[kStringOffset + i], 0)
            << "byte " << i << " of plaintext not wiped";
    }
}

TEST(StringProtectionPassTest, ExcludesStringsHitByBaseRelocation) {
    auto img = make_minimal_pe();

    const char kStr[] = "reloc_ref_ok";
    constexpr uint32_t kStringLen = sizeof(kStr) - 1;
    mx::ByteBuffer rdata(128, 0);
    std::memcpy(rdata.data(), kStr, kStringLen);
    const Rva rdata_rva = add_rodata_section(*img, ".rdata", std::move(rdata));
    const Rva string_rva = rdata_rva;

    mx::ByteBuffer text(128, 0xCC);
    constexpr size_t kLeaOffset = 8;
    const Rva text_rva = add_code_section(*img, ".text", std::move(text));
    const Rva lea_rva = text_rva + static_cast<Rva>(kLeaOffset);
    const int32_t disp32 =
        static_cast<int32_t>(string_rva) - (static_cast<int32_t>(lea_rva) + 7);
    const auto lea_bytes = encode_lea_rip(1, disp32);
    {
        auto& text_sec = *const_cast<mx::pe::SectionInfo*>(
            img->section_by_rva(lea_rva));
        std::memcpy(text_sec.data.data() + kLeaOffset,
                    lea_bytes.data(), lea_bytes.size());
    }

    // Inject a base relocation whose target lands inside the string.
    // This simulates a static data pointer (vtable, RTTI name ref) at
    // that byte — the pass must skip protecting the string so the
    // non-code consumer isn't broken.
    mx::pe::RelocationBlock block;
    block.page_rva = string_rva & ~0xFFFu;
    mx::pe::RelocationEntry entry{};
    entry.rva  = string_rva + 2;  // inside the string's bytes
    entry.type = mx::pe::IMAGE_REL_BASED_DIR64;
    block.entries.push_back(entry);
    img->relocations().push_back(std::move(block));

    const size_t section_count_before = img->sections().size();
    auto ctx = make_ctx(std::move(img));

    StringProtectionPass pass;
    ASSERT_TRUE(pass.is_applicable(ctx));
    const auto status = pass.execute(ctx);
    ASSERT_TRUE(status.has_value());

    // No new section: the only candidate was filtered out.
    EXPECT_EQ(ctx.pe_image().sections().size(), section_count_before);

    // LEA site was NOT rewritten — still a plain 7-byte LEA.
    const auto* text_sec = ctx.pe_image().section_by_name(".text");
    ASSERT_NE(text_sec, nullptr);
    EXPECT_EQ(text_sec->data[kLeaOffset],     0x48);  // REX.W
    EXPECT_EQ(text_sec->data[kLeaOffset + 1], 0x8D);  // LEA

    // Plaintext bytes were NOT wiped.
    const auto* rdata_sec = ctx.pe_image().section_by_name(".rdata");
    ASSERT_NE(rdata_sec, nullptr);
    EXPECT_EQ(rdata_sec->data[0], static_cast<uint8_t>('r'));
}

} // anonymous namespace
