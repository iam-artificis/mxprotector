/**
 * @file chaos_pdata_chain_emitter_test.cpp
 * @brief [TESTS] B.4.23.1 — `PdataChainEmitter` contract.
 *
 * Pins three invariants:
 *
 *   1. Function with no sub-block split → emitter is a no-op
 *      (zero chained entries).
 *   2. Function with one internal RET on a 4-aligned boundary
 *      yields one chained `RUNTIME_FUNCTION` entry, parent
 *      `EndAddress` is shrunk to the first sub-block end, and
 *      `IMAGE_DIRECTORY_ENTRY_EXCEPTION` is redirected to the new
 *      `.mxpdat` section.
 *   3. The chained `UNWIND_INFO` blob in `.mxchain` carries the
 *      `UNW_FLAG_CHAININFO` bit and a `ChainInfo` trailer pointing
 *      to the parent's first sub-block + parent's
 *      `UnwindInfoAddress`.
 *
 * The emitter is tested in isolation — without invoking the chaos
 * shuffler — so any future regression in chain-info bytes,
 * directory rewrite, or sub-block correlation surfaces here long
 * before stress runs.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/pdata_chain_emitter.hpp"
#include "mxprotector/pe/layout/standard_layout.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::SectionEmitter;
using mx::pe::StandardLayout;
using mx::pe::chaos::PdataChainEmitter;

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

void append_u32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&x);
    v.insert(v.end(), p, p + sizeof(x));
}

[[nodiscard]] Rva add_text_with_bytes(
    PeImage& img, const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] Rva install_pdata(
    PeImage& img, const std::vector<std::uint8_t>& bytes)
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

[[nodiscard]] Rva exception_dir_rva(const PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers())
        .OptionalHeader.DataDirectory[
            mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
}

[[nodiscard]] std::uint32_t exception_dir_size(const PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers())
        .OptionalHeader.DataDirectory[
            mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
}

[[nodiscard]] const mx::pe::SectionInfo* find_section(
    const PeImage& img, Rva rva)
{
    for (const auto& s : img.sections()) {
        if (rva >= s.virtual_address &&
            rva <  s.virtual_address + s.virtual_size)
        {
            return &s;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// No-op when no function has an internal split point
// ---------------------------------------------------------------------------

TEST(PdataChainEmitter, NoOpWhenNoSplits) {
    // One function: NOP NOP NOP NOP NOP RET (5 NOPs + RET).
    std::vector<std::uint8_t> text;
    text.resize(0x10000, 0xCC);
    for (std::size_t i = 0; i < 5; ++i) text[i] = 0x90;
    text[5] = 0xC3;

    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_with_bytes(img, text);

    std::vector<std::uint8_t> pdata;
    append_u32(pdata, text_rva);
    append_u32(pdata, text_rva + 6);
    append_u32(pdata, 0x9000);
    [[maybe_unused]] const auto pd_rva = install_pdata(img, pdata);

    const Rva orig_dir = exception_dir_rva(img);

    StandardLayout    policy;
    SectionManager    mgr{img};
    SectionEmitter    emitter{mgr, policy};
    PdataChainEmitter chain;
    EXPECT_EQ(chain.emit(img, emitter), 0u);
    // Directory unchanged (no chained entries → no-op).
    EXPECT_EQ(exception_dir_rva(img), orig_dir);
}

// ---------------------------------------------------------------------------
// One internal RET on aligned boundary → one chained entry
// ---------------------------------------------------------------------------

TEST(PdataChainEmitter, SingleSplitProducesChainedEntry) {
    // 16-byte function with internal RET at offset 7 (post-RET at
    // offset 8 — 4-aligned). plan_sub_blocks emits two sub-blocks:
    // [0, 8) and [8, 16).
    std::vector<std::uint8_t> text;
    text.resize(0x10000, 0xCC);
    for (std::size_t i = 0; i < 7; ++i)  text[i]    = 0x90;
    text[7] = 0xC3;
    for (std::size_t i = 8; i < 15; ++i) text[i]    = 0x90;
    text[15] = 0xC3;

    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_with_bytes(img, text);

    std::vector<std::uint8_t> pdata;
    append_u32(pdata, text_rva);
    append_u32(pdata, text_rva + 16);
    append_u32(pdata, 0x9000);
    [[maybe_unused]] const auto pd_rva = install_pdata(img, pdata);

    StandardLayout    policy;
    SectionManager    mgr{img};
    SectionEmitter    emitter{mgr, policy};
    PdataChainEmitter chain;
    const auto chained_count = chain.emit(img, emitter);
    EXPECT_EQ(chained_count, 1u);

    // Directory should now point at the new `.mxpdat`. Two entries
    // total (parent + chained sub-block) = 24 bytes.
    const Rva           new_dir   = exception_dir_rva(img);
    const std::uint32_t new_size  = exception_dir_size(img);
    EXPECT_NE(new_dir, pd_rva);
    EXPECT_EQ(new_size, 24u);

    // Read the two combined entries from `.mxpdat`.
    const auto* mxpdat_sec = find_section(img, new_dir);
    ASSERT_NE(mxpdat_sec, nullptr);
    const auto off = new_dir - mxpdat_sec->virtual_address;
    ASSERT_LE(off + 24u, mxpdat_sec->data.size());
    const auto* p = mxpdat_sec->data.data() + off;

    std::uint32_t b0 = 0, e0 = 0, u0 = 0;
    std::memcpy(&b0, p +  0, 4);
    std::memcpy(&e0, p +  4, 4);
    std::memcpy(&u0, p +  8, 4);
    std::uint32_t b1 = 0, e1 = 0, u1 = 0;
    std::memcpy(&b1, p + 12, 4);
    std::memcpy(&e1, p + 16, 4);
    std::memcpy(&u1, p + 20, 4);

    // Sorted by BeginAddress: parent-shrunk (covers first sub-block)
    // then chained (covers second sub-block).
    EXPECT_EQ(b0, text_rva);             // first sub-block start
    EXPECT_GE(e0, text_rva + 8u);        // first sub-block end (>= 8)
    EXPECT_EQ(u0, 0x9000u);              // parent's UnwindInfoAddress
    EXPECT_EQ(b1, text_rva + 8u);        // second sub-block start
    EXPECT_GE(e1, text_rva + 16u);       // second sub-block end (>= 16)
    EXPECT_NE(u1, 0x9000u);              // chained UnwindInfoAddress
}

// ---------------------------------------------------------------------------
// Chained UNWIND_INFO blob is well-formed
// ---------------------------------------------------------------------------

TEST(PdataChainEmitter, ChainedUnwindInfoCarriesChainFlag) {
    std::vector<std::uint8_t> text;
    text.resize(0x10000, 0xCC);
    for (std::size_t i = 0; i < 7; ++i)  text[i] = 0x90;
    text[7] = 0xC3;
    for (std::size_t i = 8; i < 15; ++i) text[i] = 0x90;
    text[15] = 0xC3;

    PeImage img = make_pe32plus_image();
    const Rva text_rva = add_text_with_bytes(img, text);

    std::vector<std::uint8_t> pdata;
    append_u32(pdata, text_rva);
    append_u32(pdata, text_rva + 16);
    append_u32(pdata, 0x9000);
    [[maybe_unused]] const auto pd_rva = install_pdata(img, pdata);

    StandardLayout    policy;
    SectionManager    mgr{img};
    SectionEmitter    emitter{mgr, policy};
    PdataChainEmitter chain;
    ASSERT_EQ(chain.emit(img, emitter), 1u);

    // Locate `.mxpdat`, read the chained entry's UnwindInfoAddress,
    // dereference into `.mxchain`, verify the 4-byte header carries
    // `UNW_FLAG_CHAININFO` (Flags bit 0x4 in the high 5 bits of byte 0
    // → `(byte0 >> 3) & 0x1F` == 0x4).
    const Rva mxpdat_dir = exception_dir_rva(img);
    const auto* mxpdat_sec = find_section(img, mxpdat_dir);
    ASSERT_NE(mxpdat_sec, nullptr);
    const auto* p = mxpdat_sec->data.data() +
                    (mxpdat_dir - mxpdat_sec->virtual_address);
    std::uint32_t chained_uwi_rva = 0;
    std::memcpy(&chained_uwi_rva, p + 12 + 8, 4);

    const auto* chain_sec = find_section(img, chained_uwi_rva);
    ASSERT_NE(chain_sec, nullptr);
    const auto chain_off = chained_uwi_rva - chain_sec->virtual_address;
    ASSERT_LE(chain_off + 16u, chain_sec->data.size());
    const auto* uwi = chain_sec->data.data() + chain_off;

    // Version (3 bits) = 1. Flags (5 bits) = UNW_FLAG_CHAININFO = 0x4.
    EXPECT_EQ(uwi[0] & 0x07, 0x01);
    EXPECT_EQ((uwi[0] >> 3) & 0x1F, 0x04);
    EXPECT_EQ(uwi[1], 0); // SizeOfProlog
    EXPECT_EQ(uwi[2], 0); // CountOfCodes
    EXPECT_EQ(uwi[3], 0); // FrameRegister | FrameOffset

    // ChainInfo's UnwindInfoAddress should match the parent's
    // original UnwindInfoAddress so the unwinder still finds the
    // parent's prologue codes after following the chain.
    std::uint32_t chain_unwind = 0;
    std::memcpy(&chain_unwind, uwi + 4 + 8, 4);
    EXPECT_EQ(chain_unwind, 0x9000u);
}

} // namespace
