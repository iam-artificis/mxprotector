/**
 * @file driver_cipher_body_test.cpp
 * @brief [TESTS] Structural + kernel-safety invariants of the
 *        kernel-driver cipher body.
 *
 * The driver body is a deliberately thin shell around the shared
 * `emit_multi_layer_decrypt` (covered by its own byte tests via the
 * surrounding user-mode body). These tests pin the *driver-specific*
 * properties:
 *
 *   1. The stub bytes are produced and non-empty.
 *   2. `DriverStubPatches` records the slots the driver-specific
 *      patcher needs (per-layer key + section LEAs, shared sbox
 *      LEA, KSA block markers, optional reloc applier patches),
 *      and leaves the user-mode-only slots at zero.
 *   3. The emitted stub does NOT contain `mov rax, gs:[0x60]`
 *      (`65 48 8B 04 25 60 00 00 00`) — that signature appears in
 *      the user-mode anti-debug probe and the Hell's Gate resolver
 *      both, neither of which the driver body emits. A regression
 *      that re-introduces either path would surface here.
 *   4. The reloc-applier opt-in flag actually drives whether the
 *      `RelocApplierPatches` are populated.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"

namespace {

using mx::Randomizer;
using mx::ByteView;
using mx::packer::build_driver_stub_bytes;
using mx::packer::DriverStubPatches;

// Same signature we use in vm_kernel_safety_test — `mov rax, gs:[0x60]`.
// Driver path must never emit it.
constexpr std::array<uint8_t, 9> kPebFetchPattern = {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
};

bool blob_contains(const mx::ByteBuffer& haystack,
                   const std::array<uint8_t, 9>& needle)
{
    return std::search(haystack.begin(), haystack.end(),
                       needle.begin(), needle.end()) != haystack.end();
}

TEST(DriverCipherBody, EmitsNonEmptyStub) {
    Randomizer rng{0x5151ull};
    auto [bytes, patches] = build_driver_stub_bytes(
        rng, ByteView{}, /*section_count=*/1, /*layer_count=*/1,
        /*apply_relocs_inline=*/false);
    EXPECT_FALSE(bytes.empty());
    // 10 push prologue (16 bytes) + thin cipher body + 10 pop epilogue
    // (16 bytes) + 5-byte jmp rel32. The cipher body is dominated by
    // the multi-layer KSA+PRGA loops which are several hundred bytes
    // even at 1/1; sanity-check that we cleared a generous floor.
    EXPECT_GT(bytes.size(), 200u);
}

TEST(DriverCipherBody, PatchesPopulateSharedSlotsOnly) {
    Randomizer rng{0x5151ull};
    auto [bytes, patches] = build_driver_stub_bytes(
        rng, ByteView{}, /*section_count=*/2, /*layer_count=*/2,
        /*apply_relocs_inline=*/false);

    // Multi-layer decrypt populates per-layer + shared sbox slots.
    ASSERT_EQ(patches.layers.size(), 2u);
    EXPECT_GT(patches.rel_to_sbox_at, 0u);
    EXPECT_GT(patches.ksa_block_start_offset, 0u);
    EXPECT_GT(patches.ksa_block_end_offset,
              patches.ksa_block_start_offset);

    for (const auto& lp : patches.layers) {
        EXPECT_GT(lp.rel_to_key_at, 0u);
        EXPECT_EQ(lp.sections.size(), 2u);
        for (const auto& ds : lp.sections) {
            EXPECT_GT(ds.patch_lea_at, 0u);
            EXPECT_GT(ds.patch_size_at, 0u);
        }
    }

    // Common stub slots: stolen bytes offset + final jmp rel32.
    EXPECT_GT(patches.stolen_bytes_offset, 0u);
    EXPECT_GT(patches.rel_to_oep_at, 0u);

    // User-mode-only slots stay at their zero defaults — the driver
    // body never emits the reprotect / IAT-wipe / imagebase blocks.
    EXPECT_EQ(patches.rel_to_impdir_at,            0u);
    EXPECT_EQ(patches.impdir_size_at,              0u);
    EXPECT_EQ(patches.rel_to_reprotect_table_at,   0u);
    EXPECT_EQ(patches.imagebase_lea_anchor_offset, 0u);
    EXPECT_EQ(patches.imagebase_sub_imm32_at,      0u);
}

TEST(DriverCipherBody, NoPebFetchSignature) {
    Randomizer rng{0x5151ull};
    auto [bytes, patches] = build_driver_stub_bytes(
        rng, ByteView{}, /*section_count=*/3, /*layer_count=*/2,
        /*apply_relocs_inline=*/false);

    EXPECT_FALSE(blob_contains(bytes, kPebFetchPattern))
        << "Driver stub unexpectedly contains `mov rax, gs:[0x60]`. "
           "Either an anti-debug probe variant or a Hell's Gate "
           "resolver leaked into the driver path — both are user-mode "
           "only and would crash in ring0.";
}

TEST(DriverCipherBody, NoPebFetchAcrossSeeds) {
    // Defence in depth — try a handful of distinct seeds because the
    // hash opaque predicate, key derivation, and section count vary
    // emitted bytes per build.
    constexpr std::array<uint64_t, 5> kSeeds = {
        0x1ull, 0xCAFEull, 0xDEADBEEFull, 0xBAADF00Dull, 0xFFFFull,
    };
    for (uint64_t seed : kSeeds) {
        Randomizer rng{seed};
        auto [bytes, patches] = build_driver_stub_bytes(
            rng, ByteView{}, /*section_count=*/2, /*layer_count=*/3,
            /*apply_relocs_inline=*/true);
        EXPECT_FALSE(blob_contains(bytes, kPebFetchPattern))
            << "Driver stub built with seed 0x" << std::hex << seed
            << " contains the user-mode PEB fetch signature.";
    }
}

TEST(DriverCipherBody, RelocApplierPopulatedOnlyWhenOpted) {
    Randomizer rng_off{0x42ull};
    auto [bytes_off, patches_off] = build_driver_stub_bytes(
        rng_off, ByteView{}, /*section_count=*/1, /*layer_count=*/1,
        /*apply_relocs_inline=*/false);

    // Default-constructed reloc patches have begin==end==0.
    EXPECT_EQ(patches_off.reloc_applier.applier_begin_offset, 0u);
    EXPECT_EQ(patches_off.reloc_applier.applier_end_offset,   0u);

    Randomizer rng_on{0x42ull};
    auto [bytes_on, patches_on] = build_driver_stub_bytes(
        rng_on, ByteView{}, /*section_count=*/1, /*layer_count=*/1,
        /*apply_relocs_inline=*/true);

    EXPECT_GT(patches_on.reloc_applier.applier_end_offset,
              patches_on.reloc_applier.applier_begin_offset);
    EXPECT_GT(patches_on.reloc_applier.preferred_base_imm64_at, 0u);
    EXPECT_GT(patches_on.reloc_applier.reloc_rva_imm32_at,      0u);
    EXPECT_GT(patches_on.reloc_applier.reloc_size_imm32_at,     0u);

    // Opting in adds exactly the applier's footprint to the stub.
    EXPECT_EQ(bytes_on.size(),
              bytes_off.size() +
              mx::packer::kRelocApplierEmittedSize);
}

} // namespace
