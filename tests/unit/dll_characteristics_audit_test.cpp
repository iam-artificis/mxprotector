/**
 * @file dll_characteristics_audit_test.cpp
 * @brief [TESTS] Pure-function bit policy for the packer's
 *        `DllCharacteristics` audit.
 *
 * Every rule in `audit_dll_characteristics` is checked here in
 * isolation — no `PeImage`, no `ProtectionContext`, no file I/O.
 * That keeps the invariants easy to pin: the pure policy either
 * clears a specific bit or it does not.
 *
 * A guard test at the top also cross-checks that the literal
 * constants the header uses (`0x4000` for `GUARD_CF`, `0x0080` for
 * `FORCE_INTEGRITY`) stay in sync with the authoritative
 * `pe_types.hpp` definitions — renaming or repurposing one of those
 * constants must fail this test loudly.
 */

#include <gtest/gtest.h>

#include <cstdint>

#include "mxprotector/core/types.hpp"  // ByteBuffer — pe_types.hpp's
                                        // SectionInfo uses it in
                                        // struct-body position, and
                                        // the PE header defers its
                                        // own include to the tail.
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/packer/dll_characteristics_audit.hpp"

namespace {

using mx::packer::audit_dll_characteristics;

// --------------------------------------------------------------------
// Constants cross-check
// --------------------------------------------------------------------

TEST(DllCharacteristicsAudit, ConstantsMatchPeTypes) {
    EXPECT_EQ(mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF,        0x4000u);
    EXPECT_EQ(mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, 0x0080u);
}

// --------------------------------------------------------------------
// GUARD_CF is cleared unconditionally
// --------------------------------------------------------------------

TEST(DllCharacteristicsAudit, ClearsGuardCfForExecutable) {
    const auto r = audit_dll_characteristics(
        mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        /*is_kernel_driver=*/false);
    EXPECT_EQ(r.output, 0u);
    EXPECT_EQ(r.cleared, mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF);
}

TEST(DllCharacteristicsAudit, ClearsGuardCfForDynamicLibrary) {
    // The policy does not distinguish EXE from DLL; both paths only
    // care about `is_kernel_driver`. Still worth pinning so a future
    // refactor that splits them does not silently drop this case.
    const auto r = audit_dll_characteristics(
        mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        /*is_kernel_driver=*/false);
    EXPECT_EQ(r.output, 0u);
    EXPECT_EQ(r.cleared, mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF);
}

TEST(DllCharacteristicsAudit, ClearsGuardCfForKernelDriver) {
    const auto r = audit_dll_characteristics(
        mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        /*is_kernel_driver=*/true);
    EXPECT_EQ(r.output, 0u);
    EXPECT_EQ(r.cleared, mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF);
}

// --------------------------------------------------------------------
// FORCE_INTEGRITY cleared ONLY for kernel driver
// --------------------------------------------------------------------

TEST(DllCharacteristicsAudit, PreservesForceIntegrityForUserMode) {
    const auto r = audit_dll_characteristics(
        mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
        /*is_kernel_driver=*/false);
    EXPECT_EQ(r.output, mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
    EXPECT_EQ(r.cleared, 0u);
}

TEST(DllCharacteristicsAudit, ClearsForceIntegrityForKernelDriver) {
    const auto r = audit_dll_characteristics(
        mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
        /*is_kernel_driver=*/true);
    EXPECT_EQ(r.output, 0u);
    EXPECT_EQ(r.cleared, mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
}

// --------------------------------------------------------------------
// Combined bits + "leave everything else alone"
// --------------------------------------------------------------------

TEST(DllCharacteristicsAudit, ClearsBothForKernelDriver) {
    const uint16_t input =
        mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF |
        mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
    const auto r = audit_dll_characteristics(input, /*is_kernel_driver=*/true);
    EXPECT_EQ(r.output,  0u);
    EXPECT_EQ(r.cleared, input);
}

TEST(DllCharacteristicsAudit, UserModeClearsOnlyGuardCfWhenBothSet) {
    const uint16_t input =
        mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF |
        mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
    const auto r = audit_dll_characteristics(input, /*is_kernel_driver=*/false);
    EXPECT_EQ(r.output,  mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
    EXPECT_EQ(r.cleared, mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF);
}

TEST(DllCharacteristicsAudit, LeavesUnrelatedBitsIntact) {
    // DYNAMIC_BASE (0x0040), NX_COMPAT (0x0100), NO_SEH (0x0400),
    // HIGH_ENTROPY_VA (0x0020 — not defined here but the policy
    // must not touch unknown bits either). Input has everything.
    constexpr uint16_t kEverything = 0xFFFF;
    const auto r_user =
        audit_dll_characteristics(kEverything, /*is_kernel_driver=*/false);
    // Only GUARD_CF must come off; everything else stays.
    EXPECT_EQ(r_user.cleared, mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    EXPECT_EQ(r_user.output,
              static_cast<uint16_t>(kEverything &
                  ~mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF));

    const auto r_drv =
        audit_dll_characteristics(kEverything, /*is_kernel_driver=*/true);
    // GUARD_CF + FORCE_INTEGRITY come off; the rest stays.
    const uint16_t expected_cleared =
        mx::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF |
        mx::pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
    EXPECT_EQ(r_drv.cleared, expected_cleared);
    EXPECT_EQ(r_drv.output,
              static_cast<uint16_t>(kEverything & ~expected_cleared));
}

TEST(DllCharacteristicsAudit, NoOpWhenNoRelevantBitsSet) {
    // An input that does not carry either managed bit stays bit-for-
    // bit identical on output. The orchestrator uses this to stay
    // silent when there is nothing to log.
    constexpr uint16_t kInput =
        mx::pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        mx::pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    const auto r_user = audit_dll_characteristics(kInput, false);
    EXPECT_EQ(r_user.output,  kInput);
    EXPECT_EQ(r_user.cleared, 0u);

    const auto r_drv = audit_dll_characteristics(kInput, true);
    EXPECT_EQ(r_drv.output,  kInput);
    EXPECT_EQ(r_drv.cleared, 0u);
}

// --------------------------------------------------------------------
// Constexpr sanity — audit_dll_characteristics is usable at compile
// time. A static_assert here catches any accidental loss of
// `constexpr` in the header.
// --------------------------------------------------------------------

TEST(DllCharacteristicsAudit, IsConstexprEvaluable) {
    constexpr auto r =
        audit_dll_characteristics(0x4080, /*is_kernel_driver=*/true);
    static_assert(r.output == 0u,
                  "GUARD_CF + FORCE_INTEGRITY on a driver should mask to 0");
    static_assert(r.cleared == 0x4080u,
                  "Both bits should be reported as cleared for the driver path");
    SUCCEED();  // reaching here means the constexpr path compiled
}

} // namespace
