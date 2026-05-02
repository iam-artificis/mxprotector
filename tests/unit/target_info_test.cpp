/**
 * @file target_info_test.cpp
 * @brief [TESTS] Predicate surface of `target::TargetInfo`.
 *
 * These tests pin the predicates that passes rely on to gate their
 * applicability. They do not exercise any pipeline behaviour — that
 * lives in `pass_applicability_test.cpp`.
 */

#include <gtest/gtest.h>

#include "mxprotector/target/target_info.hpp"

using mx::target::Arch;
using mx::target::BinaryKind;
using mx::target::ContainerFormat;
using mx::target::LoadMode;
using mx::target::Os;
using mx::target::TargetInfo;

TEST(TargetInfoTest, WindowsPeX64FactoryDefaults) {
    constexpr auto t = TargetInfo::windows_pe_x64();
    EXPECT_TRUE(t.is_windows());
    EXPECT_TRUE(t.is_pe());
    EXPECT_TRUE(t.is_x64());
    EXPECT_TRUE(t.is_windows_pe_x64());
    EXPECT_TRUE(t.is_executable());
    EXPECT_FALSE(t.is_dynamic_library());
    EXPECT_FALSE(t.is_kernel_driver());
    EXPECT_TRUE(t.is_user_mode());
    EXPECT_TRUE(t.is_os_loaded());
    EXPECT_FALSE(t.is_manually_mapped());
}

TEST(TargetInfoTest, KernelDriverIsNotUserMode) {
    TargetInfo t = TargetInfo::windows_pe_x64();
    t.kind = BinaryKind::kernel_driver;
    EXPECT_TRUE(t.is_kernel_driver());
    EXPECT_FALSE(t.is_executable());
    EXPECT_FALSE(t.is_dynamic_library());
    EXPECT_FALSE(t.is_user_mode());
    EXPECT_TRUE(t.is_windows_pe_x64()); // arch/os/container unchanged
}

TEST(TargetInfoTest, DynamicLibraryIsUserMode) {
    TargetInfo t = TargetInfo::windows_pe_x64();
    t.kind = BinaryKind::dynamic_library;
    EXPECT_TRUE(t.is_dynamic_library());
    EXPECT_TRUE(t.is_user_mode());
    EXPECT_FALSE(t.is_executable());
    EXPECT_FALSE(t.is_kernel_driver());
}

TEST(TargetInfoTest, ManualMappedOverridesLoadMode) {
    TargetInfo t = TargetInfo::windows_pe_x64();
    t.load_mode = LoadMode::manual_mapped;
    EXPECT_TRUE(t.is_manually_mapped());
    EXPECT_FALSE(t.is_os_loaded());
}

TEST(TargetInfoTest, UnknownKindMatchesNothing) {
    TargetInfo t = TargetInfo::windows_pe_x64();
    t.kind = BinaryKind::unknown;
    EXPECT_FALSE(t.is_executable());
    EXPECT_FALSE(t.is_dynamic_library());
    EXPECT_FALSE(t.is_kernel_driver());
    EXPECT_FALSE(t.is_efi());
    EXPECT_FALSE(t.is_user_mode());
}

TEST(TargetInfoTest, EfiApplicationIsNotUserModeAndNotKernelDriver) {
    // EFI binaries get is_efi() / is_efi_application() but must NOT
    // match is_user_mode() (no Win32 PEB/IAT) or is_kernel_driver()
    // (no ring0 dispatch). Every gate that today guards on
    // !is_kernel_driver() must therefore *also* guard on !is_efi()
    // — the dedicated predicate exists so that intent is explicit.
    TargetInfo t = TargetInfo::windows_pe_x64();
    t.kind = BinaryKind::efi_application;
    EXPECT_TRUE(t.is_efi());
    EXPECT_TRUE(t.is_efi_application());
    EXPECT_FALSE(t.is_user_mode());
    EXPECT_FALSE(t.is_executable());
    EXPECT_FALSE(t.is_dynamic_library());
    EXPECT_FALSE(t.is_kernel_driver());
}

TEST(TargetInfoTest, EfiPredicateIsFalseForOtherKinds) {
    // is_efi() must NOT leak into the user-mode kinds; if it did,
    // every existing user-mode gate would silently accept EFI.
    TargetInfo t = TargetInfo::windows_pe_x64();
    EXPECT_FALSE(t.is_efi());
    t.kind = BinaryKind::dynamic_library;
    EXPECT_FALSE(t.is_efi());
    t.kind = BinaryKind::kernel_driver;
    EXPECT_FALSE(t.is_efi());
}

TEST(TargetInfoTest, BinaryKindNames) {
    EXPECT_STREQ(mx::target::binary_kind_name(BinaryKind::executable),
                 "executable");
    EXPECT_STREQ(mx::target::binary_kind_name(BinaryKind::dynamic_library),
                 "dynamic_library");
    EXPECT_STREQ(mx::target::binary_kind_name(BinaryKind::kernel_driver),
                 "kernel_driver");
    EXPECT_STREQ(mx::target::binary_kind_name(BinaryKind::efi_application),
                 "efi_application");
    EXPECT_STREQ(mx::target::binary_kind_name(BinaryKind::unknown),
                 "unknown");
}

TEST(TargetInfoTest, LoadModeNames) {
    EXPECT_STREQ(mx::target::load_mode_name(LoadMode::os_loaded),
                 "os_loaded");
    EXPECT_STREQ(mx::target::load_mode_name(LoadMode::manual_mapped),
                 "manual_mapped");
}

TEST(TargetInfoTest, EqualityIncludesKindAndLoadMode) {
    auto a = TargetInfo::windows_pe_x64();
    auto b = TargetInfo::windows_pe_x64();
    EXPECT_EQ(a, b);

    b.kind = BinaryKind::kernel_driver;
    EXPECT_NE(a, b);

    b = TargetInfo::windows_pe_x64();
    b.load_mode = LoadMode::manual_mapped;
    EXPECT_NE(a, b);
}
