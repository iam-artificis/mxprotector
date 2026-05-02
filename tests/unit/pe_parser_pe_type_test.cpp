/**
 * @file pe_parser_pe_type_test.cpp
 * @brief [TESTS] Pin the `PeParser::detect_pe_type` mapping from raw
 *        PE header fields to the `PeType` enum.
 *
 * Coverage:
 *   - User-mode EXE (Subsystem WINDOWS_GUI/CUI, no DLL bit) →
 *     PeType::executable.
 *   - User-mode DLL (DLL bit set) → PeType::dynamic_library.
 *   - Driver (Subsystem NATIVE) → PeType::kernel_driver.
 *   - Every UEFI subsystem (10..13) → PeType::efi_application,
 *     including the nasty case where the DLL characteristics bit is
 *     also set (common on EFI runtime drivers and EFI ROMs).
 *   - Subsystem-driven kinds outrank the DLL bit — without that
 *     ordering UEFI binaries with the DLL bit would silently parse
 *     as user-mode dynamic libraries.
 */

#include <gtest/gtest.h>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_parser.hpp"
#include "mxprotector/pe/pe_types.hpp"

using mx::PeType;
using mx::PeParser;

namespace pe = mx::pe;

namespace {

// ---------------------------------------------------------------------------
// User-mode mappings
// ---------------------------------------------------------------------------

TEST(PeParserPeType, WindowsGuiExeIsExecutable) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  /*characteristics=*/0,
                  pe::IMAGE_SUBSYSTEM_WINDOWS_GUI),
              PeType::executable);
}

TEST(PeParserPeType, WindowsCuiExeIsExecutable) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  /*characteristics=*/0,
                  pe::IMAGE_SUBSYSTEM_WINDOWS_CUI),
              PeType::executable);
}

TEST(PeParserPeType, DllBitMakesItDynamicLibrary) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  pe::IMAGE_FILE_DLL,
                  pe::IMAGE_SUBSYSTEM_WINDOWS_GUI),
              PeType::dynamic_library);
}

// ---------------------------------------------------------------------------
// Kernel driver
// ---------------------------------------------------------------------------

TEST(PeParserPeType, NativeSubsystemIsKernelDriver) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  pe::IMAGE_FILE_DLL,
                  pe::IMAGE_SUBSYSTEM_NATIVE),
              PeType::kernel_driver);
}

// ---------------------------------------------------------------------------
// UEFI — all four variants must collapse to efi_application
// ---------------------------------------------------------------------------

TEST(PeParserPeType, EfiApplicationSubsystemIsEfi) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  /*characteristics=*/0,
                  pe::IMAGE_SUBSYSTEM_EFI_APPLICATION),
              PeType::efi_application);
}

TEST(PeParserPeType, EfiBootServiceDriverSubsystemIsEfi) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  /*characteristics=*/0,
                  pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER),
              PeType::efi_application);
}

TEST(PeParserPeType, EfiRuntimeDriverSubsystemIsEfi) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  /*characteristics=*/0,
                  pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER),
              PeType::efi_application);
}

TEST(PeParserPeType, EfiRomSubsystemIsEfi) {
    EXPECT_EQ(PeParser::detect_pe_type(
                  /*characteristics=*/0,
                  pe::IMAGE_SUBSYSTEM_EFI_ROM),
              PeType::efi_application);
}

TEST(PeParserPeType, EfiSubsystemOutranksDllBit) {
    // Real-world UEFI drivers commonly carry IMAGE_FILE_DLL alongside
    // an EFI subsystem. Without the subsystem-first ordering they
    // would silently parse as `dynamic_library` and engage user-mode
    // passes that have no business running on UEFI.
    EXPECT_EQ(PeParser::detect_pe_type(
                  pe::IMAGE_FILE_DLL,
                  pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER),
              PeType::efi_application);
    EXPECT_EQ(PeParser::detect_pe_type(
                  pe::IMAGE_FILE_DLL,
                  pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER),
              PeType::efi_application);
}

// ---------------------------------------------------------------------------
// is_efi_subsystem helper
// ---------------------------------------------------------------------------

TEST(PeParserPeType, IsEfiSubsystemRecognisesAllFourVariants) {
    EXPECT_TRUE(pe::is_efi_subsystem(pe::IMAGE_SUBSYSTEM_EFI_APPLICATION));
    EXPECT_TRUE(pe::is_efi_subsystem(
        pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER));
    EXPECT_TRUE(pe::is_efi_subsystem(
        pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER));
    EXPECT_TRUE(pe::is_efi_subsystem(pe::IMAGE_SUBSYSTEM_EFI_ROM));
}

TEST(PeParserPeType, IsEfiSubsystemRejectsNonEfiSubsystems) {
    EXPECT_FALSE(pe::is_efi_subsystem(pe::IMAGE_SUBSYSTEM_UNKNOWN));
    EXPECT_FALSE(pe::is_efi_subsystem(pe::IMAGE_SUBSYSTEM_NATIVE));
    EXPECT_FALSE(pe::is_efi_subsystem(pe::IMAGE_SUBSYSTEM_WINDOWS_GUI));
    EXPECT_FALSE(pe::is_efi_subsystem(pe::IMAGE_SUBSYSTEM_WINDOWS_CUI));
    // Past EFI_ROM (13) — should not match.
    EXPECT_FALSE(pe::is_efi_subsystem(14));
}

} // namespace
