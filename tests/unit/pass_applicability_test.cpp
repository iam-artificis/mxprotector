/**
 * @file pass_applicability_test.cpp
 * @brief [TESTS] Target-based gates on `IProtectionPass::is_applicable`.
 *
 * These tests pin the Stage 1 / Stage 2 applicability gates introduced
 * for `.sys` / driver support:
 *
 *   - `GuardPass` skips kernel-driver targets (no user-mode VEH).
 *   - `PackerPass` skips kernel-driver targets (needs a dedicated
 *      DriverEntry stub that does not exist yet).
 *   - `StringProtectionPass` *accepts* kernel-driver targets after the
 *      Stage 2 audit cleared the decryptor (pure XOR / `lock xadd` /
 *      VM core, no PEB or Hell's Gate). The gate that lived here in
 *      Stage 1 has been removed.
 *
 * The positive cases (executable / dynamic_library) confirm that the
 * gates do not over-reject — each pass still returns true for the
 * ordinary user-mode x64 PE target when its own preconditions are met.
 *
 * We deliberately construct a bare-bones `ProtectionContext` — a
 * default-constructed `PeImage`, a minimal `ProtectionConfig`, and a
 * null disassembler. `is_applicable()` never touches the image or
 * disassembler, so the fixture stays trivial and the gate becomes the
 * only thing under test.
 */

#include <gtest/gtest.h>

#include <memory>

#include "mxprotector/config/protection_config.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/target/target_info.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/guard/guard_pass.hpp"
#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/protection/string/string_protection_pass.hpp"
#include "mxprotector/protection/vm/virtualization_pass.hpp"

namespace {

using mx::target::BinaryKind;
using mx::target::binary_kind_name;
using mx::target::LoadMode;

mx::target::TargetInfo make_target(BinaryKind kind,
                                    LoadMode mode = LoadMode::os_loaded) {
    return mx::target::TargetInfo{
        .os        = mx::target::Os::windows,
        .container = mx::target::ContainerFormat::pe,
        .arch      = mx::target::Arch::x64,
        .kind      = kind,
        .load_mode = mode,
    };
}

mx::ProtectionContext make_ctx(BinaryKind kind,
                                LoadMode mode = LoadMode::os_loaded,
                                mx::Architecture arch = mx::Architecture::x64)
{
    auto img = std::make_unique<mx::PeImage>();
    img->set_architecture(arch);

    mx::ProtectionConfig cfg;
    cfg.enable_packer          = true;
    cfg.enable_mutation        = true;
    cfg.enable_obfuscation     = true;
    cfg.enable_vm              = true;
    cfg.enable_cfg_flattening  = true;
    cfg.string_protection      = mx::StringProtectionMode::stub;

    mx::ProtectionContext ctx(std::move(img), std::move(cfg), nullptr);

    // Seed both guard and VM markers so the marker-driven passes
    // (GuardPass, VirtualizationPass) can return true when their
    // target gate accepts. No-op for passes that don't filter by
    // marker presence.
    ctx.markers().push_back(mx::MarkedRegion{
        .type              = mx::MarkerType::guard_begin,
        .start_rva         = 0,
        .end_rva           = 0x10,
        .section_index     = 0,
        .begin_marker_size = 0,
        .end_marker_size   = 0,
    });
    ctx.markers().push_back(mx::MarkedRegion{
        .type              = mx::MarkerType::vm_begin,
        .start_rva         = 0x100,
        .end_rva           = 0x110,
        .section_index     = 0,
        .begin_marker_size = 0,
        .end_marker_size   = 0,
    });

    auto info = make_target(kind, mode);
    info.arch = (arch == mx::Architecture::x64)
                  ? mx::target::Arch::x64
                  : mx::target::Arch::x86;
    ctx.set_target(info);
    return ctx;
}

// --------------------------------------------------------------------
// GuardPass — VEH is a user-mode-only Win32 facility.
// --------------------------------------------------------------------

TEST(PassApplicability, GuardPassSkipsKernelDriver) {
    auto ctx = make_ctx(BinaryKind::kernel_driver);
    mx::GuardPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

TEST(PassApplicability, GuardPassSkipsEfiApplication) {
    // VEH does not exist in UEFI: no OS user-mode loader, no PEB,
    // no `RtlAddVectoredExceptionHandler`. The pass MUST reject EFI
    // before any guard markers are inspected.
    auto ctx = make_ctx(BinaryKind::efi_application);
    mx::GuardPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

TEST(PassApplicability, GuardPassAcceptsExecutable) {
    auto ctx = make_ctx(BinaryKind::executable);
    mx::GuardPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, GuardPassAcceptsDynamicLibrary) {
    auto ctx = make_ctx(BinaryKind::dynamic_library);
    mx::GuardPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

// --------------------------------------------------------------------
// StringProtectionPass
// --------------------------------------------------------------------

// Stage 2 audit lifted the kernel-driver gate. The pass should now
// accept *all* PE x64 targets when the user enabled string protection.
// `make_ctx` already sets `string_protection = stub`.
TEST(PassApplicability, StringProtectionAcceptsKernelDriver) {
    auto ctx = make_ctx(BinaryKind::kernel_driver);
    mx::StringProtectionPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, StringProtectionAcceptsExecutable) {
    auto ctx = make_ctx(BinaryKind::executable);
    mx::StringProtectionPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, StringProtectionAcceptsDynamicLibrary) {
    auto ctx = make_ctx(BinaryKind::dynamic_library);
    mx::StringProtectionPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, StringProtectionSkipsWhenDisabled) {
    auto ctx = make_ctx(BinaryKind::kernel_driver);
    ctx.config().string_protection = mx::StringProtectionMode::disabled;
    mx::StringProtectionPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

// --------------------------------------------------------------------
// PackerPass
// --------------------------------------------------------------------

// Stage 3.C lifted the kernel-driver gate. The packer now dispatches
// to `DriverStubEmitter` (see `driver_cipher_body.hpp`) which emits a
// ring0-safe cipher body — no anti-debug PEB read, no Hell's Gate, no
// `NtProtectVirtualMemory`, no IAT wipe. Drivers should be accepted
// at the same shape as EXEs and DLLs.
TEST(PassApplicability, PackerPassAcceptsKernelDriver) {
    auto ctx = make_ctx(BinaryKind::kernel_driver);
    mx::PackerPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, PackerPassAcceptsExecutable) {
    auto ctx = make_ctx(BinaryKind::executable);
    mx::PackerPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, PackerPassAcceptsDynamicLibrary) {
    auto ctx = make_ctx(BinaryKind::dynamic_library);
    mx::PackerPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

TEST(PassApplicability, PackerPassAcceptsEfiApplication) {
    // Feature C — EFI now has a dedicated `EfiStubEmitter` that
    // shares the driver cipher body (no Win32 IAT, no TLS, no VEH,
    // no anti-debug user-mode tricks). UEFI applications should
    // therefore pass the applicability gate; `execute()` dispatches
    // them to the EFI emitter.
    auto ctx = make_ctx(BinaryKind::efi_application);
    mx::PackerPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

// --------------------------------------------------------------------
// Manual-mapped load mode is an independent axis — it must not itself
// cause applicability gates to trip on user-mode kinds in Stage 1.
// (Stage 3 will introduce packer-side manual-map handling; for now the
// packer runs whether or not the output will be manually mapped.)
// --------------------------------------------------------------------

TEST(PassApplicability, ManualMappedExecutableStillAcceptsPacker) {
    auto ctx = make_ctx(BinaryKind::executable, LoadMode::manual_mapped);
    mx::PackerPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

// Stage 3.C: manual-mapped kernel driver — combines both
// orthogonal opt-ins. PackerPass should accept it (the dispatch
// picks DriverStubEmitter, the reloc applier is enabled).
TEST(PassApplicability, ManualMappedKernelDriverAccepted) {
    auto ctx = make_ctx(BinaryKind::kernel_driver, LoadMode::manual_mapped);
    mx::PackerPass pass;
    EXPECT_TRUE(pass.is_applicable(ctx));
}

// --------------------------------------------------------------------
// MutationPass / ObfuscationPass / CfgFlatteningPass /
// VirtualizationPass — all four are now gated on is_windows_pe_x64()
// so non-x64 inputs (and non-PE in the future) skip cleanly without
// engaging the x86/x64-only emitters.
// --------------------------------------------------------------------

TEST(PassApplicability, MutationPassAcceptsAllPeKinds) {
    for (auto kind : {BinaryKind::executable,
                      BinaryKind::dynamic_library,
                      BinaryKind::kernel_driver,
                      BinaryKind::efi_application}) {
        auto ctx = make_ctx(kind);
        mx::MutationPass pass;
        EXPECT_TRUE(pass.is_applicable(ctx))
            << "MutationPass must accept " << binary_kind_name(kind);
    }
}

TEST(PassApplicability, MutationPassRejectsX86Architecture) {
    auto ctx = make_ctx(BinaryKind::executable,
                        LoadMode::os_loaded,
                        mx::Architecture::x86);
    mx::MutationPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

TEST(PassApplicability, MutationPassRejectsWhenDisabled) {
    auto ctx = make_ctx(BinaryKind::executable);
    ctx.config().enable_mutation = false;
    mx::MutationPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

TEST(PassApplicability, ObfuscationPassAcceptsAllPeKinds) {
    for (auto kind : {BinaryKind::executable,
                      BinaryKind::dynamic_library,
                      BinaryKind::kernel_driver,
                      BinaryKind::efi_application}) {
        auto ctx = make_ctx(kind);
        mx::ObfuscationPass pass;
        EXPECT_TRUE(pass.is_applicable(ctx))
            << "ObfuscationPass must accept " << binary_kind_name(kind);
    }
}

TEST(PassApplicability, ObfuscationPassRejectsX86Architecture) {
    auto ctx = make_ctx(BinaryKind::executable,
                        LoadMode::os_loaded,
                        mx::Architecture::x86);
    mx::ObfuscationPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

TEST(PassApplicability, CfgFlatteningPassAcceptsAllPeKinds) {
    for (auto kind : {BinaryKind::executable,
                      BinaryKind::dynamic_library,
                      BinaryKind::kernel_driver,
                      BinaryKind::efi_application}) {
        auto ctx = make_ctx(kind);
        mx::CfgFlatteningPass pass;
        EXPECT_TRUE(pass.is_applicable(ctx))
            << "CfgFlatteningPass must accept " << binary_kind_name(kind);
    }
}

TEST(PassApplicability, CfgFlatteningPassRejectsX86Architecture) {
    auto ctx = make_ctx(BinaryKind::executable,
                        LoadMode::os_loaded,
                        mx::Architecture::x86);
    mx::CfgFlatteningPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

TEST(PassApplicability, VirtualizationPassAcceptsAllPeKindsWithMarker) {
    for (auto kind : {BinaryKind::executable,
                      BinaryKind::dynamic_library,
                      BinaryKind::kernel_driver,
                      BinaryKind::efi_application}) {
        auto ctx = make_ctx(kind);
        mx::VirtualizationPass pass;
        EXPECT_TRUE(pass.is_applicable(ctx))
            << "VirtualizationPass must accept " << binary_kind_name(kind)
            << " when a vm_begin marker is present";
    }
}

TEST(PassApplicability, VirtualizationPassRejectsX86Architecture) {
    auto ctx = make_ctx(BinaryKind::executable,
                        LoadMode::os_loaded,
                        mx::Architecture::x86);
    mx::VirtualizationPass pass;
    EXPECT_FALSE(pass.is_applicable(ctx));
}

} // namespace
