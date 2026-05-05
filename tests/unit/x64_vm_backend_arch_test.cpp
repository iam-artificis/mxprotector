/**
 * @file x64_vm_backend_arch_test.cpp
 * @brief Unit tests for `vm::x64::X64VmBackend` as an `arch::IVmBackend`.
 *
 * @details Confirms:
 *            * `X64VmBackend` reports the x64 arch family / variant.
 *            * `X64VmBackendFactory::supported_family()` reports x64.
 *            * Factory accepts x64 ArchInfo and returns a working backend.
 *            * Factory rejects non-x64 ArchInfo with a `pass_failed` error.
 *            * The blob produced via the abstract `arch::IVmBackend`
 *              pointer matches (in shape and size) the blob produced via
 *              `VmRuntimeGenerator` — proving the indirection is
 *              behaviour-preserving.
 *            * Empty instruction list returns `vm_translation_error`
 *              (fail-closed contract preserved through the interface).
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/arch/vm_backend.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_backend.hpp"

namespace {

using mx::Randomizer;
using mx::arch::ArchFamily;
using mx::arch::ArchInfo;
using mx::arch::ArchVariant;
using mx::arch::IVmBackend;
using mx::vm::VmGenOptions;
using mx::vm::VmInstruction;
using mx::vm::VmOp;
using mx::vm::VmRuntime;
using mx::vm::VmRuntimeGenerator;
using mx::vm::x64::X64VmBackend;
using mx::vm::x64::X64VmBackendFactory;

std::vector<VmInstruction> make_minimal_body() {
    VmInstruction nop{};
    nop.op = VmOp::native;
    nop.native_bytes = {0x90};
    return {nop};
}

VmGenOptions make_safe_opts() {
    return VmGenOptions{
        .emit_exit_as_jmp        = false,
        .use_imagebase_key       = false,
        .preferred_image_base    = 0,
        .skip_anti_tamper_checks = true,
    };
}

} // namespace

TEST(X64VmBackendArch, ReportsX64Family) {
    X64VmBackend backend;
    EXPECT_EQ(backend.arch().family, ArchFamily::x64);
    EXPECT_EQ(backend.arch().variant, ArchVariant::x64_generic);
}

TEST(X64VmBackendArch, FactorySupportedFamilyIsX64) {
    X64VmBackendFactory factory;
    EXPECT_EQ(factory.supported_family(), ArchFamily::x64);
}

TEST(X64VmBackendArch, FactoryAcceptsX64Info) {
    X64VmBackendFactory factory;
    auto created = factory.create(ArchInfo::x64_baseline());
    ASSERT_TRUE(created.has_value());

    std::unique_ptr<IVmBackend> backend = std::move(*created);
    ASSERT_NE(backend, nullptr);
    EXPECT_EQ(backend->arch().family, ArchFamily::x64);
}

TEST(X64VmBackendArch, FactoryRejectsArm64Info) {
    X64VmBackendFactory factory;
    auto created = factory.create(ArchInfo::arm64_v8a_application());
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error().category(), mx::ErrorCategory::protection);
}

TEST(X64VmBackendArch, AbstractInterfaceProducesValidBlob) {
    X64VmBackendFactory factory;
    auto created = factory.create(ArchInfo::x64_baseline());
    ASSERT_TRUE(created.has_value());

    std::unique_ptr<IVmBackend> backend = std::move(*created);
    Randomizer rng{0xC0FFEEull};

    auto runtime = backend->generate(make_minimal_body(), rng, make_safe_opts());
    ASSERT_TRUE(runtime.has_value());

    EXPECT_FALSE(runtime->blob.empty());
    EXPECT_GT(runtime->handler_count, 0u);
    EXPECT_LT(runtime->bytecode_offset, runtime->blob.size());
    EXPECT_LE(runtime->bytecode_offset + runtime->bytecode_size,
              runtime->blob.size());
}

TEST(X64VmBackendArch, FacadeAndDirectBackendAgree) {
    Randomizer rng_facade{0xD150D150ull};
    Randomizer rng_direct{0xD150D150ull};

    auto facade_runtime = VmRuntimeGenerator{}.generate(
        make_minimal_body(), rng_facade, make_safe_opts());
    ASSERT_TRUE(facade_runtime.has_value());

    X64VmBackend backend;
    auto direct_runtime = backend.generate(
        make_minimal_body(), rng_direct, make_safe_opts());
    ASSERT_TRUE(direct_runtime.has_value());

    EXPECT_EQ(facade_runtime->blob.size(), direct_runtime->blob.size());
    EXPECT_EQ(facade_runtime->blob,        direct_runtime->blob);
    EXPECT_EQ(facade_runtime->entry_offset, direct_runtime->entry_offset);
    EXPECT_EQ(facade_runtime->handler_count, direct_runtime->handler_count);
}

TEST(X64VmBackendArch, RejectsEmptyInstructionList) {
    X64VmBackendFactory factory;
    auto created = factory.create(ArchInfo::x64_baseline());
    ASSERT_TRUE(created.has_value());

    std::unique_ptr<IVmBackend> backend = std::move(*created);
    Randomizer rng{0x12345678ull};

    auto runtime = backend->generate({}, rng, make_safe_opts());
    ASSERT_FALSE(runtime.has_value());
    EXPECT_EQ(runtime.error().code(),
              static_cast<uint16_t>(
                  mx::ProtectionErrorCode::vm_translation_error));
}
