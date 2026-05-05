/**
 * @file x64_pe_stub_backend_test.cpp
 * @brief Unit tests for `packer::X64PeStubBackend` and its factory.
 *
 * @details Confirms:
 *            * Backend identity reports x64 family + PE container.
 *            * Factory rejects mismatched arch / container pairs.
 *            * Factory accepts (x64, pe) and returns a working backend.
 *            * `supports(kind)` is true for every defined `PackerStubKind`.
 *            * The `produce(driver, ...)` byte output is byte-for-byte
 *              equal to a direct `build_driver_stub_bytes` call (driver
 *              shape picked because it skips the user-mode-only blocks
 *              and has no VEH trap option, so the comparison is most
 *              deterministic).
 *            * The variant index of `result.patches` matches the
 *              requested `kind` enum.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/packer/packer_stub_backend.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"
#include "mxprotector/protection/packer/x64_pe_stub_backend.hpp"
#include "mxprotector/target/target_info.hpp"

namespace {

using mx::ByteBuffer;
using mx::ByteView;
using mx::Randomizer;
using mx::arch::ArchFamily;
using mx::arch::ArchInfo;
using mx::packer::DriverStubPatches;
using mx::packer::IPackerStubBackend;
using mx::packer::PackerStubKind;
using mx::packer::PackerStubResult;
using mx::packer::StubEmissionParams;
using mx::packer::X64PeStubBackend;
using mx::packer::X64PeStubBackendFactory;
using mx::target::ContainerFormat;

StubEmissionParams driver_params() {
    return StubEmissionParams{
        .section_count       = 2,
        .layer_count         = 2,
        .enable_veh_trap     = false,
        .apply_relocs_inline = false,
    };
}

ByteView empty_stolen() {
    return ByteView{};
}

} // namespace

TEST(X64PeStubBackend, ReportsX64AndPe) {
    X64PeStubBackend backend;
    EXPECT_EQ(backend.arch().family, ArchFamily::x64);
    EXPECT_EQ(backend.container(), ContainerFormat::pe);
}

TEST(X64PeStubBackend, SupportsEveryDefinedKind) {
    X64PeStubBackend backend;
    EXPECT_TRUE(backend.supports(PackerStubKind::exe_executable));
    EXPECT_TRUE(backend.supports(PackerStubKind::dll_full));
    EXPECT_TRUE(backend.supports(PackerStubKind::driver));
    EXPECT_TRUE(backend.supports(PackerStubKind::efi));
}

TEST(X64PeStubBackend, FactoryReportsX64AndPe) {
    X64PeStubBackendFactory factory;
    EXPECT_EQ(factory.supported_family(), ArchFamily::x64);
    EXPECT_EQ(factory.supported_container(), ContainerFormat::pe);
}

TEST(X64PeStubBackend, FactoryAcceptsX64Pe) {
    X64PeStubBackendFactory factory;
    auto created = factory.create(ArchInfo::x64_baseline(), ContainerFormat::pe);
    ASSERT_TRUE(created.has_value());
    std::unique_ptr<IPackerStubBackend> backend = std::move(*created);
    ASSERT_NE(backend, nullptr);
    EXPECT_EQ(backend->arch().family, ArchFamily::x64);
    EXPECT_EQ(backend->container(), ContainerFormat::pe);
}

TEST(X64PeStubBackend, FactoryRejectsArm64) {
    X64PeStubBackendFactory factory;
    auto created = factory.create(ArchInfo::arm64_v8a_application(),
                                  ContainerFormat::pe);
    ASSERT_FALSE(created.has_value());
}

TEST(X64PeStubBackend, FactoryRejectsElfContainer) {
    X64PeStubBackendFactory factory;
    auto created = factory.create(ArchInfo::x64_baseline(),
                                  ContainerFormat::elf);
    ASSERT_FALSE(created.has_value());
}

TEST(X64PeStubBackend, ProduceDriverMatchesDirectBuilder) {
    Randomizer rng_backend{0xDEADBEEFull};
    Randomizer rng_direct{0xDEADBEEFull};

    X64PeStubBackend backend;
    auto result = backend.produce(PackerStubKind::driver,
                                  rng_backend, empty_stolen(),
                                  driver_params());
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->bytes.empty());

    auto [direct_bytes, direct_patches] =
        mx::packer::build_driver_stub_bytes(rng_direct, empty_stolen(),
                                            driver_params().section_count,
                                            driver_params().layer_count,
                                            driver_params().apply_relocs_inline);

    EXPECT_EQ(result->bytes, direct_bytes);
    ASSERT_TRUE(std::holds_alternative<DriverStubPatches>(result->patches));
    EXPECT_EQ(result->kind, PackerStubKind::driver);
}

TEST(X64PeStubBackend, ProduceVariantIndexMatchesKind) {
    Randomizer rng{0x5A5A5A5Aull};
    X64PeStubBackend backend;

    {
        auto r = backend.produce(PackerStubKind::exe_executable, rng,
                                 empty_stolen(), driver_params());
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->patches.index(), 0u);
    }
    {
        auto r = backend.produce(PackerStubKind::dll_full, rng,
                                 empty_stolen(), driver_params());
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->patches.index(), 1u);
    }
    {
        auto r = backend.produce(PackerStubKind::driver, rng,
                                 empty_stolen(), driver_params());
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->patches.index(), 2u);
    }
    {
        auto r = backend.produce(PackerStubKind::efi, rng,
                                 empty_stolen(), driver_params());
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->patches.index(), 3u);
    }
}
