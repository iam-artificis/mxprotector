/**
 * @file layout_policy_test.cpp
 * @brief [TESTS] `ILayoutPolicy` contract + `StandardLayout` defaults.
 *
 * The interface is the single seam every section emission (R2.3) and
 * the post-emit finalisation (R2.5) will go through. Pinning the
 * default no-op semantics here makes a future `ChaosLayout` opt-in
 * by construction — anyone who replaces `StandardLayout` with a
 * misbehaving policy gets a loud test failure before their build
 * silently mis-emits sections.
 */

#include <gtest/gtest.h>

#include <memory>

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/layout/standard_layout.hpp"
#include "mxprotector/pe/layout_policy.hpp"
#include "mxprotector/pe/section_intent.hpp"

namespace {

using mx::pe::ILayoutPolicy;
using mx::pe::SectionContentType;
using mx::pe::SectionIntent;
using mx::pe::SectionPermissions;
using mx::pe::StandardLayout;

// ---------------------------------------------------------------------------
// StandardLayout pass-through
// ---------------------------------------------------------------------------

TEST(LayoutPolicy, StandardLayoutResolveReturnsRequestedIntentUnchanged) {
    StandardLayout policy;
    constexpr SectionIntent code_rx{
        SectionContentType::code, SectionPermissions::rx};
    constexpr SectionIntent data_rw{
        SectionContentType::data, SectionPermissions::rw};
    constexpr SectionIntent mixed_rwx{
        SectionContentType::mixed_code_data, SectionPermissions::rwx};

    EXPECT_EQ(policy.resolve(".text", code_rx),    code_rx);
    EXPECT_EQ(policy.resolve(".rdata", data_rw),   data_rw);
    EXPECT_EQ(policy.resolve(".chaos", mixed_rwx), mixed_rwx);
}

TEST(LayoutPolicy, StandardLayoutNameLiteralIsStable) {
    // Sidecar / log strings are matched on this literal; a rename is
    // a public-contract change worth catching here.
    StandardLayout policy;
    EXPECT_EQ(policy.name(), "standard");
}

TEST(LayoutPolicy, StandardLayoutFinalizeIsNoOpAndSucceeds) {
    StandardLayout policy;
    mx::PeImage img;
    const auto status = policy.finalize(img);
    EXPECT_TRUE(status.has_value())
        << "StandardLayout::finalize must succeed unconditionally";
}

// ---------------------------------------------------------------------------
// ProtectionContext default + override
// ---------------------------------------------------------------------------

TEST(LayoutPolicy, ProtectionContextDefaultsToStandardLayout) {
    auto img = std::make_unique<mx::PeImage>();
    img->set_architecture(mx::Architecture::x64);

    mx::ProtectionContext ctx(
        std::move(img), mx::ProtectionConfig{}, nullptr);
    EXPECT_EQ(ctx.layout_policy().name(), "standard");
}

namespace {

/// Tiny test double — flips every intent to RWX to verify the
/// override seam is wired correctly without depending on the
/// (future) `ChaosLayout` implementation.
class AlwaysRwxLayout final : public ILayoutPolicy {
public:
    [[nodiscard]] SectionIntent resolve(
        std::string_view /*section_name*/,
        SectionIntent    requested) const noexcept override
    {
        return {requested.content, SectionPermissions::rwx};
    }

    [[nodiscard]] mx::MxStatus finalize(mx::PeImage&) const override {
        return {};
    }

    [[nodiscard]] std::string_view name() const noexcept override {
        return "test-rwx";
    }
};

} // anonymous

TEST(LayoutPolicy, SetLayoutPolicyReplacesActivePolicy) {
    auto img = std::make_unique<mx::PeImage>();
    img->set_architecture(mx::Architecture::x64);
    mx::ProtectionContext ctx(
        std::move(img), mx::ProtectionConfig{}, nullptr);

    ctx.set_layout_policy(std::make_unique<AlwaysRwxLayout>());
    EXPECT_EQ(ctx.layout_policy().name(), "test-rwx");

    constexpr SectionIntent code_rx{
        SectionContentType::code, SectionPermissions::rx};
    const auto resolved = ctx.layout_policy().resolve(".text", code_rx);
    EXPECT_EQ(resolved.perms,   SectionPermissions::rwx);
    EXPECT_EQ(resolved.content, SectionContentType::code);
}

TEST(LayoutPolicy, SetLayoutPolicyIgnoresNullToPreserveInvariant) {
    // The context guarantees a live policy at all times; passing a
    // null pointer must NOT corrupt that invariant. The accessor
    // would otherwise dereference null.
    auto img = std::make_unique<mx::PeImage>();
    img->set_architecture(mx::Architecture::x64);
    mx::ProtectionContext ctx(
        std::move(img), mx::ProtectionConfig{}, nullptr);

    ctx.set_layout_policy(nullptr);
    EXPECT_EQ(ctx.layout_policy().name(), "standard");
}

} // namespace
