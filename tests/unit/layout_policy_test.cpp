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
#include "mxprotector/pe/pe_builder.hpp"
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

// ---------------------------------------------------------------------------
// PeBuilder::build — finalize hook integration (R2.5)
// ---------------------------------------------------------------------------

namespace {

/// Policy that records whether `finalize` was invoked. The build
/// path must call it once before serialisation; nothing else may.
class CountingFinalizeLayout final : public ILayoutPolicy {
public:
    [[nodiscard]] SectionIntent resolve(
        std::string_view, SectionIntent r) const noexcept override
    {
        return r;
    }
    [[nodiscard]] mx::MxStatus finalize(mx::PeImage&) const override {
        ++calls_;
        return {};
    }
    [[nodiscard]] std::string_view name() const noexcept override {
        return "counting";
    }
    [[nodiscard]] int call_count() const noexcept { return calls_; }

private:
    mutable int calls_ = 0;
};

/// Policy that fails finalize. Used to verify the build path
/// surfaces the policy's error rather than swallowing it.
class FailingFinalizeLayout final : public ILayoutPolicy {
public:
    [[nodiscard]] SectionIntent resolve(
        std::string_view, SectionIntent r) const noexcept override
    {
        return r;
    }
    [[nodiscard]] mx::MxStatus finalize(mx::PeImage&) const override {
        return std::unexpected(mx::error::pe_fmt(
            mx::PeErrorCode::section_alignment_violation,
            "policy refused to finalize for testing"));
    }
    [[nodiscard]] std::string_view name() const noexcept override {
        return "failing";
    }
};

/// Build a tiny but well-formed PeImage so PeBuilder::build can run
/// to completion. We do not exercise the writer's correctness here
/// — only the policy hook — so a header-only image is sufficient.
[[nodiscard]] mx::PeImage make_minimal_image() {
    mx::PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    return img;
}

} // anonymous

TEST(LayoutPolicy, PeBuilderInvokesFinalizeExactlyOnce) {
    auto img = make_minimal_image();
    CountingFinalizeLayout policy;

    auto status = mx::PeBuilder::build(img, policy);
    // We don't care whether build succeeds for a header-only image —
    // we care that finalize was consulted exactly once.
    (void)status;
    EXPECT_EQ(policy.call_count(), 1);
}

TEST(LayoutPolicy, PeBuilderPropagatesFinalizeError) {
    auto img = make_minimal_image();
    FailingFinalizeLayout policy;

    auto status = mx::PeBuilder::build(img, policy);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code(),
              static_cast<std::uint16_t>(mx::PeErrorCode::section_alignment_violation));
}

} // namespace
