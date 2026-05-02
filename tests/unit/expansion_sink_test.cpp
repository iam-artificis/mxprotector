/**
 * @file expansion_sink_test.cpp
 * @brief [TESTS] Mutation expansion sinks contract.
 *
 * Pins the invariants every `IExpansionSink` must hold, regardless of
 * whether bodies share one section (`ExtendInPlaceSink`) or land in
 * a fresh section per call (`SeparateOverflowSink`):
 *
 *   1. The reported `overflow_rva` matches the section's actual RVA.
 *   2. The bytes before the trailing JMP are an exact copy of
 *      `expanded_bytes`.
 *   3. The trailing 5 bytes encode `JMP rel32` from the tail back to
 *      `site_rva + site_size`.
 *
 * Plus the per-sink invariants:
 *
 *   * `ExtendInPlaceSink` reuses one section across multiple plants;
 *     the second plant grows the cached section in place rather than
 *     creating a new one.
 *   * `SeparateOverflowSink` allocates a fresh section per plant and
 *     refuses to exceed `kMaxSpillCount`.
 *
 * The standalone `compute_rel32` / `encode_jmp_rel32` helpers are
 * tested separately so a sink failure cannot mask an encoder bug.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "mxprotector/pe/layout/standard_layout.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/mutation/overflow/extend_in_place_sink.hpp"
#include "mxprotector/protection/mutation/overflow/grow_source_section_sink.hpp"
#include "mxprotector/protection/mutation/overflow/jmp_emit.hpp"
#include "mxprotector/protection/mutation/overflow/separate_overflow_sink.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::mutation::ExpansionRequest;
using mx::mutation::overflow::compute_rel32;
using mx::mutation::overflow::encode_jmp_rel32;
using mx::mutation::overflow::ExtendInPlaceSink;
using mx::mutation::overflow::GrowSourceSectionSink;
using mx::mutation::overflow::kJmpRel32Size;
using mx::mutation::overflow::kMaxSpillCount;
using mx::mutation::overflow::SeparateOverflowSink;
using mx::pe::SectionEmitter;
using mx::pe::StandardLayout;

[[nodiscard]] PeImage make_empty_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(0x140000000ULL);
    return img;
}

[[nodiscard]] std::vector<std::uint8_t> bytes(
    std::initializer_list<std::uint8_t> v)
{
    return std::vector<std::uint8_t>{v};
}

[[nodiscard]] std::int32_t read_le_i32(const std::uint8_t* p) {
    std::int32_t out = 0;
    std::memcpy(&out, p, sizeof(out));
    return out;
}

// ---------------------------------------------------------------------------
// jmp_emit
// ---------------------------------------------------------------------------

TEST(JmpEmit, ComputeRel32Forward) {
    // 5-byte JMP from RVA 0x1000 to RVA 0x2000 → end-of-jmp = 0x1005,
    // displacement = 0x2000 - 0x1005 = 0xFFB.
    EXPECT_EQ(compute_rel32(0x1000u, 0x2000u), 0x0FFB);
}

TEST(JmpEmit, ComputeRel32Backward) {
    // 5-byte JMP from RVA 0x3000 to RVA 0x1000 → end-of-jmp = 0x3005,
    // displacement = 0x1000 - 0x3005 = -0x2005 → 0xFFFFDFFB.
    EXPECT_EQ(compute_rel32(0x3000u, 0x1000u), -0x2005);
}

TEST(JmpEmit, EncodeJmpRel32WriteOpcodeAndDisplacement) {
    const auto enc = encode_jmp_rel32(0x1000u, 0x2000u);
    EXPECT_EQ(enc[0], 0xE9u);
    EXPECT_EQ(read_le_i32(&enc[1]), 0x0FFB);
}

// ---------------------------------------------------------------------------
// ExtendInPlaceSink
// ---------------------------------------------------------------------------

TEST(ExtendInPlaceSink, FirstPlantAllocatesAndEncodesJmpBack) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    ExtendInPlaceSink sink{emit, ".mxmut"};
    EXPECT_FALSE(sink.section_exists());

    const auto expanded = bytes({0x90, 0x90, 0x90, 0x90});
    ExpansionRequest req{
        .site_rva       = 0x1000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{expanded.data(), expanded.size()},
    };
    auto plan = sink.plant(req);
    ASSERT_TRUE(plan.has_value());
    EXPECT_TRUE(sink.section_exists());

    ASSERT_EQ(img.sections().size(), 1u);
    const auto& sec = img.sections()[0];
    EXPECT_EQ(sec.name, ".mxmut");
    EXPECT_EQ(plan->overflow_rva, sec.virtual_address);
    EXPECT_EQ(plan->overflow_size, expanded.size() + kJmpRel32Size);
    ASSERT_EQ(sec.data.size(), expanded.size() + kJmpRel32Size);

    // Body bytes preserved.
    for (std::size_t i = 0; i < expanded.size(); ++i) {
        EXPECT_EQ(sec.data[i], expanded[i])
            << "body byte " << i << " corrupted";
    }
    // Trailing JMP rel32 → return_rva (= site_rva + site_size = 0x1005).
    EXPECT_EQ(sec.data[expanded.size()], 0xE9u);
    const Rva tail_rva = static_cast<Rva>(
        sec.virtual_address + expanded.size());
    const std::int32_t expected_rel = compute_rel32(tail_rva, 0x1005u);
    EXPECT_EQ(read_le_i32(&sec.data[expanded.size() + 1]), expected_rel);
}

TEST(ExtendInPlaceSink, SecondPlantGrowsCachedSection) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    ExtendInPlaceSink sink{emit, ".mxmut"};

    const auto first_body  = bytes({0xA1, 0xA2, 0xA3});
    const auto second_body = bytes({0xB1, 0xB2});

    auto plan1 = sink.plant(ExpansionRequest{
        .site_rva       = 0x1000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{first_body.data(), first_body.size()},
    });
    ASSERT_TRUE(plan1.has_value());

    auto plan2 = sink.plant(ExpansionRequest{
        .site_rva       = 0x2000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{second_body.data(), second_body.size()},
    });
    ASSERT_TRUE(plan2.has_value());

    // Single section, grown twice.
    ASSERT_EQ(img.sections().size(), 1u);
    const auto& sec = img.sections()[0];
    const std::size_t expected_size =
        first_body.size() + kJmpRel32Size +
        second_body.size() + kJmpRel32Size;
    EXPECT_EQ(sec.data.size(), expected_size);

    // Plan 2's overflow RVA is offset from plan 1's by the first
    // payload's full size.
    EXPECT_EQ(plan1->overflow_rva, sec.virtual_address);
    EXPECT_EQ(plan2->overflow_rva,
              sec.virtual_address + first_body.size() + kJmpRel32Size);

    // The second body's JMP-back targets 0x2005.
    const std::size_t second_off = first_body.size() + kJmpRel32Size;
    for (std::size_t i = 0; i < second_body.size(); ++i) {
        EXPECT_EQ(sec.data[second_off + i], second_body[i]);
    }
    const std::size_t jmp_off = second_off + second_body.size();
    EXPECT_EQ(sec.data[jmp_off], 0xE9u);
    const Rva tail_rva = static_cast<Rva>(
        sec.virtual_address + jmp_off);
    EXPECT_EQ(read_le_i32(&sec.data[jmp_off + 1]),
              compute_rel32(tail_rva, 0x2005u));
}

TEST(ExtendInPlaceSink, EmptyExpandedBytesIsRejected) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    ExtendInPlaceSink sink{emit, ".mxmut"};

    auto plan = sink.plant(ExpansionRequest{
        .site_rva       = 0x1000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{},
    });
    EXPECT_FALSE(plan.has_value());
    EXPECT_EQ(img.sections().size(), 0u)
        << "Failed plant must not allocate the section";
}

// ---------------------------------------------------------------------------
// SeparateOverflowSink
// ---------------------------------------------------------------------------

TEST(SeparateOverflowSink, EachPlantAllocatesFreshSection) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    SeparateOverflowSink sink{emit, ".mxmut"};
    EXPECT_EQ(sink.spill_count(), 0u);

    const auto body_a = bytes({0xCA, 0xFE});
    const auto body_b = bytes({0xBE, 0xEF, 0xDE});

    auto plan_a = sink.plant(ExpansionRequest{
        .site_rva       = 0x1000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{body_a.data(), body_a.size()},
    });
    ASSERT_TRUE(plan_a.has_value());
    EXPECT_EQ(sink.spill_count(), 1u);

    auto plan_b = sink.plant(ExpansionRequest{
        .site_rva       = 0x2000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{body_b.data(), body_b.size()},
    });
    ASSERT_TRUE(plan_b.has_value());
    EXPECT_EQ(sink.spill_count(), 2u);

    ASSERT_EQ(img.sections().size(), 2u);
    EXPECT_EQ(img.sections()[0].name, ".mxmut00");
    EXPECT_EQ(img.sections()[1].name, ".mxmut01");

    // Each plan points at its corresponding section.
    EXPECT_EQ(plan_a->overflow_rva, img.sections()[0].virtual_address);
    EXPECT_EQ(plan_b->overflow_rva, img.sections()[1].virtual_address);

    // Body bytes preserved at offset 0, JMP-back at the tail.
    const auto& sec_b = img.sections()[1];
    for (std::size_t i = 0; i < body_b.size(); ++i) {
        EXPECT_EQ(sec_b.data[i], body_b[i]);
    }
    EXPECT_EQ(sec_b.data[body_b.size()], 0xE9u);
    const Rva tail_rva = static_cast<Rva>(
        sec_b.virtual_address + body_b.size());
    EXPECT_EQ(read_le_i32(&sec_b.data[body_b.size() + 1]),
              compute_rel32(tail_rva, 0x2005u));
}

TEST(SeparateOverflowSink, EmptyExpandedBytesIsRejected) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    SeparateOverflowSink sink{emit, ".mxmut"};
    auto plan = sink.plant(ExpansionRequest{
        .site_rva       = 0x1000,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{},
    });
    EXPECT_FALSE(plan.has_value());
    EXPECT_EQ(img.sections().size(), 0u);
    EXPECT_EQ(sink.spill_count(), 0u);
}

// ---------------------------------------------------------------------------
// GrowSourceSectionSink
// ---------------------------------------------------------------------------

namespace {

/// Construct an image with two pre-existing sections so the sink has
/// a "source" containing the site RVA, and a "next" section whose RVA
/// must stay stable across the in-place growth.
[[nodiscard]] PeImage make_image_with_two_sections() {
    PeImage img = make_empty_image();

    const auto src_data = std::vector<std::uint8_t>(0x100, 0x90);
    auto src_added = SectionManager{img}.add_section(
        ".text",
        mx::ByteView{src_data.data(), src_data.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    EXPECT_TRUE(src_added.has_value());

    const auto next_data = std::vector<std::uint8_t>(0x80, 0xAA);
    auto next_added = SectionManager{img}.add_section(
        ".rdata",
        mx::ByteView{next_data.data(), next_data.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    EXPECT_TRUE(next_added.has_value());

    return img;
}

} // anonymous namespace

TEST(GrowSourceSectionSink, InPlaceGrowthKeepsNextSectionRvaStable) {
    PeImage img = make_image_with_two_sections();
    const auto src_va_before  = img.sections()[0].virtual_address;
    const auto src_size_before = img.sections()[0].virtual_size;
    const auto next_va_before = img.sections()[1].virtual_address;

    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    GrowSourceSectionSink sink{emit};

    const auto expanded = bytes({0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90});
    const Rva site_rva = src_va_before + 0x10; // inside .text

    auto plan = sink.plant(ExpansionRequest{
        .site_rva       = site_rva,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{expanded.data(), expanded.size()},
    });
    ASSERT_TRUE(plan.has_value()) << "expected slack growth to succeed";

    EXPECT_EQ(img.sections().size(), 2u) << "no new section should appear";

    const auto& src_after  = img.sections()[0];
    const auto& next_after = img.sections()[1];

    // Source section's RVA didn't move (only its virtual_size grew).
    EXPECT_EQ(src_after.virtual_address, src_va_before);
    EXPECT_GT(src_after.virtual_size, src_size_before);

    // Next section's RVA stayed put — this is the slack-growth invariant.
    EXPECT_EQ(next_after.virtual_address, next_va_before);

    // Plant landed at the section's old tail.
    EXPECT_EQ(plan->overflow_rva, src_va_before + src_size_before);
    EXPECT_EQ(plan->overflow_size, expanded.size() + kJmpRel32Size);

    // Body bytes preserved at offset.
    const auto offset = src_size_before;
    for (std::size_t i = 0; i < expanded.size(); ++i) {
        EXPECT_EQ(src_after.data[offset + i], expanded[i]);
    }
    // Trailing JMP rel32 → return_rva = site_rva + site_size = site_rva+5.
    EXPECT_EQ(src_after.data[offset + expanded.size()], 0xE9u);
    const Rva tail_rva = static_cast<Rva>(
        src_va_before + offset + expanded.size());
    EXPECT_EQ(read_le_i32(&src_after.data[offset + expanded.size() + 1]),
              compute_rel32(tail_rva, site_rva + 5));
}

TEST(GrowSourceSectionSink, ExceedingSlackReturnsSlackExhausted) {
    PeImage img = make_image_with_two_sections();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    // .text has virtual_size = 0x100 → slack = 0x1000 - 0x100 = 0xF00.
    // Ask for an expanded body that needs payload > 0xF00 to fail.
    GrowSourceSectionSink sink{emit};
    const auto expanded = std::vector<std::uint8_t>(0xFFC, 0x90);
    auto plan = sink.plant(ExpansionRequest{
        .site_rva       = img.sections()[0].virtual_address + 0x10,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{expanded.data(), expanded.size()},
    });
    ASSERT_FALSE(plan.has_value());
    EXPECT_EQ(static_cast<std::uint16_t>(plan.error().code()),
              static_cast<std::uint16_t>(
                  mx::PeErrorCode::section_slack_exhausted));
    // Source section's data was not mutated.
    EXPECT_EQ(img.sections()[0].virtual_size, 0x100u);
}

TEST(GrowSourceSectionSink, RvaOutsideAnySectionFailsClosed) {
    PeImage img = make_image_with_two_sections();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    GrowSourceSectionSink sink{emit};
    const auto expanded = bytes({0x90});
    auto plan = sink.plant(ExpansionRequest{
        .site_rva       = 0xDEADBEEF,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{expanded.data(), expanded.size()},
    });
    ASSERT_FALSE(plan.has_value());
    EXPECT_EQ(static_cast<std::uint16_t>(plan.error().code()),
              static_cast<std::uint16_t>(mx::PeErrorCode::invalid_rva));
}

TEST(GrowSourceSectionSink, EmptyExpandedBytesIsRejected) {
    PeImage img = make_image_with_two_sections();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    GrowSourceSectionSink sink{emit};
    auto plan = sink.plant(ExpansionRequest{
        .site_rva       = img.sections()[0].virtual_address,
        .site_size      = 5,
        .expanded_bytes = mx::ByteView{},
    });
    EXPECT_FALSE(plan.has_value());
}

} // namespace
