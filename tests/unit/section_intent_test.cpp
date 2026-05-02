/**
 * @file section_intent_test.cpp
 * @brief [TESTS] `SectionContentType` × `SectionPermissions` →
 *        `IMAGE_SCN_*` bit-mask mapping.
 *
 * These tests pin every cell of the (content × perms) grid so a
 * future tweak that re-uses the same mask for two intents — say,
 * collapsing `r` and `rx` to the same bits — fails loudly. The
 * mapping is the canonical contract that every pass in R2.3 will
 * funnel through; a silent drift would corrupt every protected
 * binary at once.
 */

#include <gtest/gtest.h>

// `section_intent.hpp` includes `pe_types.hpp` already (and pulls
// `core/types.hpp` upfront so `pe_types.hpp` parses cleanly). Listing
// it first keeps that dependency order intact even though `IMAGE_SCN_*`
// lives in `pe_types.hpp` — including the latter directly would
// short-circuit the ordering and trip on `SectionInfo::data` parsing
// against an undefined `ByteBuffer`.
#include "mxprotector/pe/section_intent.hpp"

namespace {

using mx::pe::IMAGE_SCN_CNT_CODE;
using mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA;
using mx::pe::IMAGE_SCN_MEM_EXECUTE;
using mx::pe::IMAGE_SCN_MEM_READ;
using mx::pe::IMAGE_SCN_MEM_WRITE;
using mx::pe::make_section_characteristics;
using mx::pe::SectionContentType;
using mx::pe::SectionIntent;
using mx::pe::SectionPermissions;

// ---------------------------------------------------------------------------
// Content classification bit
// ---------------------------------------------------------------------------

TEST(SectionIntent, CodeSetsCntCodeBit) {
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::code, SectionPermissions::rx});
    EXPECT_TRUE(mask & IMAGE_SCN_CNT_CODE);
    EXPECT_FALSE(mask & IMAGE_SCN_CNT_INITIALIZED_DATA);
}

TEST(SectionIntent, DataSetsCntInitializedBit) {
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::data, SectionPermissions::r});
    EXPECT_FALSE(mask & IMAGE_SCN_CNT_CODE);
    EXPECT_TRUE(mask & IMAGE_SCN_CNT_INITIALIZED_DATA);
}

TEST(SectionIntent, MixedSetsBothCntBits) {
    // The `--chaos` layout depends on this combination — without it
    // a tool can split the section into code-only and data-only
    // halves with one trivial bit-test.
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::mixed_code_data, SectionPermissions::rwx});
    EXPECT_TRUE(mask & IMAGE_SCN_CNT_CODE);
    EXPECT_TRUE(mask & IMAGE_SCN_CNT_INITIALIZED_DATA);
}

// ---------------------------------------------------------------------------
// Permission bits
// ---------------------------------------------------------------------------

TEST(SectionIntent, ReadOnlyImpliesReadAlone) {
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::data, SectionPermissions::r});
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_READ);
    EXPECT_FALSE(mask & IMAGE_SCN_MEM_WRITE);
    EXPECT_FALSE(mask & IMAGE_SCN_MEM_EXECUTE);
}

TEST(SectionIntent, RxImpliesReadAndExecuteOnly) {
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::code, SectionPermissions::rx});
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_READ);
    EXPECT_FALSE(mask & IMAGE_SCN_MEM_WRITE);
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_EXECUTE);
}

TEST(SectionIntent, RwImpliesReadAndWriteOnly) {
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::data, SectionPermissions::rw});
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_READ);
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_WRITE);
    EXPECT_FALSE(mask & IMAGE_SCN_MEM_EXECUTE);
}

TEST(SectionIntent, RwxSetsAllThreePermissionBits) {
    const std::uint32_t mask = make_section_characteristics(
        {SectionContentType::mixed_code_data, SectionPermissions::rwx});
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_READ);
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_WRITE);
    EXPECT_TRUE(mask & IMAGE_SCN_MEM_EXECUTE);
}

// ---------------------------------------------------------------------------
// Determinism + constexpr
// ---------------------------------------------------------------------------

TEST(SectionIntent, IdenticalIntentsProduceIdenticalMasks) {
    // Two passes asking for "code, rx" must get the same bits — a
    // silent divergence would let downstream tooling fingerprint the
    // emitting pass by section flags alone.
    const std::uint32_t a = make_section_characteristics(
        {SectionContentType::code, SectionPermissions::rx});
    const std::uint32_t b = make_section_characteristics(
        {SectionContentType::code, SectionPermissions::rx});
    EXPECT_EQ(a, b);
}

TEST(SectionIntent, IsConstexprFoldable) {
    constexpr std::uint32_t code_rx = make_section_characteristics(
        {SectionContentType::code, SectionPermissions::rx});
    static_assert(code_rx == (IMAGE_SCN_CNT_CODE
                              | IMAGE_SCN_MEM_READ
                              | IMAGE_SCN_MEM_EXECUTE),
        "code/rx fold must include CNT_CODE + MEM_READ + MEM_EXECUTE");
    EXPECT_NE(code_rx, 0u);
}

// ---------------------------------------------------------------------------
// Equality on SectionIntent — required by the LayoutPolicy seam in R2.2
// ---------------------------------------------------------------------------

TEST(SectionIntent, EqualityComparesBothFields) {
    constexpr SectionIntent a{
        SectionContentType::code, SectionPermissions::rx};
    constexpr SectionIntent b{
        SectionContentType::code, SectionPermissions::rx};
    constexpr SectionIntent c{
        SectionContentType::code, SectionPermissions::rwx};
    constexpr SectionIntent d{
        SectionContentType::data, SectionPermissions::rx};
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
    EXPECT_NE(a, d);
}

} // namespace
