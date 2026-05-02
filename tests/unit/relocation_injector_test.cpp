/**
 * @file relocation_injector_test.cpp
 * @brief [TESTS] `RelocationInjector` API contract.
 *
 * Coverage:
 *   - Single insertion creates a fresh `RelocationBlock` whose
 *     `page_rva` is the 4 KB-aligned page containing the target.
 *   - Two insertions on the same page reuse the existing block;
 *     two on different pages produce two blocks.
 *   - Multiple entries within one block are stored in registration
 *     order (we only require deterministic ordering, not a specific
 *     order — but pinning insertion-order makes a future regression
 *     loud).
 *   - The convenience helpers `add_dir64` / `add_highlow` write
 *     the right `IMAGE_REL_BASED_*` type.
 */

#include <gtest/gtest.h>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/relocation_injector.hpp"

namespace {

using mx::PeImage;
using mx::pe::RelocationInjector;

TEST(RelocationInjector, AddCreatesBlockForFreshPage) {
    PeImage img;
    RelocationInjector inj{img};

    inj.add(0x12345, mx::pe::IMAGE_REL_BASED_DIR64);

    ASSERT_EQ(img.relocations().size(), 1u);
    EXPECT_EQ(img.relocations()[0].page_rva, 0x12000u);
    ASSERT_EQ(img.relocations()[0].entries.size(), 1u);
    EXPECT_EQ(img.relocations()[0].entries[0].rva,  0x12345u);
    EXPECT_EQ(img.relocations()[0].entries[0].type,
              mx::pe::IMAGE_REL_BASED_DIR64);
}

TEST(RelocationInjector, MultipleAddsOnSamePageReuseBlock) {
    PeImage img;
    RelocationInjector inj{img};

    inj.add(0x4010, mx::pe::IMAGE_REL_BASED_DIR64);
    inj.add(0x4020, mx::pe::IMAGE_REL_BASED_DIR64);
    inj.add(0x4FFC, mx::pe::IMAGE_REL_BASED_DIR64);

    ASSERT_EQ(img.relocations().size(), 1u);
    EXPECT_EQ(img.relocations()[0].page_rva, 0x4000u);
    EXPECT_EQ(img.relocations()[0].entries.size(), 3u);
}

TEST(RelocationInjector, AddsOnDifferentPagesProduceSeparateBlocks) {
    PeImage img;
    RelocationInjector inj{img};

    inj.add(0x1000, mx::pe::IMAGE_REL_BASED_DIR64);
    inj.add(0x2000, mx::pe::IMAGE_REL_BASED_DIR64);
    inj.add(0x3050, mx::pe::IMAGE_REL_BASED_DIR64);

    ASSERT_EQ(img.relocations().size(), 3u);
    EXPECT_EQ(img.relocations()[0].page_rva, 0x1000u);
    EXPECT_EQ(img.relocations()[1].page_rva, 0x2000u);
    EXPECT_EQ(img.relocations()[2].page_rva, 0x3000u);
}

TEST(RelocationInjector, EntriesPreserveRegistrationOrder) {
    PeImage img;
    RelocationInjector inj{img};

    inj.add(0x4030, mx::pe::IMAGE_REL_BASED_DIR64);
    inj.add(0x4010, mx::pe::IMAGE_REL_BASED_HIGHLOW);
    inj.add(0x4020, mx::pe::IMAGE_REL_BASED_DIR64);

    ASSERT_EQ(img.relocations().size(), 1u);
    const auto& entries = img.relocations()[0].entries;
    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(entries[0].rva, 0x4030u);
    EXPECT_EQ(entries[1].rva, 0x4010u);
    EXPECT_EQ(entries[1].type, mx::pe::IMAGE_REL_BASED_HIGHLOW);
    EXPECT_EQ(entries[2].rva, 0x4020u);
}

TEST(RelocationInjector, AddDir64ConvenienceUsesDir64Type) {
    PeImage img;
    RelocationInjector inj{img};

    inj.add_dir64(0x5008);

    ASSERT_EQ(img.relocations().size(), 1u);
    ASSERT_EQ(img.relocations()[0].entries.size(), 1u);
    EXPECT_EQ(img.relocations()[0].entries[0].type,
              mx::pe::IMAGE_REL_BASED_DIR64);
}

TEST(RelocationInjector, AddHighlowConvenienceUsesHighlowType) {
    PeImage img;
    RelocationInjector inj{img};

    inj.add_highlow(0x6004);

    ASSERT_EQ(img.relocations().size(), 1u);
    ASSERT_EQ(img.relocations()[0].entries.size(), 1u);
    EXPECT_EQ(img.relocations()[0].entries[0].type,
              mx::pe::IMAGE_REL_BASED_HIGHLOW);
}

TEST(RelocationInjector, PreExistingBlocksAreNotDuplicated) {
    PeImage img;
    img.relocations().push_back(mx::pe::RelocationBlock{
        .page_rva = 0x7000,
        .entries  = {mx::pe::RelocationEntry{0x7100, mx::pe::IMAGE_REL_BASED_DIR64}},
    });
    RelocationInjector inj{img};

    inj.add_dir64(0x7200);
    inj.add_dir64(0x8000);

    ASSERT_EQ(img.relocations().size(), 2u);
    EXPECT_EQ(img.relocations()[0].entries.size(), 2u);
    EXPECT_EQ(img.relocations()[1].page_rva, 0x8000u);
}

} // namespace
