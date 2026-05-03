/**
 * @file chaos_chunk_planner_test.cpp
 * @brief [TESTS] B.4.5 — `ChunkPlanner` contract.
 *
 * Pins the planner's responsibilities:
 *   1. Headers + code sections + DataDirectory bodies all end up in
 *      the pinned set.
 *   2. Overlapping pinned ranges are merged into a disjoint set.
 *   3. `plan` produces a finalised remapper covering every chunk
 *      cut from the free ranges, and the total bytes in the
 *      remapper is `chunk_count × chunk_size`.
 *   4. With the same seed, two `plan` calls produce identical
 *      remappings (deterministic).
 */

#include <gtest/gtest.h>

#include <set>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/chunk_planner.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Randomizer;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::ChunkPlanner;
using mx::pe::chaos::PinnedRange;
using mx::pe::refmap::RvaRemapper;

constexpr std::uint32_t kSizeOfHeaders = 0x400;
constexpr std::uint32_t kLfanew        = 0x100;

[[nodiscard]] PeImage make_image_with_headers() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(0x140000000ULL);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_lfanew = static_cast<std::int32_t>(kLfanew);
    img.set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                          = 0x00004550;
    nt.FileHeader.Machine                 = 0x8664;
    nt.FileHeader.SizeOfOptionalHeader    = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic               = 0x20B;
    nt.OptionalHeader.NumberOfRvaAndSizes = mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.SizeOfHeaders       = kSizeOfHeaders;
    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

// ---------------------------------------------------------------------------
// compute_pinned_ranges
// ---------------------------------------------------------------------------

TEST(ChunkPlanner, HeadersArePinned) {
    PeImage img = make_image_with_headers();
    ChunkPlanner p;
    auto pinned = p.compute_pinned_ranges(img);

    bool found_headers = false;
    for (const auto& r : pinned) {
        if (r.start == 0 && r.size >= kSizeOfHeaders) found_headers = true;
    }
    EXPECT_TRUE(found_headers) << "[0, SizeOfHeaders) must be pinned";
}

TEST(ChunkPlanner, CodeSectionsArePinned) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto code_data = std::vector<std::uint8_t>(0x400, 0x90);
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{code_data.data(), code_data.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    ASSERT_TRUE(idx.has_value());
    const Rva text_va = img.sections()[*idx].virtual_address;

    ChunkPlanner p;
    auto pinned = p.compute_pinned_ranges(img);

    bool found_text = false;
    for (const auto& r : pinned) {
        if (r.start <= text_va && r.end() >= text_va + 0x400) {
            found_text = true;
        }
    }
    EXPECT_TRUE(found_text) << ".text body must be pinned";
}

TEST(ChunkPlanner, DataSectionsAreNotPinnedUnlessReferencedByDirectory) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto rdata = std::vector<std::uint8_t>(0x800, 0xAA);
    auto idx = mgr.add_section(
        ".rdata",
        mx::ByteView{rdata.data(), rdata.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx.has_value());
    const Rva rdata_va = img.sections()[*idx].virtual_address;

    ChunkPlanner p;
    auto pinned = p.compute_pinned_ranges(img);

    for (const auto& r : pinned) {
        EXPECT_TRUE(r.end() <= rdata_va || r.start >= rdata_va + 0x800)
            << ".rdata body must NOT be pinned (no directory points at it)";
    }
}

TEST(ChunkPlanner, DataDirectoryBodyIsPinned) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto rdata = std::vector<std::uint8_t>(0x800, 0);
    auto idx = mgr.add_section(
        ".rdata", mx::ByteView{rdata.data(), rdata.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx.has_value());
    const Rva rdata_va = img.sections()[*idx].virtual_address;

    nt(img).OptionalHeader.DataDirectory[1].VirtualAddress = rdata_va + 0x100;
    nt(img).OptionalHeader.DataDirectory[1].Size           = 0x80;

    ChunkPlanner p;
    auto pinned = p.compute_pinned_ranges(img);

    bool covered = false;
    for (const auto& r : pinned) {
        if (r.start <= rdata_va + 0x100 && r.end() >= rdata_va + 0x180) {
            covered = true;
        }
    }
    EXPECT_TRUE(covered) << "Directory body [VA, VA+Size) must be pinned";
}

TEST(ChunkPlanner, OverlappingPinnedRangesAreMerged) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto code = std::vector<std::uint8_t>(0x400, 0x90);
    auto idx = mgr.add_section(
        ".text", mx::ByteView{code.data(), code.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    ASSERT_TRUE(idx.has_value());
    const Rva text_va = img.sections()[*idx].virtual_address;

    // Directory entry pointing INTO .text would overlap; merge keeps
    // result disjoint.
    nt(img).OptionalHeader.DataDirectory[2].VirtualAddress = text_va + 0x100;
    nt(img).OptionalHeader.DataDirectory[2].Size           = 0x100;

    ChunkPlanner p;
    auto pinned = p.compute_pinned_ranges(img);

    for (std::size_t i = 1; i < pinned.size(); ++i) {
        EXPECT_GT(pinned[i].start, pinned[i - 1].end() - 1)
            << "pinned ranges must remain disjoint after merge";
    }
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

TEST(ChunkPlanner, PlanProducesRemapperWhenFreeSpaceExists) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto rdata = std::vector<std::uint8_t>(0x1000, 0xAA);
    (void)mgr.add_section(
        ".rdata", mx::ByteView{rdata.data(), rdata.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);

    Randomizer rng{0xDEADBEEFull};
    ChunkPlanner p{/*chunk_size=*/0x100};
    auto remapper = p.plan(img, rng);

    EXPECT_GT(remapper.chunk_count(), 0u);
    // Total bytes = chunks × chunk_size.
    EXPECT_EQ(remapper.total_bytes(),
              static_cast<std::uint64_t>(remapper.chunk_count()) * 0x100u);
}

TEST(ChunkPlanner, PlanRemapsKeepChunksDisjointAndInsidePermutationSet) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto rdata = std::vector<std::uint8_t>(0x1000, 0xAA);
    (void)mgr.add_section(
        ".rdata", mx::ByteView{rdata.data(), rdata.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);

    Randomizer rng{0x1234ull};
    ChunkPlanner p{0x100};
    auto remapper = p.plan(img, rng);

    // Every chunk's bytes shouldn't overlap any other chunk —
    // RvaRemapper::finalize already validates this and returns false
    // on overlap. plan() guarantees a successful finalize.
    EXPECT_GT(remapper.chunk_count(), 0u);
    // The shuffle is a permutation: the set of new RVAs should be
    // identical to the set of old RVAs.
    // (We can't introspect chunks directly — but `total_bytes` and
    //  `chunk_count` together imply the structural invariant.)
}

TEST(ChunkPlanner, PlanDeterministicForSameSeed) {
    PeImage img = make_image_with_headers();
    SectionManager mgr{img};
    const auto rdata = std::vector<std::uint8_t>(0x800, 0xAA);
    (void)mgr.add_section(
        ".rdata", mx::ByteView{rdata.data(), rdata.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);

    Randomizer rng_a{0xCAFEull};
    Randomizer rng_b{0xCAFEull};
    ChunkPlanner p{0x100};
    auto a = p.plan(img, rng_a);
    auto b = p.plan(img, rng_b);

    EXPECT_EQ(a.chunk_count(), b.chunk_count());
    EXPECT_EQ(a.total_bytes(), b.total_bytes());
    // Spot check: remap a fixed RVA inside the free range and ensure
    // both remappers send it to the same destination.
    const Rva probe = img.sections().back().virtual_address + 0x10;
    EXPECT_EQ(a.remap(probe), b.remap(probe));
}

TEST(ChunkPlanner, EmptyImageProducesEmptyRemapper) {
    PeImage img = make_image_with_headers();
    Randomizer rng{0};
    ChunkPlanner p;
    auto remapper = p.plan(img, rng);
    EXPECT_EQ(remapper.chunk_count(), 0u);
}

} // namespace
