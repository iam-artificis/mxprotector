/**
 * @file chaos_atomic_chunk_planner_test.cpp
 * @brief [TESTS] B.4.9.6 — `AtomicChunkPlanner` contract.
 *
 * Five invariants:
 *   1. Empty image (no sections) → empty remapper.
 *   2. With no atom sources, every byte becomes a `loose_chunk_size`
 *      chunk and the remapper covers exactly the image span.
 *   3. With one synthetic atom source, atoms preserve their size in
 *      the remapper and the rest is filled with loose chunks.
 *   4. Total mapped bytes == image span size.
 *   5. Old-RVA range is preserved (every byte in the span is in
 *      exactly one chunk; coverage is contiguous).
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/atom_source.hpp"
#include "mxprotector/pe/chaos/atomic_chunk_planner.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Randomizer;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::Atom;
using mx::pe::chaos::AtomicChunkPlanner;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;
using mx::pe::chaos::IAtomSource;

[[nodiscard]] PeImage make_pe32plus_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(0x140000000ULL);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_lfanew = 0x100;
    img.set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                          = 0x00004550;
    nt.FileHeader.Machine                 = 0x8664;
    nt.FileHeader.SizeOfOptionalHeader    = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic               = 0x20B;
    nt.OptionalHeader.NumberOfRvaAndSizes =
        mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] Rva add_section(
    PeImage& img, std::string_view name, std::uint32_t size)
{
    SectionManager mgr{img};
    std::vector<std::uint8_t> bytes(size, 0);
    auto idx = mgr.add_section(
        std::string(name),
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    return img.sections()[*idx].virtual_address;
}

/// Stub source that emits a fixed list of atoms regardless of image.
class StubAtomSource final : public IAtomSource {
public:
    explicit StubAtomSource(std::vector<Atom> atoms) noexcept
        : atoms_(std::move(atoms)) {}

    void emit_atoms(const PeImage&, AtomTable& out) const override {
        for (const auto& a : atoms_) out.add(a);
    }

private:
    std::vector<Atom> atoms_;
};

// ---------------------------------------------------------------------------
// Empty image
// ---------------------------------------------------------------------------

TEST(AtomicChunkPlanner, EmptyImageProducesEmptyRemapper) {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);

    AtomicChunkPlanner planner;
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);
    EXPECT_EQ(remapper.chunk_count(), 0u);
}

// ---------------------------------------------------------------------------
// No sources — all loose
// ---------------------------------------------------------------------------

TEST(AtomicChunkPlanner, NoSourcesAllLooseChunksCoverSpan) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec1 = add_section(img, ".s1", 64);

    AtomicChunkPlanner planner{/*loose_chunk_size=*/16};
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // 64 bytes / 16 per chunk = 4 chunks.
    EXPECT_EQ(remapper.chunk_count(), 4u);
    EXPECT_EQ(remapper.total_bytes(), 64u);
}

TEST(AtomicChunkPlanner, OneByteLooseChunksMaximizeGranularity) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec1 = add_section(img, ".s1", 16);

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    EXPECT_EQ(remapper.chunk_count(), 16u);
    EXPECT_EQ(remapper.total_bytes(), 16u);
}

// ---------------------------------------------------------------------------
// Atoms + loose
// ---------------------------------------------------------------------------

TEST(AtomicChunkPlanner, AtomPreservesItsSizeInRemapper) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 32);

    // One 8-byte atom in the middle of the section.
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 + 8), 8, AtomOrigin::instruction},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // 8 bytes loose [sec, sec+8) + 8B atom + 16 bytes loose [sec+16, sec+32)
    // = 8 + 1 + 16 = 25 chunks.
    EXPECT_EQ(remapper.chunk_count(), 25u);
    EXPECT_EQ(remapper.total_bytes(), 32u);
}

TEST(AtomicChunkPlanner, TotalBytesEqualsImageSpan) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec1 = add_section(img, ".s1", 100);
    [[maybe_unused]] const auto sec2 = add_section(img, ".s2", 200);

    // Span = max(va + vsize) - min(va). With section_alignment = 0x1000,
    // each section's vsize rounds up. The PeImage helper aligns
    // virtual_address to section_alignment between sections, so
    // span includes the alignment padding between .s1 and .s2.
    AtomicChunkPlanner planner{/*loose_chunk_size=*/64};
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // Don't assert exact chunk count (depends on alignment math),
    // but total bytes must equal image span.
    Rva first_va = img.sections().front().virtual_address;
    std::uint32_t last_end = 0;
    for (const auto& s : img.sections()) {
        last_end = std::max(last_end, s.virtual_address + s.virtual_size);
    }
    const std::uint64_t span = last_end - first_va;
    EXPECT_EQ(remapper.total_bytes(), span);
}

TEST(AtomicChunkPlanner, OverlappingAtomsAreMergedBeforePlanning) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 64);

    // Two overlapping atoms — should merge into one bigger atom
    // before chunk allocation.
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 +  0), 16, AtomOrigin::instruction},
        Atom{static_cast<Rva>(sec1 +  8), 16, AtomOrigin::ascii_string},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // Merged atom = [sec, sec+24) (24 B). Loose = [sec+24, sec+64) = 40 bytes.
    // Total chunks = 1 atom + 40 loose = 41.
    EXPECT_EQ(remapper.chunk_count(), 41u);
    EXPECT_EQ(remapper.total_bytes(), 64u);
}

// ---------------------------------------------------------------------------
// Determinism: same seed → same remapper
// ---------------------------------------------------------------------------

TEST(AtomicChunkPlanner, SameSeedProducesSameLayout) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec = add_section(img, ".s1", 32);

    AtomicChunkPlanner planner{/*loose_chunk_size=*/4};

    Randomizer rng_a{0x12345678};
    Randomizer rng_b{0x12345678};
    const auto a = planner.plan(img, rng_a);
    const auto b = planner.plan(img, rng_b);

    ASSERT_EQ(a.chunk_count(), b.chunk_count());
    EXPECT_EQ(a.total_bytes(), b.total_bytes());
    // Walk every old RVA and confirm same remap result.
    for (std::uint32_t off = 0; off < 32; ++off) {
        const Rva rva = static_cast<Rva>(sec + off);
        EXPECT_EQ(a.remap(rva), b.remap(rva));
    }
}

// ---------------------------------------------------------------------------
// B.4.10.1 — alignment-aware: pinned atoms stay at their original RVA,
//             movable bytes shuffle among themselves in the gaps.
// ---------------------------------------------------------------------------

TEST(AtomicChunkPlanner, PinnedAtomKeepsOriginalRvaPassthrough) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 64);

    // One pinned 8-byte atom at sec+24 (alignment 8 from origin policy).
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 + 24), 8, AtomOrigin::tls_directory},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // Pinned atom is NOT a chunk in the remapper — it's a passthrough.
    // Span = 64 B; 8 B are pinned → 56 B movable carved into 56 loose
    // chunks (loose_chunk_size = 1).
    EXPECT_EQ(remapper.total_bytes(), 56u);
    EXPECT_EQ(remapper.chunk_count(), 56u);

    // Pinned slot RVA must remap to itself.
    for (std::uint32_t off = 0; off < 8; ++off) {
        const Rva rva = static_cast<Rva>(sec1 + 24 + off);
        EXPECT_EQ(remapper.remap(rva), rva)
            << "pinned byte must passthrough at off=" << off;
    }
}

TEST(AtomicChunkPlanner, MultiplePinnedAtomsCreateMultipleFreeRanges) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 96);

    // Two pinned atoms at sec+32 and sec+64, splitting the section
    // into three free ranges.
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 + 32), 8, AtomOrigin::tls_directory},
        Atom{static_cast<Rva>(sec1 + 64), 8, AtomOrigin::import_thunk},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // Movable bytes = 96 - 16 = 80; loose_chunk_size = 1 → 80 chunks.
    EXPECT_EQ(remapper.total_bytes(), 80u);
    EXPECT_EQ(remapper.chunk_count(), 80u);

    // Both pinned atoms must passthrough.
    EXPECT_EQ(remapper.remap(static_cast<Rva>(sec1 + 32)),
              static_cast<Rva>(sec1 + 32));
    EXPECT_EQ(remapper.remap(static_cast<Rva>(sec1 + 64)),
              static_cast<Rva>(sec1 + 64));
}

TEST(AtomicChunkPlanner, MovableAtomShuffledAroundPinnedNeighbour) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 64);

    // Pinned atom at sec+32; one movable instruction atom at sec+0.
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 +  0), 16, AtomOrigin::instruction},
        Atom{static_cast<Rva>(sec1 + 32),  8, AtomOrigin::tls_directory},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng{0x1234};
    const auto remapper = planner.plan(img, rng);

    // Movable bytes = 64 - 8 = 56; movable atom = 16 B + loose 16+24 = 40 B.
    // Free range A = [sec, sec+32) = 32 B → atom 16 B + 16 loose = 17 chunks.
    // Free range B = [sec+40, sec+64) = 24 B → 24 loose chunks.
    EXPECT_EQ(remapper.total_bytes(), 56u);
    EXPECT_EQ(remapper.chunk_count(), 17u + 24u);

    // Pinned atom passthrough.
    for (std::uint32_t off = 0; off < 8; ++off) {
        const Rva rva = static_cast<Rva>(sec1 + 32 + off);
        EXPECT_EQ(remapper.remap(rva), rva);
    }
}

} // namespace
