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

TEST(AtomicChunkPlanner, NoSourcesNoChunksEmitted) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec1 = add_section(img, ".s1", 64);

    // B.4.12: the planner no longer carves "loose" chunks for bytes
    // outside any atom. With no atom sources registered, the entire
    // image span is passthrough — 0 chunks emitted.
    AtomicChunkPlanner planner{/*loose_chunk_size=*/16};
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    EXPECT_EQ(remapper.chunk_count(), 0u);
    EXPECT_EQ(remapper.total_bytes(), 0u);
}

TEST(AtomicChunkPlanner, LooseChunkSizeIgnoredWithoutSources) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec1 = add_section(img, ".s1", 16);

    // B.4.12: the loose-chunk size parameter is preserved in the
    // public API but no longer drives any carving. With no atom
    // sources, no chunks are emitted regardless of the size.
    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    EXPECT_EQ(remapper.chunk_count(), 0u);
    EXPECT_EQ(remapper.total_bytes(), 0u);
}

// ---------------------------------------------------------------------------
// Atoms + loose
// ---------------------------------------------------------------------------

TEST(AtomicChunkPlanner, AlignedMovableAtomBecomesItsOwnChunk) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 32);

    // 8-byte movable atom whose start AND end are 8-aligned.
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 + 8), 8, AtomOrigin::instruction},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // B.4.12: only the atom becomes a chunk. The bytes outside it
    // (the section's leading 8 bytes and trailing 16 bytes) are
    // passthrough — 0 loose chunks.
    EXPECT_EQ(remapper.chunk_count(), 1u);
    EXPECT_EQ(remapper.total_bytes(), 8u);
}

TEST(AtomicChunkPlanner, NoSourcesNoBytesShuffled) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto sec1 = add_section(img, ".s1", 100);
    [[maybe_unused]] const auto sec2 = add_section(img, ".s2", 200);

    // B.4.12: without atom sources, no chunks are produced. Total
    // shuffled bytes is therefore 0 regardless of image span size.
    AtomicChunkPlanner planner{/*loose_chunk_size=*/64};
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);
    EXPECT_EQ(remapper.total_bytes(), 0u);
    EXPECT_EQ(remapper.chunk_count(), 0u);
}

TEST(AtomicChunkPlanner, OverlappingAtomsAreMergedBeforePlanning) {
    PeImage img = make_pe32plus_image();
    const auto sec1 = add_section(img, ".s1", 64);

    // Two overlapping atoms — merge into one [sec, sec+24) atom.
    std::vector<Atom> atoms = {
        Atom{static_cast<Rva>(sec1 +  0), 16, AtomOrigin::instruction},
        Atom{static_cast<Rva>(sec1 +  8), 16, AtomOrigin::ascii_string},
    };

    AtomicChunkPlanner planner{/*loose_chunk_size=*/1};
    planner.add_source(std::make_unique<StubAtomSource>(atoms));
    Randomizer rng;
    const auto remapper = planner.plan(img, rng);

    // B.4.12: merged atom [sec, sec+24) is 8-aligned at both ends
    // and stays movable → 1 chunk. The remaining 40 bytes of the
    // section are passthrough, no chunk emitted.
    EXPECT_EQ(remapper.chunk_count(), 1u);
    EXPECT_EQ(remapper.total_bytes(), 24u);
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

    // B.4.12: pinned atom is passthrough; everything else also
    // passthrough (no movable atoms registered) → 0 chunks.
    EXPECT_EQ(remapper.total_bytes(), 0u);
    EXPECT_EQ(remapper.chunk_count(), 0u);

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

    // B.4.12: only movable atoms become chunks; without any
    // movable sources only the pinned atoms exist → 0 chunks.
    EXPECT_EQ(remapper.total_bytes(), 0u);
    EXPECT_EQ(remapper.chunk_count(), 0u);

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

    // B.4.12: only the 16-byte movable atom (8-aligned at both
    // ends) becomes a chunk. Bytes after it stay at original RVA.
    EXPECT_EQ(remapper.total_bytes(), 16u);
    EXPECT_EQ(remapper.chunk_count(), 1u);

    // Pinned atom passthrough.
    for (std::uint32_t off = 0; off < 8; ++off) {
        const Rva rva = static_cast<Rva>(sec1 + 32 + off);
        EXPECT_EQ(remapper.remap(rva), rva);
    }
}

} // namespace
