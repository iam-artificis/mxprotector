/**
 * @file chaos_instruction_cluster_atom_source_test.cpp
 * @brief [TESTS] B.4.10.2 — `InstructionClusterAtomSource` contract.
 *
 * Five invariants:
 *   1. PE32 image / no code sections → no-op.
 *   2. Atoms cover the section bytes contiguously (every byte is in
 *      exactly one atom). Internal cluster boundaries are an
 *      implementation detail; the tile invariant is what matters
 *      for the planner.
 *   3. With `min_insns == max_insns == 1` the cluster source
 *      degenerates to per-instruction granularity — same atom
 *      count as `InstructionAtomSource`.
 *   4. With `min_insns == max_insns == N` and a section of K
 *      single-byte NOPs, K ≥ N produces `ceil(K/N)` cluster atoms.
 *   5. Same seed → same cluster boundaries (determinism).
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/instruction_atom_source.hpp"
#include "mxprotector/pe/chaos/instruction_cluster_atom_source.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::Atom;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;
using mx::pe::chaos::InstructionAtomSource;
using mx::pe::chaos::InstructionClusterAtomSource;

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

[[nodiscard]] Rva add_code_section(
    PeImage&                         img,
    std::string_view                 name,
    const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        std::string(name),
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_CODE |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    return img.sections()[*idx].virtual_address;
}

// ---------------------------------------------------------------------------
// Empty / disabled cases
// ---------------------------------------------------------------------------

TEST(InstructionClusterAtomSource, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    InstructionClusterAtomSource s{0xCAFEBABE, 4, 15};
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(InstructionClusterAtomSource, EmptySectionEmitsNoAtoms) {
    PeImage img = make_pe32plus_image();
    [[maybe_unused]] const auto rva = add_code_section(img, ".text", {});

    InstructionClusterAtomSource s{0x1234, 4, 15};
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Coverage invariant — atoms tile every byte
// ---------------------------------------------------------------------------

TEST(InstructionClusterAtomSource, AtomsTileSectionContiguously) {
    PeImage img = make_pe32plus_image();
    // 32 NOPs.
    std::vector<std::uint8_t> bytes(32, 0x90);
    const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionClusterAtomSource s{0xDEADBEEF, 4, 15};
    AtomTable t;
    s.emit_atoms(img, t);
    t.normalize();   // sort

    Rva cursor = sec_rva;
    for (const auto& a : t.atoms()) {
        EXPECT_EQ(a.start_rva, cursor);
        cursor = a.end_rva();
    }
    EXPECT_EQ(cursor, sec_rva + bytes.size());
}

// ---------------------------------------------------------------------------
// Degenerate cluster size — one instruction per cluster
// ---------------------------------------------------------------------------

TEST(InstructionClusterAtomSource, OneInsnPerClusterMatchesPerInstructionSource) {
    PeImage img = make_pe32plus_image();
    const std::vector<std::uint8_t> bytes = {
        0x89, 0xC0,                       // MOV EAX, EAX (2 B)
        0xB8, 0x01, 0x00, 0x00, 0x00,     // MOV EAX, 1   (5 B)
        0xC3,                              // RET          (1 B)
        0x90,                              // NOP          (1 B)
    };
    [[maybe_unused]] const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionClusterAtomSource cluster{0x1, 1, 1};
    AtomTable cluster_atoms;
    cluster.emit_atoms(img, cluster_atoms);

    InstructionAtomSource per_insn;
    AtomTable per_insn_atoms;
    per_insn.emit_atoms(img, per_insn_atoms);

    EXPECT_EQ(cluster_atoms.size(), per_insn_atoms.size());
}

// ---------------------------------------------------------------------------
// Fixed cluster size — atom count is ceil(K / N)
// ---------------------------------------------------------------------------

TEST(InstructionClusterAtomSource, FixedClusterSizeProducesCeilDivisionAtoms) {
    PeImage img = make_pe32plus_image();
    // 12 single-byte NOPs.
    std::vector<std::uint8_t> bytes(12, 0x90);
    [[maybe_unused]] const Rva sec_rva = add_code_section(img, ".text", bytes);

    // Cluster size fixed at 5 → 12 / 5 = 2 full + 1 trailing = 3 atoms.
    InstructionClusterAtomSource s{0xABC, 5, 5};
    AtomTable t;
    s.emit_atoms(img, t);
    EXPECT_EQ(t.size(), 3u);
}

TEST(InstructionClusterAtomSource, FixedClusterSizeAtomLengthsAreCorrect) {
    PeImage img = make_pe32plus_image();
    // 10 NOPs (1 byte each).
    std::vector<std::uint8_t> bytes(10, 0x90);
    [[maybe_unused]] const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionClusterAtomSource s{0x1, 4, 4};
    AtomTable t;
    s.emit_atoms(img, t);

    // 10 / 4 = 2 full clusters of 4 B + 1 trailing of 2 B = 3 atoms.
    ASSERT_EQ(t.size(), 3u);
    EXPECT_EQ(t.atoms()[0].size, 4u);
    EXPECT_EQ(t.atoms()[1].size, 4u);
    EXPECT_EQ(t.atoms()[2].size, 2u);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

TEST(InstructionClusterAtomSource, SameSeedProducesSameClusters) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(64, 0x90);
    [[maybe_unused]] const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionClusterAtomSource a{0x42, 4, 15};
    InstructionClusterAtomSource b{0x42, 4, 15};
    AtomTable ta;
    AtomTable tb;
    a.emit_atoms(img, ta);
    b.emit_atoms(img, tb);

    ASSERT_EQ(ta.size(), tb.size());
    for (std::size_t i = 0; i < ta.size(); ++i) {
        EXPECT_EQ(ta.atoms()[i].start_rva, tb.atoms()[i].start_rva);
        EXPECT_EQ(ta.atoms()[i].size,      tb.atoms()[i].size);
    }
}

// ---------------------------------------------------------------------------
// Undecodable bytes — flush + advance
// ---------------------------------------------------------------------------

TEST(InstructionClusterAtomSource, AtomsAlwaysCoverAllSectionBytes) {
    PeImage img = make_pe32plus_image();
    // Mix of valid and dubious bytes.
    const std::vector<std::uint8_t> bytes = {
        0x90, 0x90, 0x90, 0x90, 0x90,  // NOP×5
        0xC3,                            // RET
        0x90, 0x90, 0x90,              // NOP×3
    };
    [[maybe_unused]] const Rva sec_rva = add_code_section(img, ".text", bytes);

    InstructionClusterAtomSource s{0x1, 4, 15};
    AtomTable t;
    s.emit_atoms(img, t);
    t.normalize();

    Rva cursor = sec_rva;
    for (const auto& a : t.atoms()) {
        EXPECT_EQ(a.start_rva, cursor);
        cursor = a.end_rva();
    }
    EXPECT_EQ(cursor, sec_rva + bytes.size());
}

} // namespace
