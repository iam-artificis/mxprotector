/**
 * @file instruction_cluster_atom_source.cpp
 * @brief Implementation — see header.
 *
 * Walk each code section with a Zydis x64 long-mode decoder. Maintain
 * an in-progress cluster `[start, cursor)` that grows by one decoded
 * instruction at a time. When the cluster reaches its target
 * instruction count, emit it as one `instruction` atom and resample
 * a new target. Decode failures flush the in-progress cluster, emit
 * a 1-byte `instruction_undecoded` atom, and reset.
 */

#include "mxprotector/pe/chaos/instruction_cluster_atom_source.hpp"

#include <algorithm>
#include <cstdint>

#include <Zydis/Zydis.h>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

/// One-shot Zydis decoder, configured for x64 long mode. Stateless —
/// re-created per `emit_atoms` call to avoid hidden coupling between
/// runs and to keep the source thread-friendly.
class ZydisX64Decoder {
public:
    ZydisX64Decoder() noexcept {
        ZydisDecoderInit(&decoder_,
                         ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64);
    }

    /// Returns instruction length on success, 0 on decode failure.
    /// `ZydisDecoderDecodeFull` writes into the FULL operand list
    /// (including hidden operands) — the buffer must be sized to
    /// `ZYDIS_MAX_OPERAND_COUNT`, not `_VISIBLE`. Smaller buffers
    /// caused stack corruption and apparent infinite loops on NOP
    /// runs in earlier work.
    [[nodiscard]] std::uint8_t decode_one(
        const std::uint8_t* data,
        std::size_t         remaining) noexcept
    {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        const auto status = ZydisDecoderDecodeFull(
            &decoder_, data, remaining, &insn, ops);
        if (!ZYAN_SUCCESS(status)) return 0;
        return insn.length;
    }

private:
    ZydisDecoder decoder_;
};

/// Cluster-builder state shared by `flush_cluster` and the section
/// walker. Holds the in-progress cluster's section-relative offset
/// and the number of instructions already accumulated.
struct ClusterBuilder {
    std::size_t   start_off    = 0;
    std::uint32_t insn_count   = 0;
    std::uint32_t target_size  = 0;  // resample on each emit
};

/// Pick the next cluster's target instruction count.
[[nodiscard]] std::uint32_t resample_target(
    std::uint32_t min_insns,
    std::uint32_t max_insns,
    Randomizer&   rng) noexcept
{
    if (max_insns <= min_insns) return min_insns;
    return rng.next_range(min_insns, max_insns);
}

/// Emit the current cluster as one atom (if non-empty) and reset.
void flush_cluster(
    Rva                   section_va,
    std::size_t           cluster_end_off,
    ClusterBuilder&       builder,
    AtomTable&            out)
{
    if (builder.insn_count == 0) return;
    const auto bytes = static_cast<std::uint32_t>(
        cluster_end_off - builder.start_off);
    if (bytes == 0) {
        builder.insn_count = 0;
        return;
    }
    out.add(Atom{
        .start_rva = static_cast<Rva>(section_va + builder.start_off),
        .size      = bytes,
        .origin    = AtomOrigin::instruction,
    });
    builder.insn_count = 0;
}

/// Emit one `instruction_undecoded` atom for `[off, off + 1)`.
void emit_undecoded_byte(
    Rva         section_va,
    std::size_t off,
    AtomTable&  out)
{
    out.add(Atom{
        .start_rva = static_cast<Rva>(section_va + off),
        .size      = 1,
        .origin    = AtomOrigin::instruction_undecoded,
    });
}

/// Walk one code section, emit cluster atoms.
void scan_one_code_section(
    const pe::SectionInfo& sec,
    std::uint32_t          min_insns,
    std::uint32_t          max_insns,
    Randomizer&            rng,
    AtomTable&             out)
{
    if (sec.data.empty()) return;
    const std::size_t walk_size = std::min(
        sec.data.size(),
        static_cast<std::size_t>(sec.virtual_size));
    if (walk_size == 0) return;

    ZydisX64Decoder decoder;
    ClusterBuilder  builder;
    builder.target_size = resample_target(min_insns, max_insns, rng);

    std::size_t offset = 0;
    while (offset < walk_size) {
        const auto length = decoder.decode_one(
            sec.data.data() + offset, walk_size - offset);

        if (length == 0) {
            // Flush whatever we had, then mark the unparseable byte.
            flush_cluster(sec.virtual_address, offset, builder, out);
            emit_undecoded_byte(sec.virtual_address, offset, out);
            offset += 1;
            builder.start_off  = offset;
            builder.target_size = resample_target(min_insns, max_insns, rng);
            continue;
        }

        if (builder.insn_count == 0) {
            builder.start_off = offset;
        }
        builder.insn_count += 1;
        offset += length;

        if (builder.insn_count >= builder.target_size) {
            flush_cluster(sec.virtual_address, offset, builder, out);
            builder.target_size = resample_target(min_insns, max_insns, rng);
        }
    }

    // Trailing partial cluster.
    flush_cluster(sec.virtual_address, walk_size, builder, out);
}

} // anonymous namespace

InstructionClusterAtomSource::InstructionClusterAtomSource(
    std::uint64_t seed,
    std::uint32_t min_insns,
    std::uint32_t max_insns) noexcept
    : seed_(seed)
    , min_insns_(min_insns == 0 ? kDefaultMinInsns : min_insns)
    , max_insns_(max_insns < (min_insns == 0 ? kDefaultMinInsns : min_insns)
                  ? (min_insns == 0 ? kDefaultMinInsns : min_insns)
                  : max_insns)
{}

void InstructionClusterAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    Randomizer rng{seed_};
    for (const auto& sec : image.sections()) {
        if (!sec.is_code()) continue;
        scan_one_code_section(sec, min_insns_, max_insns_, rng, out);
    }
}

} // namespace mx::pe::chaos
