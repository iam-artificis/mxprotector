/**
 * @file padding_filler.cpp
 * @brief Implementation of the dead-padding filler — see header.
 *
 * Code is mechanically lifted from the previous in-line body in
 * `mutation_pass.cpp` (R3.3). Heuristic and write order are
 * preserved; the only externally visible change is the (hpp,cpp)
 * split itself.
 */

#include "mxprotector/protection/mutation/padding_filler.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/mutation/junk_generator.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"

namespace mx::mutation {

namespace {

/// One contiguous run of dead padding bytes (offset within the
/// section's byte buffer + length).
struct PaddingRun {
    std::size_t byte_offset;
    std::size_t byte_size;
};

/// True iff the disassembled instruction is a single NOP or INT3
/// byte (the only padding shapes the compiler / linker emits).
[[nodiscard]] bool is_padding_instruction(const analysis::Instruction& insn) {
    return insn.mnemonic() == "nop" || insn.mnemonic() == "int3";
}

/// True iff the padding run starting at @p run_start_idx in @p insns
/// is "dead" — safe to overwrite. INT3 runs are always dead; NOP
/// runs are dead at the start of the section or directly after a
/// `ret` / unconditional `jmp`.
[[nodiscard]] bool is_dead_padding(
    const std::vector<analysis::Instruction>& insns,
    std::size_t                                run_start_idx)
{
    if (insns[run_start_idx].mnemonic() == "int3") return true;
    if (run_start_idx == 0) return true;

    const auto& prev = insns[run_start_idx - 1];
    return prev.is_return() || prev.is_unconditional_jump();
}

/// Walk @p instructions and return every contiguous dead padding
/// run of at least @p min_size bytes.
[[nodiscard]] std::vector<PaddingRun> find_dead_padding(
    const std::vector<analysis::Instruction>& instructions,
    Va                                         base_address,
    std::size_t                                min_size = 2)
{
    std::vector<PaddingRun> runs;

    for (std::size_t i = 0; i < instructions.size(); ) {
        if (!is_padding_instruction(instructions[i])) {
            ++i;
            continue;
        }

        const std::size_t run_start = i;
        const std::size_t byte_offset =
            static_cast<std::size_t>(instructions[i].address() - base_address);
        std::size_t byte_size = 0;

        while (i < instructions.size() &&
               is_padding_instruction(instructions[i]))
        {
            byte_size += instructions[i].length();
            ++i;
        }

        if (byte_size >= min_size &&
            is_dead_padding(instructions, run_start))
        {
            runs.push_back({byte_offset, byte_size});
        }
    }

    return runs;
}

/// Try to write an always-true opaque predicate into @p run with
/// the dead branch hosting the junk fill. Returns true if the
/// predicate fit; the caller falls back to plain-junk fill on false.
[[nodiscard]] bool fill_with_opaque_predicate(
    std::uint8_t*             dst,
    const PaddingRun&         run,
    JunkGenerator&            junk_gen,
    OpaquePredicateGenerator& pred_gen,
    Randomizer&               rng,
    PaddingFillStats&         stats)
{
    auto predicate = pred_gen.generate_always_true(rng, 0);
    if (predicate.code.empty()
        || predicate.total_size >= run.byte_size
        || (run.byte_size - predicate.total_size) > 127)
    {
        return false;
    }

    const auto junk_size =
        static_cast<std::uint8_t>(run.byte_size - predicate.total_size);

    predicate.code[predicate.true_branch_offset + 1] = junk_size;
    std::copy(predicate.code.begin(), predicate.code.end(), dst);

    auto junk = junk_gen.generate(junk_size, rng);
    std::copy(junk.begin(), junk.end(), dst + predicate.total_size);

    stats.junk_bytes += static_cast<std::uint32_t>(run.byte_size);
    ++stats.regions_filled;
    ++stats.predicates_inserted;
    return true;
}

} // anonymous namespace

PaddingFillStats fill_section_padding(
    MutableByteView           code,
    Va                        base_address,
    analysis::IDisassembler&  disasm,
    JunkGenerator&            junk_gen,
    OpaquePredicateGenerator& pred_gen,
    Randomizer&               rng)
{
    PaddingFillStats stats;

    auto decode_result = disasm.decode_buffer(
        ByteView{code.data(), code.size()}, base_address);
    if (!decode_result || decode_result->empty()) return stats;

    const auto runs = find_dead_padding(*decode_result, base_address);

    for (const auto& run : runs) {
        if (run.byte_offset + run.byte_size > code.size()) continue;

        std::uint8_t* dst = code.data() + run.byte_offset;

        // Larger runs get a 50% chance of an opaque predicate;
        // smaller runs (or the other 50%) fall through to plain junk.
        constexpr std::size_t kPredicateMinRunSize = 14;
        if (run.byte_size >= kPredicateMinRunSize && rng.next_bool(0.5)) {
            if (fill_with_opaque_predicate(
                    dst, run, junk_gen, pred_gen, rng, stats))
            {
                continue;
            }
        }

        auto junk = junk_gen.generate(run.byte_size, rng);
        std::copy(junk.begin(), junk.end(), dst);
        stats.junk_bytes += static_cast<std::uint32_t>(run.byte_size);
        ++stats.regions_filled;
    }

    return stats;
}

} // namespace mx::mutation
