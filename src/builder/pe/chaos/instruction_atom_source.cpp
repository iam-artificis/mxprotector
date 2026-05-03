/**
 * @file instruction_atom_source.cpp
 * @brief Implementation — see header.
 *
 * Uses Zydis in long-mode (x64). Each successful decode produces
 * one atom of `instruction.length` bytes; a decode failure produces
 * a 1-byte `instruction_undecoded` atom and the cursor advances by
 * one. This guarantees forward progress on any input.
 */

#include "mxprotector/pe/chaos/instruction_atom_source.hpp"

#include <algorithm>

#include <Zydis/Zydis.h>

#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

/// One-shot Zydis decoder, configured for x64 long mode. The
/// decoder is stateless — it walks byte ranges; we re-create one
/// per `emit_atoms` call to avoid hidden lifetime coupling between
/// runs.
class ZydisX64Decoder {
public:
    ZydisX64Decoder() noexcept {
        ZydisDecoderInit(
            &decoder_,
            ZYDIS_MACHINE_MODE_LONG_64,
            ZYDIS_STACK_WIDTH_64);
    }

    /// Decode one instruction at `data[offset..]`. Returns the
    /// instruction length on success, 0 on decode failure.
    ///
    /// `ZydisDecoderDecodeFull` writes the *full* operand list
    /// (including hidden operands), so the buffer must be sized to
    /// `ZYDIS_MAX_OPERAND_COUNT`. Sizing it to
    /// `ZYDIS_MAX_OPERAND_COUNT_VISIBLE` (5 vs 10) caused stack
    /// corruption that surfaced as an apparent infinite loop on
    /// trivial NOP runs.
    [[nodiscard]] std::uint8_t decode_one(
        const std::uint8_t* data,
        std::size_t         remaining) noexcept
    {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        const auto status = ZydisDecoderDecodeFull(
            &decoder_, data, remaining,
            &insn, ops);
        if (!ZYAN_SUCCESS(status)) return 0;
        return insn.length;
    }

private:
    ZydisDecoder decoder_;
};

/// Walk one code section's bytes, emitting one atom per decoded
/// instruction (or per undecodable byte). The walk is bounded by
/// `min(data.size(), virtual_size)` so we never read padding past
/// the section's in-memory extent.
void scan_one_code_section(
    const pe::SectionInfo& sec,
    AtomTable&             out)
{
    if (sec.data.empty()) return;
    const std::size_t walk_size = std::min(
        sec.data.size(),
        static_cast<std::size_t>(sec.virtual_size));
    if (walk_size == 0) return;

    ZydisX64Decoder dec;
    std::size_t offset = 0;
    while (offset < walk_size) {
        const auto length = dec.decode_one(
            sec.data.data() + offset,
            walk_size - offset);

        if (length == 0) {
            // Undecodable byte — emit a 1-byte atom so the planner
            // still owns this byte and the shuffler treats it as a
            // movable unit.
            out.add(Atom{
                .start_rva = static_cast<Rva>(sec.virtual_address + offset),
                .size      = 1,
                .origin    = AtomOrigin::instruction_undecoded,
            });
            offset += 1;
            continue;
        }

        out.add(Atom{
            .start_rva = static_cast<Rva>(sec.virtual_address + offset),
            .size      = length,
            .origin    = AtomOrigin::instruction,
        });
        offset += length;
    }
}

} // anonymous namespace

void InstructionAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    for (const auto& sec : image.sections()) {
        if (!sec.is_code()) continue;
        scan_one_code_section(sec, out);
    }
}

} // namespace mx::pe::chaos
