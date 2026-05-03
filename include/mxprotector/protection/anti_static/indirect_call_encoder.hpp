/**
 * @file indirect_call_encoder.hpp
 * @brief [PROTECTION] Static-analysis-defeating call dispatch
 *        encoder interface (B.4.19).
 *
 * ### Why
 *
 * A naïve `call rel32` is a single edge in any decompiler's call
 * graph: IDA, Ghidra, Binary Ninja, even simple disassembly
 * scripts read the 5-byte instruction and follow the displacement
 * to the target — done. To frustrate that, every call site in the
 * protected binary is rewritten to call a tiny per-target
 * **dispatch stub** instead. The stub computes the real target's
 * runtime VA through a chain of arithmetic / logical instructions
 * and ends with `jmp rax`. The original `call → target` edge in
 * the CFG becomes `call → stub → ???`, and every stub is built
 * from a different opcode mix so a single pattern match cannot
 * unwrap them all.
 *
 * ### Contract
 *
 * An `IIndirectCallEncoder` knows how to:
 *
 *   1. Report its byte size (`stub_size()`) so the pass can lay
 *      out stubs back-to-back in a dedicated section.
 *
 *   2. Emit one stub instance via `emit(...)` — picking random
 *      constants from `rng` so two stubs targeting the same
 *      function produce different bytes when adjacent encoder
 *      slots happen to pick the same encoder.
 *
 *   3. Return the metadata the chaos-shuffle reference patcher
 *      needs to rewrite the embedded LEA disp32 if the target
 *      moves later. The encoder collapses its chain of
 *      operations into a single "constant offset `K`" that the
 *      patcher applies via the `rel32_with_imm_offset`
 *      reference encoding.
 *
 * ### Variety axis
 *
 * Encoders sit on three axes the registry shuffles independently:
 *
 *   * **Opcode mix** — `add`/`sub`/`xor`/`rol`/`ror`/`not`/`neg`
 *     in arbitrary chains.
 *   * **Constants** — random per-call imm32 values.
 *   * **Tail shape** — `jmp rax`, `push rax; ret`, `lea rcx;
 *     mov rcx, rax; jmp rcx`.
 *
 * New encoders implement the interface and register themselves;
 * the rest of the pipeline does not change.
 *
 * SOLID:
 *   * SRP — one encoder == one decode-resistant pattern. Adding a
 *     new pattern is a new file, not a switch in this header.
 *   * OCP — `EncoderRegistry` consumers iterate via the abstract
 *     interface; new encoders plug in without touching pass code.
 *   * LSP — every encoder is interchangeable so the pass can pick
 *     uniformly at random per call site.
 *
 * Threading: `emit()` is allowed to mutate the encoder's
 * `Randomizer&` argument; concurrent calls on the same encoder
 * with the same `rng` are not safe. The pipeline is single-
 * threaded by construction.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx {
class Randomizer;
}

namespace mx::protection::anti_static {

/**
 * @brief Output of one stub emission — see header.
 */
struct EncodedStub {
    /// Exactly `IIndirectCallEncoder::stub_size()` bytes, ready to
    /// drop into the stub section.
    std::vector<std::uint8_t> bytes;

    /// Offset (within `bytes`) of the LEA `disp32` slot that
    /// carries the chain's encoded target. The chaos-shuffle
    /// reference patcher rewrites these four bytes when the target
    /// moves.
    std::uint32_t disp32_byte_offset{0};

    /// Algebraic offset `K` such that
    /// `disp32 = (target - lea_pc_after) - K` makes the runtime
    /// chain land on `target`. `K` is signed and packed into the
    /// reference's `aux` field.
    std::int32_t  constant_offset{0};
};

/**
 * @brief Indirect-call encoder — see header.
 */
class IIndirectCallEncoder {
public:
    virtual ~IIndirectCallEncoder() = default;

    /// Diagnostic / log-friendly name. Lowercase, hyphenated. Must
    /// be unique across registered encoders so logs disambiguate.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /// Size of one emitted stub in bytes. Constant for a given
    /// encoder type — variation comes from constants, not length.
    [[nodiscard]] virtual std::uint32_t stub_size() const noexcept = 0;

    /**
     * @brief Emit a stub that, when executed at `stub_rva`, jumps
     *        to `target_rva`.
     *
     * @param stub_rva   RVA of the stub's first byte.
     * @param target_rva RVA of the actual call destination.
     * @param rng        Source of randomness for the encoder's
     *                   per-stub constants.
     *
     * @return The byte payload plus the metadata the chaos-shuffle
     *         reference patcher needs to keep the LEA disp32 in
     *         sync if `target_rva` moves later.
     */
    [[nodiscard]] virtual EncodedStub emit(
        Rva          stub_rva,
        Rva          target_rva,
        Randomizer&  rng) const = 0;
};

} // namespace mx::protection::anti_static
