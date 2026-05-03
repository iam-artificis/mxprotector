/**
 * @file code_reference_scanner.hpp
 * @brief Walks a code buffer with Zydis and emits a `Reference` for
 *        every relative branch and every RIP-relative memory operand.
 *
 * The chaos shuffler must rewrite every RVA-bearing slot inside code
 * when bytes move. Two kinds of slots originate from instructions:
 *
 *   * Relative branches — `CALL`/`JMP rel32`, `Jcc rel32`,
 *     short `JMP rel8`, `Jcc rel8`, `LOOP`/`LOOPE`/`LOOPNE rel8`.
 *     Slot is the trailing displacement; the slot value is
 *     `target - (next_instruction)`, so both source-side and
 *     target-side moves change the encoded value.
 *
 *   * RIP-relative memory operands — every `mov`/`lea`/`add`/…
 *     that addresses memory through `[RIP + disp32]`. Same rel
 *     semantics as branches.
 *
 * The scanner does not own the code bytes, does not modify them,
 * and emits nothing about non-relative operands (immediates, register
 * operands, `[reg]` memory). It is purely a "find the slots"
 * service; the patcher takes the final mile.
 *
 * Why a dedicated scanner rather than extending `IDisassembler`:
 * the existing `Instruction` abstraction deliberately hides operand-
 * level detail (mnemonic, branch flag, target VA — all that's
 * needed by the marker scanner / CFG builder). Adding RIP-relative
 * disp32 metadata to it would leak Zydis-shaped detail to consumers
 * that do not need it. A separate scanner keeps the seam clean and
 * lets the chaos pipeline use Zydis directly without bloating the
 * shared abstraction.
 *
 * Threading: not safe for concurrent use; instantiate one scanner
 * per scan.
 */

#pragma once

#include <cstdint>
#include <memory>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/chaos/reference.hpp"

namespace mx::pe::chaos {

/**
 * @brief Code-level reference scanner — see file header.
 *
 * x86_64 only. The chaos pipeline runs only on `is_windows_pe_x64`
 * targets, so the scanner does not handle 32-bit instruction
 * decoding.
 */
class CodeReferenceScanner final {
public:
    CodeReferenceScanner();
    ~CodeReferenceScanner();

    CodeReferenceScanner(const CodeReferenceScanner&)            = delete;
    CodeReferenceScanner& operator=(const CodeReferenceScanner&) = delete;
    CodeReferenceScanner(CodeReferenceScanner&&) noexcept;
    CodeReferenceScanner& operator=(CodeReferenceScanner&&) noexcept;

    /**
     * @brief Decode every instruction in `code` (starting at
     *        `base_rva`) and append one `Reference` for each
     *        relative branch and each RIP-relative memory operand.
     *
     * Decode failures are tolerated — a single byte is skipped and
     * decoding resumes at the next byte. The number of failed
     * instructions is returned so the caller can log if the scan
     * tripped.
     *
     * @param code      Code bytes to scan. Lifetime must outlive the
     *                  call.
     * @param base_rva  RVA of `code[0]`. Used to compute slot and
     *                  target RVAs.
     * @param table     Receives every emitted reference. Reset by
     *                  the caller if a fresh scan is desired.
     * @return Number of decode failures encountered.
     */
    [[nodiscard]] std::uint32_t scan(
        ByteView         code,
        Rva              base_rva,
        ReferenceTable&  table);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace mx::pe::chaos
