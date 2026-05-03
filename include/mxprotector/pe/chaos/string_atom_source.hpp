/**
 * @file string_atom_source.hpp
 * @brief Atom sources that detect ASCIIZ and UTF-16 LE strings in
 *        non-code sections and emit one atom per string.
 *
 * Why: long string literals are the most likely thing a chaos
 * shuffler can break — a 30-character DLL name that gets split
 * across chunks is no longer a valid string, the loader fails to
 * load the DLL, the binary refuses to start. Treating each string
 * as one atom keeps it intact while still letting the planner
 * scatter strings among instructions and other data atoms.
 *
 * What constitutes a "string":
 *
 *   * **ASCII** — a run of bytes in `[0x20, 0x7E]` (printable
 *     ASCII, including space) followed by a `0x00` terminator.
 *     Configurable minimum length defaults to 4 visible chars
 *     (so 5 bytes total: 4 visible + NUL).
 *
 *   * **UTF-16 LE** — a run of 16-bit little-endian code units
 *     where every unit's high byte is `0x00` and the low byte is
 *     printable ASCII, followed by a 16-bit `0x0000` terminator.
 *     Same minimum-length default.
 *
 * The threshold of 4 chars is empirical: shorter "strings" tend
 * to be coincidental ASCII patterns inside data tables (e.g. the
 * bytes of a small-magnitude integer happen to look like printable
 * letters). Pinning every accidental 1-3 char run would over-pin
 * `.data`. The two-character cutoff between "shuffleable byte" and
 * "indivisible string" is a soft tradeoff documented here.
 *
 * What this source does NOT touch:
 *
 *   * Code sections — strings inside `.text` are exotic and the
 *     `InstructionAtomSource` already covers code bytes. We avoid
 *     double-claiming.
 *
 *   * Sections smaller than the minimum string length.
 *
 * Threading: stateless. Construct on the stack, call `emit_atoms`,
 * throw away.
 */

#pragma once

#include <cstdint>

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Default minimum visible-character count for a string atom.
 *
 * Below this length the run is considered noise (incidental ASCII
 * patterns in data) and not pinned.
 */
inline constexpr std::uint32_t kDefaultStringMinChars = 4;

/**
 * @brief ASCIIZ string atom source — see file header.
 *
 * Configurable threshold. Emits atoms covering the run plus its
 * NUL terminator (so the atom's `size = visible_chars + 1`).
 */
class AsciiStringAtomSource final : public IAtomSource {
public:
    explicit AsciiStringAtomSource(
        std::uint32_t min_chars = kDefaultStringMinChars) noexcept
        : min_chars_(min_chars) {}

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;

private:
    std::uint32_t min_chars_;
};

/**
 * @brief UTF-16 LE string atom source — see file header.
 *
 * Same threshold semantics as the ASCII variant; the atom size
 * counts bytes (so `size = (visible_chars + 1) * 2` for the run
 * plus the 16-bit terminator).
 */
class Utf16StringAtomSource final : public IAtomSource {
public:
    explicit Utf16StringAtomSource(
        std::uint32_t min_chars = kDefaultStringMinChars) noexcept
        : min_chars_(min_chars) {}

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;

private:
    std::uint32_t min_chars_;
};

} // namespace mx::pe::chaos
