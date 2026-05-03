/**
 * @file string_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/string_atom_source.hpp"

#include <algorithm>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// Printable ASCII range (space through tilde inclusive). We do
/// not treat `\t` / `\n` / `\r` as part of strings here — they
/// occur often as numeric data in PE headers and would noisily
/// extend "strings" through unrelated bytes.
[[nodiscard]] constexpr bool is_printable_ascii(std::uint8_t b) noexcept {
    return b >= 0x20 && b <= 0x7E;
}

/// Skip code sections — `InstructionAtomSource` already covers
/// every code byte and we must not double-claim.
[[nodiscard]] bool should_scan_for_strings(
    const pe::SectionInfo& sec) noexcept
{
    if (sec.is_code()) return false;
    if (sec.data.empty()) return false;
    return true;
}

/// Walk one section's bytes looking for ASCIIZ runs of at least
/// `min_chars` visible characters. Each run becomes one atom
/// covering `[start, run_end + 1)` (the NUL terminator is part of
/// the atom so the loader still sees a properly terminated string
/// after the shuffle).
void scan_ascii_in_section(
    const pe::SectionInfo& sec,
    std::uint32_t          min_chars,
    AtomTable&             out)
{
    const std::size_t walk = std::min(
        sec.data.size(),
        static_cast<std::size_t>(sec.virtual_size));
    if (walk < static_cast<std::size_t>(min_chars) + 1) return;

    std::size_t i = 0;
    while (i < walk) {
        if (!is_printable_ascii(sec.data[i])) {
            ++i;
            continue;
        }
        std::size_t run_start = i;
        std::size_t j = i;
        while (j < walk && is_printable_ascii(sec.data[j])) ++j;
        // `j` now points at the first non-printable byte after the
        // run (or `walk`). A valid ASCIIZ requires that byte to be
        // `0x00`.
        const bool nul_terminated = (j < walk && sec.data[j] == 0x00);
        const std::size_t visible_chars = j - run_start;
        if (nul_terminated && visible_chars >= min_chars) {
            out.add(Atom{
                .start_rva = static_cast<Rva>(
                    sec.virtual_address + run_start),
                .size      = static_cast<std::uint32_t>(visible_chars + 1),
                .origin    = AtomOrigin::ascii_string,
            });
            i = j + 1; // step past the NUL
        } else {
            i = j;     // skip the rejected run, resume at first
                       // non-printable
            if (i < walk) ++i; // also step past it
        }
    }
}

/// True when a 16-bit LE code unit at `data[off]` looks like a
/// printable ASCII character (high byte zero, low byte in
/// printable range).
[[nodiscard]] bool utf16_unit_is_printable(
    const std::uint8_t* data,
    std::size_t         off,
    std::size_t         walk) noexcept
{
    if (off + 1 >= walk) return false;
    return data[off + 1] == 0x00 && is_printable_ascii(data[off]);
}

/// True when a 16-bit LE code unit at `data[off]` is `0x0000`.
[[nodiscard]] bool utf16_unit_is_terminator(
    const std::uint8_t* data,
    std::size_t         off,
    std::size_t         walk) noexcept
{
    if (off + 1 >= walk) return false;
    return data[off] == 0x00 && data[off + 1] == 0x00;
}

/// Walk one section's bytes looking for UTF-16 LE strings whose
/// visible-character count meets the threshold. Each accepted
/// string becomes one atom covering bytes through the 16-bit
/// terminator.
void scan_utf16_in_section(
    const pe::SectionInfo& sec,
    std::uint32_t          min_chars,
    AtomTable&             out)
{
    const std::size_t walk = std::min(
        sec.data.size(),
        static_cast<std::size_t>(sec.virtual_size));
    const std::size_t min_bytes =
        static_cast<std::size_t>(min_chars) * 2 + 2;
    if (walk < min_bytes) return;

    // 2-byte aligned scan — UTF-16 strings the linker emits are
    // 2-byte aligned. Misaligned probes generate too many false
    // positives.
    std::size_t i = 0;
    while (i + 1 < walk) {
        if (!utf16_unit_is_printable(sec.data.data(), i, walk)) {
            i += 2;
            continue;
        }
        const std::size_t run_start = i;
        std::size_t j = i;
        while (j + 1 < walk &&
               utf16_unit_is_printable(sec.data.data(), j, walk))
        {
            j += 2;
        }
        const bool nul_terminated =
            utf16_unit_is_terminator(sec.data.data(), j, walk);
        const std::size_t visible_units = (j - run_start) / 2;
        if (nul_terminated && visible_units >= min_chars) {
            const std::size_t total_bytes = (visible_units + 1) * 2;
            out.add(Atom{
                .start_rva = static_cast<Rva>(
                    sec.virtual_address + run_start),
                .size      = static_cast<std::uint32_t>(total_bytes),
                .origin    = AtomOrigin::utf16_string,
            });
            i = j + 2; // step past the terminator
        } else {
            i = j + 2; // skip rejected run + first non-printable unit
        }
    }
}

} // anonymous namespace

void AsciiStringAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;
    for (const auto& sec : image.sections()) {
        if (!should_scan_for_strings(sec)) continue;
        scan_ascii_in_section(sec, min_chars_, out);
    }
}

void Utf16StringAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;
    for (const auto& sec : image.sections()) {
        if (!should_scan_for_strings(sec)) continue;
        scan_utf16_in_section(sec, min_chars_, out);
    }
}

} // namespace mx::pe::chaos
