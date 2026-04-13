/**
 * @file string_scanner.hpp
 * @brief [BUILDER] Finds printable-ASCII string candidates in a byte buffer.
 *
 * Part of the S2 string-protection pipeline. The scanner is a pure
 * byte-level analyser: it knows nothing about PE, sections, or XREFs.
 * Given a raw buffer (typically the contents of a `.rdata` section)
 * and that buffer's base RVA, it returns a list of printable-ASCII
 * runs that plausibly contain C strings — every run in the list is
 * a `CANDIDATE`, not a confirmed string. The XREF finder later
 * decides which candidates are actually referenced by `LEA rip+disp32`
 * instructions in `.text`; candidates with zero references stay
 * untouched at build time, so the scanner can be generous without
 * risk: false positives cost nothing.
 *
 * The scanner is deliberately kept trivial. Extra filters (heuristics
 * to drop RTTI symbol names, import table entries, CRT tables) live
 * outside the scanner proper — they can be composed on top of the
 * candidate list if a specific binary needs tighter filtering. The
 * baseline rule is: a printable-ASCII run terminated by NUL, of at
 * least `min_length` bytes.
 *
 * The scanner's output views alias the input buffer. Callers must
 * keep the buffer alive for as long as they use the returned list.
 *
 * ## Namespace
 *
 * Lives under `mx::string_protect` alongside the other S2 building
 * blocks (`XrefFinder`, `StringEncryptor`, runtime emitter, the pass
 * orchestrator). The nested namespace mirrors how `anti_emulation`
 * and `anti_tamper` organise their internals — keeps the names short
 * inside the module and out of the way outside it.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::string_protect {

/**
 * @brief A single candidate discovered by `StringScanner::scan`.
 *
 * `rva_start` is the absolute RVA of the string's first byte in the
 * image (= `base_rva` passed to `scan` + offset within the buffer).
 * `length` is the number of printable bytes, not counting the NUL
 * terminator. `bytes` is a non-owning view aliasing the source
 * buffer's [offset, offset+length) range.
 */
struct FoundString {
    Rva              rva_start = 0;
    uint32_t         length    = 0;
    std::string_view bytes;
};

/**
 * @brief Tunables for `StringScanner`.
 *
 * `min_length` is the smallest number of printable bytes before a
 * run is accepted. 6 is empirically a good default: shorter runs
 * match far too many accidental sequences in jump tables, import
 * strings, and exception unwind data. Tests can lower it to probe
 * edge cases.
 *
 * `max_length` caps each candidate so that a single corrupt run of
 * printable bytes (a big lookup table mistaken for a string) cannot
 * eat an unbounded amount of memory in the XREF finder downstream.
 * 4096 is generous — real C strings above that size are vanishingly
 * rare and usually benefit from being excluded.
 *
 * `require_null_terminator` is on by default: the byte immediately
 * after the printable run must be `\0`. This is the single
 * highest-signal filter against false positives because nearly every
 * real C string in an MSVC-built PE is null-terminated in `.rdata`.
 */
struct ScannerConfig {
    uint32_t min_length              = 6;
    uint32_t max_length              = 4096;
    bool     require_null_terminator = true;
};

class StringScanner {
public:
    StringScanner() = default;
    explicit StringScanner(ScannerConfig config) noexcept
        : config_(config) {}

    /**
     * @brief Scan `data` for printable-ASCII candidates.
     *
     * @param data      The byte buffer to scan (typically a section's data).
     * @param base_rva  The RVA of `data[0]` inside the image. Used to
     *                  stamp absolute `rva_start` values into the returned
     *                  records so downstream modules don't need to know
     *                  about the section layout.
     *
     * @return All candidates satisfying the scanner's configuration,
     *         in the order they appear in `data`. The returned views
     *         alias `data` — don't outlive the buffer.
     *
     * Scanning is linear in `data.size()` and allocation-bounded by
     * the output vector's capacity.
     */
    [[nodiscard]] std::vector<FoundString>
    scan(ByteView data, Rva base_rva) const;

    [[nodiscard]] const ScannerConfig& config() const noexcept { return config_; }

    /**
     * @brief Byte classifier: is `c` a byte that can legally appear
     *        inside an MxProtector candidate string?
     *
     * Printable ASCII is `0x20..0x7E`. We additionally accept `\t`
     * (0x09), `\n` (0x0A), and `\r` (0x0D) — format strings like
     * `"[tag] message\n"` or `"\tcolumn1\tcolumn2\n"` are routine in
     * release builds and would otherwise get chopped at the newline,
     * leaving the "NUL-terminator" check to reject them entirely
     * because what follows the printable run is `\n`, not `\0`.
     *
     * The earlier policy excluded `\n`/`\r` on the theory that
     * multiline strings usually indicate binary data. In practice
     * that heuristic missed the most common printf-style logging
     * strings in every C/C++ program, which is much worse than the
     * occasional false positive from binary data.
     *
     * This is exposed so tests can probe the classifier directly
     * without constructing a full scanner.
     */
    [[nodiscard]] static constexpr bool is_string_byte(uint8_t c) noexcept {
        return (c >= 0x20 && c <= 0x7E) ||
               c == 0x09 || c == 0x0A || c == 0x0D;
    }

private:
    ScannerConfig config_{};
};

} // namespace mx::string_protect
