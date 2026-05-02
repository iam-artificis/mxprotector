/**
 * @file section_intent.hpp
 * @brief Intent-based description of a section's contents and runtime
 *        permissions, decoupled from raw `IMAGE_SCN_*` bit-mask soup.
 *
 * Today every pass that emits a new PE section computes its own
 * `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | …` literal at the
 * call site of `SectionManager::add_section`. That couples each pass
 * to the on-wire PE encoding *and* makes it impossible for a single
 * higher-level policy (e.g. the upcoming `--chaos` mode that merges
 * everything into one RWX section) to override the layout without
 * reaching into every emission site.
 *
 * Phase R2.1 introduces this header as the seam: passes describe
 * **what they are emitting** (`SectionContentType`) and **what they
 * need at runtime** (`SectionPermissions`); a free factory translates
 * the pair into the `IMAGE_SCN_*` bit-mask the PE writer wants. R2.3
 * then plugs a `SectionEmitter` facade in front of `SectionManager`
 * and migrates every pass to declare its intent instead of computing
 * a bit-mask. R2.2 introduces the `LayoutPolicy` strategy that
 * intercepts the translation so chaos mode can rewrite both the
 * permission and the content type uniformly.
 *
 * Design rules:
 *   - Pure data + free function. No state, no allocations, no
 *     dependencies beyond `pe_types.hpp` for the `IMAGE_SCN_*`
 *     constants.
 *   - constexpr-evaluable so the migration in R2.3 produces zero
 *     runtime overhead vs the current literal masks.
 *   - One canonical mapping. Two passes that ask for the same intent
 *     must produce the same characteristics — otherwise downstream
 *     tools (PE-checkers, packers) see inconsistent flags on
 *     identically-described sections.
 */

#pragma once

#include <cstdint>

// `pe_types.hpp` historically pulls `core/types.hpp` *at its tail*
// for `ByteBuffer`, so any TU that wants to consume `pe_types.hpp`
// in isolation must source `core/types.hpp` first or the
// `SectionInfo` struct fails to parse. Until that ordering is fixed
// at its root, this header preserves the public-facing contract by
// pulling `core/types.hpp` upfront.
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe {

/**
 * @brief What kind of bytes the section will hold.
 *
 * The PE format distinguishes "this section holds executable code"
 * from "this section holds initialised data" via the `CNT_CODE` /
 * `CNT_INITIALIZED_DATA` characteristics bits. Disassemblers, dumpers
 * and the OS loader use these to decide whether to walk the bytes as
 * instructions or treat them as opaque blob.
 *
 *   * `code`             — pure executable region (e.g. mxprotector's
 *                          `.mxguard`, `.mxvm`). Sets `CNT_CODE`.
 *   * `data`             — pure read/write data (e.g. encrypted
 *                          string blobs). Sets `CNT_INITIALIZED_DATA`.
 *   * `mixed_code_data`  — section interleaves code and data. Sets
 *                          BOTH `CNT_CODE` and `CNT_INITIALIZED_DATA`.
 *                          Required for the `--chaos` layout where a
 *                          single section interleaves `.text` /
 *                          `.rdata` / `.data` to defeat the simple
 *                          "code lives in `.text`" assumption every
 *                          stock disassembler bakes in.
 */
enum class SectionContentType : std::uint8_t {
    code            = 0,
    data            = 1,
    mixed_code_data = 2,
};

/**
 * @brief Runtime page protection the section requires.
 *
 * Maps directly onto the `MEM_READ` / `MEM_WRITE` / `MEM_EXECUTE`
 * characteristics bits.
 *
 *   * `r`   — read-only data. e.g. `.rdata`-style constants.
 *   * `rx`  — executable code, no writes. Default for protected
 *             code sections (`.mxguard`, `.mxvm`, `.text`).
 *   * `rw`  — read/write data, no execution.
 *   * `rwx` — read/write/execute. Required by the packer's
 *             scratch section (RC4 KSA writes the s-box, then the
 *             stub jumps in) and by the `--chaos` unified section.
 *
 * Page protection on a real Windows loader follows these flags
 * exactly (modulo CET / DEP overrides) — `rwx` will be reported as
 * RWX by tools like Process Hacker and is one of the strongest
 * heuristics packed binaries trip; we ask for it explicitly.
 */
enum class SectionPermissions : std::uint8_t {
    r   = 0,
    rx  = 1,
    rw  = 2,
    rwx = 3,
};

/**
 * @brief One emit's full intent — the pair the PE writer needs.
 *
 * Aggregating into a single struct lets `LayoutPolicy::resolve()`
 * (R2.2) take and return one value, which is the cleanest seam for
 * the chaos override that rewrites *both* fields uniformly.
 */
struct SectionIntent {
    SectionContentType content;
    SectionPermissions perms;

    [[nodiscard]] constexpr bool operator==(const SectionIntent&) const noexcept = default;
};

/**
 * @brief Translate a `SectionIntent` to the `IMAGE_SCN_*` bit-mask
 *        the PE on-wire format expects.
 *
 * Constexpr — invoking with constant arguments folds at compile time,
 * so migrating a pass from a hand-built literal mask to
 * `make_section_characteristics(...)` produces identical machine
 * code. The function exists purely as a SOLID seam: every pass
 * funnels through this single mapping, and a future override (chaos
 * layout) only has to intercept the seam, not patch every call site.
 *
 * @param intent  Content type + runtime permissions the caller wants.
 * @return        The corresponding `IMAGE_SCN_*` bit-mask, ready to
 *                hand to `SectionManager::add_section` /
 *                `PeImage::add_section`.
 */
[[nodiscard]] constexpr std::uint32_t make_section_characteristics(
    SectionIntent intent) noexcept
{
    std::uint32_t mask = 0;

    // Content classification. `mixed_code_data` deliberately sets
    // BOTH bits — that combination is what lets a disassembler /
    // tool see an interleaved section and refuse to commit either
    // a flat code listing or a flat data dump.
    switch (intent.content) {
        case SectionContentType::code:
            mask |= IMAGE_SCN_CNT_CODE;
            break;
        case SectionContentType::data:
            mask |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            break;
        case SectionContentType::mixed_code_data:
            mask |= IMAGE_SCN_CNT_CODE
                  | IMAGE_SCN_CNT_INITIALIZED_DATA;
            break;
    }

    // Runtime permissions. `MEM_READ` is implicit on every variant —
    // a section the loader could not read would be unusable.
    switch (intent.perms) {
        case SectionPermissions::r:
            mask |= IMAGE_SCN_MEM_READ;
            break;
        case SectionPermissions::rx:
            mask |= IMAGE_SCN_MEM_READ
                  | IMAGE_SCN_MEM_EXECUTE;
            break;
        case SectionPermissions::rw:
            mask |= IMAGE_SCN_MEM_READ
                  | IMAGE_SCN_MEM_WRITE;
            break;
        case SectionPermissions::rwx:
            mask |= IMAGE_SCN_MEM_READ
                  | IMAGE_SCN_MEM_WRITE
                  | IMAGE_SCN_MEM_EXECUTE;
            break;
    }

    return mask;
}

} // namespace mx::pe
