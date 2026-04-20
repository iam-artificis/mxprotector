/**
 * @file section_name_pool.hpp
 * @brief Stealth pools for the pipeline's injected-section names.
 *
 * The packer (and several earlier passes — virtualisation, CFF
 * flattening, string protection, guard) inject new PE sections
 * into the protected image. Hardcoding recognisable names like
 * `.mxvm` / `.mxpack` makes reverse engineering trivial: a grep on
 * the section table names the whole pipeline. To defeat that, each
 * build randomly picks names from a pool that resembles legitimate
 * toolchain output for the corresponding binary shape.
 *
 * Two pools exist:
 *   * User-mode (EXE / DLL) — MSVC / clang idioms like `.rdata2`,
 *     `.tls1`, `.CRT$XC`, `.didat`, `.xtors`, `.orpc`.
 *   * Kernel driver (.sys) — Windows kernel image idioms like
 *     `PAGEBGFX`, `PAGEKD`, `PAGEVRFY`, `NONPAGED`, `ALMOSTRO`,
 *     `CDEXEC`, sampled from real ntoskrnl / hal / fs-driver
 *     section-table snapshots. Using user-mode names in a `.sys`
 *     would stand out under even a cursory look in a kernel
 *     debugger.
 *
 * The module is a pure utility: the pools themselves are
 * compile-time constants and `pick_section_names` is a thin
 * Fisher–Yates sampler that never touches the filesystem or
 * network. Everything is unit-testable in isolation.
 */

#pragma once

#include <string>
#include <vector>

#include "mxprotector/core/context.hpp"      // SectionNameMap
#include "mxprotector/core/randomizer.hpp"   // Randomizer
#include "mxprotector/target/target_info.hpp" // BinaryKind

namespace mx {

/**
 * @brief Return the stealth section-name pool for the given target
 *        shape.
 *
 * Every entry is ≤ 8 ASCII bytes (PE section name limit) and
 * starts either with `.` (user-mode MSVC/clang idiom) or an
 * uppercase letter (kernel driver idiom). The pool has ≥ 5
 * entries so `pick_section_names` can draw the full {vm, cff,
 * packer, str, guard} slot set without repetition.
 *
 * `BinaryKind::executable` and `BinaryKind::dynamic_library` share
 * the user-mode pool. `BinaryKind::kernel_driver` uses the driver
 * pool. `BinaryKind::unknown` falls back to the user-mode pool —
 * the caller should ordinarily have resolved the kind from the
 * PE parser before reaching this code, so this fallback exists
 * mostly as a don't-crash-the-build safety net.
 */
[[nodiscard]] const std::vector<std::string>&
stealth_section_pool_for(target::BinaryKind kind);

/**
 * @brief Pick the five stealth section names the pipeline needs.
 *
 * @param kind                 Target binary kind (dispatches pool).
 * @param debug_section_names  When true, short-circuits and
 *                             returns the fixed
 *                             `.mxvm / .mxprot1 / .mxpack /
 *                             .mxstr / .mxguard` set regardless of
 *                             `kind`. Set by `--debug-sections` on
 *                             the command line.
 * @param rng                  Used to shuffle a copy of the pool;
 *                             same seed ⇒ same draws.
 *
 * The five output slots are filled in a fixed order (vm / cff /
 * packer / str / guard) and every slot gets a distinct name.
 * Guard slot is filled even for kernel drivers, where the
 * `GuardPass` is gated off — the slot is never referenced but
 * keeping the function's output shape uniform simplifies the
 * call site.
 */
[[nodiscard]] SectionNameMap pick_section_names(
    target::BinaryKind kind,
    bool               debug_section_names,
    Randomizer&        rng);

} // namespace mx
