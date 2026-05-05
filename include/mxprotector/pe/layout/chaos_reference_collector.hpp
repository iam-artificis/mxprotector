/**
 * @file chaos_reference_collector.hpp
 * @brief Walk every refmap scanner over a `PeImage` and return one
 *        accumulated `ReferenceTable`.
 *
 * @details The chaos pipeline runs ~9 distinct reference scanners,
 *          each surfacing a different family of byte slots that need
 *          remapping after sub-block shuffle: code-side rel32 / RIP-rel,
 *          PE-structure pointers, deep-directory tables, UNWIND_INFO
 *          trailers, switch jump tables, obfuscated tail-dispatch,
 *          VM `CallPop` trampolines, fall-back DIR64 relocations,
 *          plus pre-scanned slot overrides emitted by the indirect-call
 *          stub pass and the ChainInfo emitter.
 *
 *          Pulling the orchestration into its own translation unit
 *          keeps the chaos layout class thin and lets new scanners
 *          drop in without touching the layout file.
 */

#pragma once

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx::pe::chaos {

/**
 * @brief Run every refmap scanner over @p image and return the
 *        accumulated reference table.
 *
 * @details Scanner ordering is irrelevant — each scanner only
 *          appends — but we run code → structure → directories →
 *          UNWIND_INFO → switch / obfuscated JT → CallPop trampolines
 *          → fall-back DIR64 → pre-scanned overrides → extra-RVA
 *          overrides, so logs read in increasing-detail order. The
 *          reserved capacity (8192) is sized for typical Windows
 *          binaries; the table grows as needed.
 */
[[nodiscard]] refmap::ReferenceTable scan_all_references(const PeImage& image);

} // namespace mx::pe::chaos
