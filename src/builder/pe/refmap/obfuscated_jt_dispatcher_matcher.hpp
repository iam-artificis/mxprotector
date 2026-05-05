/**
 * @file obfuscated_jt_dispatcher_matcher.hpp
 * @brief Private helper — recognise the 7-instruction obfuscated
 *        jump-table dispatcher prologue.
 *
 * The dispatcher pattern (compiler-emitted by some MSVC switch
 * lowering modes when string-pool / dispatch-jump-table obfuscation
 * is enabled at the compiler level) looks like:
 *
 *      lea    base, [rip + jt_disp32]      ; rip-relative table base
 *      mov    eax,  dword ptr [base+rax*4] ; 4-byte slot
 *      xor    eax,  imm32                  ; static key (NOT stack key)
 *      movsxd rax,  eax                    ; sign-extend
 *      add    base, rax                    ; target = base + delta
 *      jmp    base                         ; (or: push base; ret)
 *
 * `find_dispatchers` walks every code section, decodes with Zydis,
 * and returns one `DispatcherSite` per matched pattern. The
 * matching is strict (exact mnemonics, register pairs, operand
 * shapes) to avoid false positives.
 *
 * Lives in `src/builder/pe/refmap/` — internal to the refmap
 * scanner. Public consumers see only `ObfuscatedJtScanner::scan`
 * from `obfuscated_jt_scanner.hpp`; this header is the
 * implementation seam between the two halves of that scanner
 * (dispatcher matching here, jump-table-entry walking in
 * obfuscated_jt_scanner.cpp).
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::refmap {

/**
 * @brief One recognised dispatcher site.
 *
 * `jt_base_rva` is the rip-relative LEA target — the start of the
 * encrypted 4-byte jump-table slots. `key` is the imm32 the
 * dispatcher XORs into each slot before sign-extension.
 */
struct DispatcherSite {
    Rva           jt_base_rva;
    std::uint32_t key;
};

/**
 * @brief Find every dispatcher pattern in every code section.
 *
 * Deduped (one entry per unique `jt_base_rva`) and sorted by
 * `jt_base_rva` so the table-entry walker can use the next-base
 * RVA as an upper bound on the current table.
 */
[[nodiscard]] std::vector<DispatcherSite>
    find_dispatchers(const PeImage& image);

} // namespace mx::pe::refmap
