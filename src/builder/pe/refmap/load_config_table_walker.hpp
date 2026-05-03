/**
 * @file load_config_table_walker.hpp
 * @brief Helper used by `LoadConfigDirectoryScanner` to walk the
 *        five RVA-bearing function tables LOAD_CONFIG can carry.
 *
 * CFG / IAT-taken / longjmp / EH-continuation / SEH-handler tables
 * all share the same shape — `count` records of `stride` bytes each,
 * the first 4 bytes of every record being an RVA into `.text`. The
 * only differences are the table's offset / count fields inside
 * LOAD_CONFIG and the stride (4 plus optional metadata for
 * CFG-class tables; pure 4 for EH-cont / SEH).
 *
 * Internal to the refmap module — not part of the public include
 * surface.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

/**
 * @brief Walk an array of `count` records of `stride` bytes each
 *        starting at `table_rva`. Emit one `byte4`/`rva`/
 *        `load_config_table_entry` reference per non-zero record.
 *
 * Pre-conditions:
 *   * `stride >= 4` — every record has at least the 4-byte RVA.
 *   * `count > 0` — caller has already screened empty tables.
 *   * `table_rva != 0`.
 *
 * Truncates to the records that fully fit inside the host section
 * (a malformed `count` cannot drive an OOB read).
 */
void walk_rva_function_table(
    const PeImage&  image,
    Rva             table_rva,
    std::uint64_t   count,
    std::uint32_t   stride,
    ReferenceTable& table);

} // namespace mx::pe::refmap
