/**
 * @file import_descriptor_scanner.hpp
 * @brief Walks the IMPORT directory and emits one `Reference` per
 *        RVA-bearing slot the chaos shuffler needs to rewrite.
 *
 * The IMPORT directory `IMAGE_DIRECTORY_ENTRY_IMPORT` (idx 1) points
 * at a null-terminated array of `IMAGE_IMPORT_DESCRIPTOR`. Each
 * descriptor carries three RVA fields:
 *
 *   * `Name`               — RVA of the imported DLL's ASCIIZ name.
 *   * `OriginalFirstThunk` — RVA of the Import Name Table (INT) — a
 *                            null-terminated array of 8-byte
 *                            `IMAGE_THUNK_DATA64` entries.
 *   * `FirstThunk`         — RVA of the Import Address Table (IAT) —
 *                            same shape as INT; the loader rewrites
 *                            this with resolved function VAs.
 *
 * Each non-ordinal thunk entry stores the RVA of an
 * `IMAGE_IMPORT_BY_NAME` record in the *low 4 bytes* of its 8-byte
 * slot. The high bit of the upper 32 bits (`IMAGE_ORDINAL_FLAG64 >> 32`)
 * being set means the entry is an ordinal import — we skip those
 * because the lower bits encode the ordinal number, not an RVA.
 *
 * What this scanner deliberately does NOT touch:
 *
 *   * The ASCIIZ DLL name string itself (no RVA-bearing field inside
 *     a string).
 *   * The `IMAGE_IMPORT_BY_NAME` records (no RVA-bearing field — only
 *     a `Hint` and the function name string).
 *
 * Why the redundancy with the chunk planner's "pin the whole section"
 * rule: the chunk planner pins `.rdata` because the IMPORT directory
 * lives there, so in *most* practical layouts the bytes pointed at by
 * these references never move and the scanner is a no-op. But some
 * compilers / linker scripts split the IAT into a separate `.idata`
 * section, or the BoundImport / DelayLoad descriptors can target a
 * non-pinned section. Emitting the references unconditionally keeps
 * the shuffle correct under every layout the scanners cover.
 *
 * Threading: stateless; safe to share across threads. Construct on
 * the stack, call `scan`, throw away.
 */

#pragma once

#include "mxprotector/pe/refmap/reference.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

/**
 * @brief IMPORT-directory deep scanner — see file header.
 *
 * No-op on PE32 (chaos pipeline runs only on PE32+).
 */
class ImportDescriptorScanner final {
public:
    ImportDescriptorScanner() noexcept = default;

    /**
     * @brief Walk `image`'s IMPORT directory and append every
     *        emitted reference to `table`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * IMPORT directory empty (`VirtualAddress == 0`) → no-op.
     *   * Descriptor table truncated past the section's data → walker
     *     stops at the last entry that fully fits.
     *   * Thunk array truncated past its section's data → walker
     *     stops at the last entry that fully fits.
     *   * Out-of-section thunk RVAs → skipped per-entry, scan
     *     continues.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
