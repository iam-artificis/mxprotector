/**
 * @file structure_reference_scanner.hpp
 * @brief Walks the PE structure (NT headers + `.pdata`) and emits a
 *        `Reference` for every RVA-bearing slot the chaos shuffler
 *        will need to rewrite.
 *
 * Three categories of slots:
 *
 *   * `AddressOfEntryPoint` in `IMAGE_OPTIONAL_HEADER`. One slot,
 *     `byte4`/`rva`/`entry_point`.
 *
 *   * `DataDirectory[i].VirtualAddress` for every non-empty entry
 *     (i ∈ `[0, NumberOfRvaAndSizes)`). One `byte4`/`rva`/`data_directory_entry`
 *     reference per non-zero entry.
 *
 *   * `.pdata` `RUNTIME_FUNCTION` entries — three `byte4`/`rva`/
 *     `pdata_runtime_function` references per entry (`BeginAddress`,
 *     `EndAddress`, `UnwindInfoAddress`). The pointed-to function /
 *     unwind-info bytes may move; the entry RVAs need updating.
 *
 * What the scanner deliberately does NOT touch (yet):
 *
 *   * Internal directory pointers — Import descriptor `Original
 *     FirstThunk` / `FirstThunk` / `Name`, Export `AddressOfFunctions`
 *     / `AddressOfNames` / `AddressOfNameOrdinals`, Resource directory
 *     internals, TLS callback array. The chaos planner pins the
 *     directory contents themselves so internal RVAs stay valid by
 *     construction.
 *
 *   * Absolute VAs in data — handled by
 *     `RelocAbsoluteVaScanner` (B.4.4) via the `.reloc` directory.
 *
 * Header-RVA references (entry point, data-directory entries) live
 * at low RVAs inside the PE header range, not in any section. The
 * patcher (B.4.6) writes through `PeImage::nt_headers()` for those
 * references; section-located references are written into the
 * section's data buffer.
 */

#pragma once

#include "mxprotector/pe/chaos/reference.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::chaos {

/**
 * @brief PE-structure reference scanner — see file header.
 *
 * Stateless. Construct on the stack, call `scan`, throw away.
 */
class StructureReferenceScanner final {
public:
    StructureReferenceScanner() noexcept = default;

    /**
     * @brief Walk `image`'s NT headers + `.pdata` and append every
     *        emitted reference to `table`.
     *
     * No-op when `image.is_64bit()` is `false` — the chaos pipeline
     * only runs on PE32+ targets, and this scanner reads
     * `IMAGE_NT_HEADERS64`-shaped fields exclusively.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::chaos
