/**
 * @file export_directory_scanner.hpp
 * @brief Walks the EXPORT directory and emits one `Reference` per
 *        RVA-bearing slot the chaos shuffler needs to rewrite.
 *
 * The EXPORT directory `IMAGE_DIRECTORY_ENTRY_EXPORT` (idx 0) points
 * at exactly one `IMAGE_EXPORT_DIRECTORY` struct carrying these
 * RVA-bearing slots:
 *
 *   * `Name`                  — RVA of the module's ASCIIZ name.
 *   * `AddressOfFunctions`    — RVA of the Export Address Table
 *                               (EAT) — `NumberOfFunctions` × 4-byte
 *                               RVAs to functions or forwarder strings.
 *   * `AddressOfNames`        — RVA of the name pointer table —
 *                               `NumberOfNames` × 4-byte RVAs to
 *                               ASCIIZ name strings.
 *   * `AddressOfNameOrdinals` — RVA of the name-ordinal table —
 *                               `NumberOfNames` × 2-byte ordinals.
 *                               Ordinals are not RVAs, so the table
 *                               *contents* are not scanned, but the
 *                               *pointer* to the table is.
 *
 * Each non-zero EAT entry stores either a function RVA (resolves
 * inside the image) or a forwarder-string RVA (resolves to an
 * ASCIIZ "DllName.FuncName" record inside the export section). Both
 * shapes are RVAs and emitted as `byte4`/`rva` references.
 *
 * Each non-zero name-pointer entry stores the RVA of the ASCIIZ
 * function name string. Same encoding.
 *
 * Why the redundancy with the chunk planner's "pin the section
 * containing each DataDirectory entry" rule: the planner pins the
 * section containing the `IMAGE_EXPORT_DIRECTORY` struct, which is
 * usually `.rdata`. In most layouts the EAT / name table / name
 * strings live in the same section, so the references are no-ops. But
 * exported function bodies live in `.text` (different section, also
 * pinned because it's code) — and forwarder strings can theoretically
 * land in any section. Scanning unconditionally guarantees correctness
 * regardless of layout.
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
 * @brief EXPORT-directory deep scanner — see file header.
 *
 * No-op on PE32 (chaos pipeline runs only on PE32+).
 */
class ExportDirectoryScanner final {
public:
    ExportDirectoryScanner() noexcept = default;

    /**
     * @brief Walk `image`'s EXPORT directory and append every
     *        emitted reference to `table`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * EXPORT directory empty (`VirtualAddress == 0`) → no-op.
     *   * The IMAGE_EXPORT_DIRECTORY struct does not fit inside its
     *     containing section → no-op (a malformed image we refuse
     *     to fix up).
     *   * EAT / name pointer table that walks past its section's
     *     data → walk truncated to the entries that fully fit.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
