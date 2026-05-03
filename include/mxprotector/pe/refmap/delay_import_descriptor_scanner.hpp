/**
 * @file delay_import_descriptor_scanner.hpp
 * @brief Walks the DELAY_IMPORT directory and emits one `Reference`
 *        per RVA-bearing slot the chaos shuffler needs to rewrite.
 *
 * The DELAY_IMPORT directory `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`
 * (idx 13) points at a null-terminated array of
 * `IMAGE_DELAYLOAD_DESCRIPTOR` records. Each record carries six RVA
 * fields (when the `RvaBased` attribute bit is set, which is the
 * modern x64 norm):
 *
 *   * `DllNameRVA`                  — RVA of the DLL's ASCIIZ name.
 *   * `ModuleHandleRVA`             — RVA of the HMODULE cache slot
 *                                     (writable; the runtime fills it
 *                                     after the first call).
 *   * `ImportAddressTableRVA`       — RVA of the IAT (8-byte thunks).
 *   * `ImportNameTableRVA`          — RVA of the INT (8-byte thunks).
 *   * `BoundImportAddressTableRVA`  — RVA of an optional bound IAT
 *                                     (zero when not bound).
 *   * `UnloadInformationTableRVA`   — RVA of an optional unload info
 *                                     table (zero when no unload
 *                                     support emitted).
 *
 * Each non-ordinal thunk in the IAT and INT stores the RVA of an
 * `IMAGE_IMPORT_BY_NAME` record in the low 4 bytes of the 8-byte
 * slot. Same encoding as regular IMPORT thunks.
 *
 * What this scanner deliberately does NOT touch:
 *
 *   * Records with `(Attributes & 1) == 0` — the RvaBased bit is
 *     clear, so all fields are absolute 32-bit VAs that cannot be
 *     ramapped through the chunk planner. Legacy compilers only;
 *     modern x64 toolchains always set the bit.
 *   * The HMODULE cache cell pointed at by `ModuleHandleRVA` — the
 *     bytes there are runtime state, not RVAs.
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
 * @brief DELAY_IMPORT directory deep scanner — see file header.
 *
 * No-op on PE32 (chaos pipeline runs only on PE32+).
 */
class DelayImportDescriptorScanner final {
public:
    DelayImportDescriptorScanner() noexcept = default;

    /**
     * @brief Walk `image`'s DELAY_IMPORT directory and append every
     *        emitted reference to `table`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * DELAY_IMPORT directory empty → no-op.
     *   * Descriptor with `(Attributes & 1) == 0` (legacy VA-based) →
     *     skipped per-descriptor; scan continues for siblings.
     *   * Descriptor table truncated past section bounds → walker
     *     stops at the last descriptor that fully fits.
     *   * Thunk array truncated past section bounds → walker stops
     *     at the last thunk that fully fits.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
