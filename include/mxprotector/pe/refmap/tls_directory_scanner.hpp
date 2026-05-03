/**
 * @file tls_directory_scanner.hpp
 * @brief Walks the TLS directory and emits one `Reference` per
 *        absolute-VA slot the chaos shuffler needs to rewrite.
 *
 * The TLS directory `IMAGE_DIRECTORY_ENTRY_TLS` (idx 9) points at one
 * `IMAGE_TLS_DIRECTORY64` struct. Unlike most PE directories, every
 * pointer field inside it is stored as an *absolute virtual address*
 * (image base + RVA), not as an RVA — the loader rewrites these via
 * `.reloc` entries at load time, but during chaos shuffling we have
 * to handle them ourselves so the static image references stay valid.
 *
 * RVA-bearing (encoded as absolute VA) slots:
 *
 *   * `StartAddressOfRawData` — VA of the first byte of TLS data.
 *   * `EndAddressOfRawData`   — VA one-past-end of TLS data.
 *   * `AddressOfIndex`        — VA of a writable cell holding the
 *                                TLS slot index after thread init.
 *   * `AddressOfCallBacks`    — VA of a null-terminated array of
 *                                TLS-callback function VAs.
 *
 * The callback array itself is a sequence of 8-byte absolute VAs,
 * each pointing at a `VOID NTAPI Callback(PVOID, DWORD, PVOID)`
 * function. Each non-zero entry emits one `byte8`/`absolute_va`/
 * `tls_callback` reference.
 *
 * Why this scanner *and* the .reloc scanner: every absolute VA in the
 * image gets a `.reloc` entry, so in principle the
 * `RelocAbsoluteVaScanner` already sees these slots and emits refs
 * for them. The TLS scanner exists for two reasons:
 *
 *   1. **Defence in depth** — if a build's `.reloc` is malformed or
 *      stripped (e.g. `--no-relocs`), we still pick up TLS refs.
 *   2. **Diagnostic clarity** — the TLS-tagged origin lets us
 *      distinguish TLS callbacks from other DIR64 entries in logs and
 *      assertions.
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
 * @brief TLS directory deep scanner — see file header.
 *
 * No-op on PE32 (chaos pipeline runs only on PE32+).
 */
class TlsDirectoryScanner final {
public:
    TlsDirectoryScanner() noexcept = default;

    /**
     * @brief Walk `image`'s TLS directory and append every emitted
     *        reference to `table`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * TLS directory empty → no-op.
     *   * The IMAGE_TLS_DIRECTORY64 struct does not fit inside its
     *     containing section → no-op.
     *   * VA slots whose stored value is below `image_base` (would
     *     underflow the RVA conversion) → skipped per-slot.
     *   * Callback array out-of-section → walk halts at the last
     *     entry that fully fits.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
