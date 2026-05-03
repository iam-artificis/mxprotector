/**
 * @file load_config_directory_scanner.hpp
 * @brief Walks the LOAD_CONFIG directory and emits one `Reference`
 *        per VA-bearing slot the chaos shuffler needs to rewrite.
 *
 * The LOAD_CONFIG directory `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`
 * (idx 10) carries `IMAGE_LOAD_CONFIG_DIRECTORY64` — a struct that
 * has grown over time as Microsoft added Control Flow Guard, XFG,
 * EH continuation, and other security features. Two field categories
 * matter for chaos:
 *
 *   * **Absolute-VA pointer slots** — every CFG / SEH / volatile /
 *     enclave / RF table pointer field, plus `SecurityCookie`. Each
 *     non-zero slot whose VA is `>= image_base` emits one
 *     `byte8`/`absolute_va`/`load_config_directory` reference.
 *
 *   * **Function-table contents** — the CFG, IAT-taken, long-jump,
 *     and EH-continuation tables are arrays of stride-N records
 *     where the first 4 bytes of each record are an RVA into `.text`.
 *     Stride = `4 + ((GuardFlags >> 28) & 0xF)`. Each non-zero entry
 *     emits one `byte4`/`rva`/`load_config_table_entry` reference.
 *
 * Why this matters: the chunk planner pins the section that *holds*
 * the LOAD_CONFIG struct (typically `.rdata`), so the struct itself
 * is anchored. But the targets it points at — `.gfids` / `.giats` /
 * `.gehcont` / `.fptable` — are commonly emitted into their own
 * sections that no DataDirectory entry references directly. Without
 * deep scanning, those sections stay shuffleable while the LOAD_CONFIG
 * pointer slots still hold their pre-shuffle VAs, and the loader
 * dereferences a stale pointer at module start → CFG / EH crash.
 *
 * The directory's reported `Size` (the LOAD_CONFIG block's first
 * 4 bytes, mirrored in `DataDirectory[LOAD_CONFIG].Size`) bounds
 * the scan. Slots beyond `Size` did not exist when the image was
 * linked and must not be read.
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
 * @brief LOAD_CONFIG directory deep scanner — see file header.
 *
 * No-op on PE32 (chaos pipeline runs only on PE32+).
 */
class LoadConfigDirectoryScanner final {
public:
    LoadConfigDirectoryScanner() noexcept = default;

    /**
     * @brief Walk `image`'s LOAD_CONFIG directory and append every
     *        emitted reference to `table`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * LOAD_CONFIG directory empty → no-op.
     *   * LOAD_CONFIG out-of-section → no-op.
     *   * Slot offset beyond reported `Size` → skipped per-slot.
     *   * Slot VA below `image_base` (would underflow) → skipped.
     *   * Function table out-of-section / oversized count →
     *     truncated to entries that fully fit.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
