/**
 * @file reloc_rebuilder.hpp
 * @brief Rewrite the `.reloc` directory after a chunk shuffle (B.4.10.3).
 *
 * The chaos shuffle moves bytes inside the unified section. Every
 * relocatable slot (`IMAGE_REL_BASED_DIR64` target) gets a new RVA
 * that the existing `.reloc` directory still encodes against the
 * OLD position. Without rewriting `.reloc`, the Windows loader
 * applies the ASLR delta to the old slot positions — which now
 * hold unrelated bytes — and corrupts the image.
 *
 * `RelocRebuilder` walks the old directory, runs every entry's
 * slot RVA through `RvaRemapper::remap`, regroups the entries by
 * the new 4 KiB page, and emits a fresh byte stream that fits in
 * the original directory's capacity (always true under the chaos
 * planner — pinned `.reloc` blocks keep their old size class).
 *
 * Operates after the planner has shuffled bytes and after
 * `ReferencePatcher` has rewritten slot contents. The slot bytes
 * (8-byte absolute VAs) already carry preferred-image-base values
 * pointing at the new target RVA, so the loader's ASLR delta
 * application produces the correct runtime address as long as the
 * `.reloc` entries point at the new slot positions.
 *
 * SOLID:
 *   * SRP — the rebuilder neither parses the directory itself nor
 *     reads atoms; it only translates and re-emits.
 *   * OCP — adding new reloc entry types is a switch in the entry
 *     parser; the rebuilder does not branch on type semantics.
 *
 * Threading: not safe for concurrent mutation. Pure read of
 * remapper, mutation of one image.
 */

#pragma once

#include <cstdint>

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

class RvaRemapper;

/**
 * @brief Result of a `.reloc` rebuild attempt.
 */
struct RelocRebuildStats {
    /// Total entries parsed out of the old directory.
    std::uint32_t parsed = 0;
    /// Entries successfully translated and emitted.
    std::uint32_t translated = 0;
    /// `IMAGE_REL_BASED_ABSOLUTE` (type 0) padding entries kept.
    std::uint32_t absolute_padding = 0;
    /// `true` when the new directory bytes fit and were written.
    bool          written = false;
};

/**
 * @brief Post-shuffle `.reloc` rewriter — see file header.
 */
class RelocRebuilder {
public:
    RelocRebuilder() = default;

    /**
     * @brief Rebuild `.reloc` in place using the supplied remapper.
     *
     * Pre-conditions:
     *   * `remapper.finalize()` has been called and returned `true`.
     *   * The image's `.reloc` directory bytes live inside one of
     *     `image.sections()` (the chaos planner keeps them in the
     *     unified section).
     *
     * Behaviour:
     *   * No-op (returns `parsed == 0`) when the image has no
     *     `.reloc` directory or the directory is malformed.
     *   * No-op + `written = false` when the new bytes do not fit
     *     in the old directory's capacity. The caller can detect
     *     this via the `written` flag and surface as an error.
     *   * Otherwise overwrites the old directory bytes in place and
     *     zero-pads the residual capacity (pad bytes are loader-
     *     ignored because each block's `SizeOfBlock` controls the
     *     walk).
     *
     * @return Diagnostic counts (see `RelocRebuildStats`).
     */
    [[nodiscard]] RelocRebuildStats rebuild(
        PeImage&           image,
        const RvaRemapper& remapper) const;
};

} // namespace mx::pe::refmap
