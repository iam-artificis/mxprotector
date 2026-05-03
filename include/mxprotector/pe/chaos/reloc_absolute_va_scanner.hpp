/**
 * @file reloc_absolute_va_scanner.hpp
 * @brief Walks the `.reloc` directory and emits one `Reference` per
 *        `IMAGE_REL_BASED_DIR64` slot found in the image's data.
 *
 * `.reloc` lists every byte the loader needs to fix up at load time:
 * 64-bit absolute virtual addresses embedded in code or data, used
 * for things like vtables, function pointers, RTTI, TLS callback
 * arrays, and any `mov rax, imm64` that refers to another image
 * RVA. When the chaos shuffler moves a byte to a new RVA, every
 * absolute VA stored anywhere in the image that pointed to that
 * byte must be rewritten so the binary still loads correctly.
 *
 * The scanner reads the existing `.reloc` block layout, identifies
 * every `IMAGE_REL_BASED_DIR64` entry, reads the 8 bytes at the
 * slot, computes its current target RVA (`stored_va - image_base`),
 * and emits one `byte8`/`absolute_va`/`reloc_absolute_va`
 * reference. The patcher (B.4.6) then computes the new target VA
 * by remapping `target_rva` and writing back the new 8-byte value.
 *
 * Why not also scan `IMAGE_REL_BASED_HIGHLOW` (32-bit absolute, the
 * PE32 case): the chaos pipeline runs only on x64 (PE32+) targets,
 * and PE32+ images always use `DIR64` for full 64-bit slots. A
 * stray HIGHLOW entry in an x64 binary is exotic enough to be a
 * real defect we should not silently fix up.
 *
 * Skip rules:
 *
 *   * `.reloc` directory empty or missing → no-op.
 *   * Block whose `BlockSize < 8` or that spills past the directory
 *     bounds → walk stops cleanly (the directory may have been
 *     truncated by an earlier pass).
 *   * `IMAGE_REL_BASED_ABSOLUTE` and other entry types → skipped.
 *   * Slot RVA outside any section, or 8-byte VA below `image_base`
 *     (would underflow the RVA conversion) → skipped, not fatal.
 */

#pragma once

#include "mxprotector/pe/chaos/reference.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::chaos {

/**
 * @brief `.reloc`-driven absolute-VA scanner — see file header.
 *
 * Stateless. Construct on the stack, call `scan`, throw away.
 */
class RelocAbsoluteVaScanner final {
public:
    RelocAbsoluteVaScanner() noexcept = default;

    /**
     * @brief Walk `image`'s `.reloc` directory and append one
     *        `Reference` per `IMAGE_REL_BASED_DIR64` slot.
     *
     * No-op when:
     *   * `image.is_64bit()` is `false`.
     *   * `DataDirectory[BASERELOC]` is empty.
     *   * The pointed-to bytes do not fit in any section.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::chaos
