/**
 * @file reference_patcher.hpp
 * @brief Walks a `ReferenceTable` and rewrites every slot at its
 *        post-shuffle location to point at the post-shuffle target.
 *
 * The patcher closes the loop between the scanners (B.4.2-B.4.4)
 * and the chunk planner (B.4.5). For each `Reference`:
 *
 *   1. Remap the slot's location through `RvaRemapper` — find where
 *      the slot's bytes ended up after shuffling.
 *   2. Remap the slot's target through `RvaRemapper` — find where
 *      the byte the slot points at ended up.
 *   3. Encode the new target according to `Reference.encoding`:
 *      * `rel`         — `new_target - (new_location + width)`
 *      * `rva`         — `new_target` (raw RVA)
 *      * `absolute_va` — `image_base + new_target` (8-byte VA)
 *   4. Write `width` bytes of the encoded value at the new
 *      location, dispatched to either the section's `data` buffer
 *      (for section-located slots) or `image.nt_headers()` (for
 *      slots inside the PE header range).
 *
 * Pre-condition: the chunk-shuffle has already been applied to the
 * image's section bytes — the patcher writes into post-shuffle
 * positions. Calling the patcher *before* shuffling would smear
 * encoded values onto the wrong bytes.
 *
 * Threading: not safe for concurrent use; the chaos pipeline is
 * single-threaded by construction.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

/**
 * @brief Counters returned from one patcher run. Useful in logs and
 *        for test assertions.
 */
struct PatchStats {
    std::uint32_t total          = 0; ///< Total references walked.
    std::uint32_t patched        = 0; ///< References successfully written.
    std::uint32_t header_writes  = 0; ///< Slots written into NT headers.
    std::uint32_t section_writes = 0; ///< Slots written into a section's data.
    std::uint32_t skipped        = 0; ///< Slots whose location did not resolve.
};

/**
 * @brief Reference patcher — see file header.
 */
class ReferencePatcher final {
public:
    ReferencePatcher() noexcept = default;

    /**
     * @brief Apply every reference in `table` to `image` using
     *        `remapper` to compute new positions.
     *
     * Side effects: writes into `image.sections()[*].data` and
     * `image.nt_headers()` in place. The image's section table /
     * directory entries themselves are not modified — only their
     * payload bytes (the slot values).
     *
     * @return Per-category counts. The patcher does not fail-stop
     *         on a single unresolvable slot — those increment
     *         `skipped` and the run continues.
     */
    [[nodiscard]] PatchStats apply(
        PeImage&              image,
        const ReferenceTable& table,
        const RvaRemapper&    remapper) const;
};

} // namespace mx::pe::refmap
