/**
 * @file resource_directory_scanner.hpp
 * @brief Recursively walks the RESOURCE directory tree and emits one
 *        `Reference` per `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData`
 *        slot it finds.
 *
 * The RESOURCE directory `IMAGE_DIRECTORY_ENTRY_RESOURCE` (idx 2) is
 * a nested tree:
 *
 *   `IMAGE_RESOURCE_DIRECTORY` (16 B header)
 *     └── N × `IMAGE_RESOURCE_DIRECTORY_ENTRY` (8 B each)
 *           ├── Subdirectory  → recurse via offset (relative to .rsrc)
 *           └── Data entry    → `IMAGE_RESOURCE_DATA_ENTRY`
 *                               (`OffsetToData` is a full RVA)
 *
 * Two pointer flavours appear in the tree:
 *
 *   * `IMAGE_RESOURCE_DIRECTORY_ENTRY.OffsetToData` — when the
 *     subdirectory bit is set, this is an *offset relative to the
 *     `.rsrc` directory's base*. NOT an RVA. As long as the .rsrc
 *     section is pinned (which it is — it's a DataDirectory entry),
 *     these offsets stay valid by construction. We do not emit refs
 *     for them.
 *
 *   * `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` — despite the name,
 *     this is a *full RVA* into the image. Resource bytes typically
 *     live inside .rsrc (also pinned), but the format permits them
 *     to live anywhere. We emit a `byte4`/`rva`/`resource_data_entry`
 *     reference for every leaf so chaos shuffling stays correct
 *     regardless of layout.
 *
 * Recursion guard: the walker stops at depth 8 (PE practice rarely
 * goes past 3 — Type/Name/Lang/Data — so 8 is plenty of headroom and
 * blocks any malformed cycle).
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
 * @brief RESOURCE directory deep scanner — see file header.
 *
 * No-op on PE32 (chaos pipeline runs only on PE32+).
 */
class ResourceDirectoryScanner final {
public:
    ResourceDirectoryScanner() noexcept = default;

    /**
     * @brief Walk `image`'s RESOURCE directory tree and append one
     *        reference per leaf data entry to `table`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * RESOURCE directory empty → no-op.
     *   * RESOURCE directory's host section not found → no-op.
     *   * Subdirectory offset out-of-section → that branch silently
     *     dropped; siblings continue.
     *   * Recursion depth > 8 → branch silently dropped.
     */
    void scan(const PeImage& image, ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
