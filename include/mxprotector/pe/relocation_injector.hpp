/**
 * @file relocation_injector.hpp
 * @brief High-level API for inserting `IMAGE_REL_BASED_*` entries
 *        into the image's relocation table at any point in the
 *        pipeline.
 *
 * Today passes that emit code containing absolute pointers (e.g. a
 * `lea rax, [imagebase + rva]` patched at load time, or a DIR64
 * pointer table) have no clean way to announce a relocation entry —
 * they would need to find the right `RelocationBlock`, append a raw
 * `RelocationEntry`, and create a new block when none exists for
 * the target page.
 *
 * R2.4 introduces this facade so passes can say "I just emitted an
 * absolute pointer at RVA X — please relocate it" with one call. The
 * upcoming features that depend on this seam:
 *
 *   - `--chaos` (R2.5 / feature B): when `.data` and `.rdata` are
 *     interleaved into a single section, any DIR64 pointer that
 *     used to live there must be relocated to its new RVA.
 *   - Mutation overflow (feature A): although the spill-stub uses a
 *     RIP-relative `JMP rel32` (no relocation needed), some mutated
 *     bodies may emit `LEA rax, [rip + …]` whose RIP-relative range
 *     overflows after spilling — those will use this API.
 *
 * Design rules:
 *   - The injector groups entries into the right `RelocationBlock`
 *     by 4 KB page automatically. Callers never compute
 *     `page_rva = rva & ~0xFFF` themselves.
 *   - The order of entries within a block is not specified; tests
 *     verify only set-equality. The PE base-relocation directory
 *     accepts any order.
 *   - Stateless beyond the bound `PeImage` reference. Construct
 *     freely on the stack of the emitting helper.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe {

/**
 * @brief Page-aware injector for base-relocation entries.
 *
 * Wraps the `PeImage::relocations()` vector with a "by RVA" API:
 * the caller hands in a target RVA and a relocation type
 * (`IMAGE_REL_BASED_*`), and the injector finds (or creates) the
 * matching 4 KB-aligned `RelocationBlock` and appends the entry.
 */
class RelocationInjector {
public:
    /**
     * @brief Bind to a mutable image. Reference must outlive the
     *        injector. Construct one per emission helper; the cost
     *        is one pointer.
     */
    explicit RelocationInjector(PeImage& image) noexcept
        : image_(image) {}

    RelocationInjector(const RelocationInjector&)            = delete;
    RelocationInjector& operator=(const RelocationInjector&) = delete;

    /**
     * @brief Register a relocation entry at @p target_rva of @p type.
     *
     * The entry is appended to the `RelocationBlock` whose
     * `page_rva` covers @p target_rva. A fresh block is appended
     * when none exists for the target's page.
     *
     * @param target_rva  RVA of the bytes that need fixing up at
     *                    load time. Must be inside one of the image
     *                    sections — the injector does NOT validate
     *                    this; an out-of-bounds RVA is a programmer
     *                    error and will be flagged by the loader at
     *                    process start with a STATUS_ACCESS_VIOLATION.
     * @param type        One of the `IMAGE_REL_BASED_*` constants
     *                    from `pe_types.hpp`. Common cases:
     *                      - `IMAGE_REL_BASED_DIR64` for 64-bit
     *                        absolute pointers (the only kind on x64
     *                        that is not the no-op `ABSOLUTE`).
     *                      - `IMAGE_REL_BASED_HIGHLOW` for 32-bit
     *                        absolute pointers (x86 builds, or
     *                        legacy fields in PE32+ images).
     */
    void add(Rva target_rva, std::uint16_t type);

    /// @brief Convenience for the x64 default — DIR64.
    void add_dir64(Rva target_rva) {
        add(target_rva, IMAGE_REL_BASED_DIR64);
    }

    /// @brief Convenience for 32-bit absolute references — HIGHLOW.
    void add_highlow(Rva target_rva) {
        add(target_rva, IMAGE_REL_BASED_HIGHLOW);
    }

private:
    PeImage& image_;

    /// @brief Locate the block whose `page_rva` covers @p rva, or
    /// append a fresh one. Returns a reference into
    /// `image_.relocations()` — invalidated by subsequent calls.
    [[nodiscard]] RelocationBlock& block_for_page(Rva rva);
};

} // namespace mx::pe
