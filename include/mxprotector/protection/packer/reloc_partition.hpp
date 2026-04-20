/**
 * @file reloc_partition.hpp
 * @brief Build-time partitioning of `.reloc` entries into
 *        mapper-visible and stub-private halves.
 *
 * ### Why
 *
 * The packer encrypts selected sections (`.text`, the CFF trampoline
 * section, the VM blob section) at build time. A mapper — whether
 * kdmapper, `MmLoadSystemImage`, the user-mode Windows loader, or
 * any third-party DLL injector — walks the `.reloc` directory at
 * load time and applies `delta = runtime_base - preferred_base` to
 * every `IMAGE_REL_BASED_DIR64` entry. If the target address of any
 * such entry falls inside an encrypted section, the mapper modifies
 * ciphertext BEFORE our stub gets control. The stub's XOR decrypt
 * then runs against mutated bytes and produces garbage plaintext at
 * exactly the relocation targets.
 *
 * Setting `IMAGE_FILE_RELOCS_STRIPPED` discourages some mappers
 * from applying relocations, but is not a universal guarantee —
 * several well-known injectors (kdmapper among them) ignore the
 * flag and always relocate. The only mapper-agnostic fix is to
 * make the visible `.reloc` directory *safe to apply* irrespective
 * of what the mapper decides.
 *
 * ### How
 *
 * For every `IMAGE_BASE_RELOCATION` block whose `page_rva` lies
 * inside an encrypted section's virtual coverage:
 *   1. Copy the block (header + non-`ABSOLUTE` entries) into a
 *      stub-private blob, preserving the original type bits.
 *   2. Rewrite the source entries in place: set the top 4 bits
 *      (type) to `IMAGE_REL_BASED_ABSOLUTE` (0). Mappers treat
 *      absolute entries as padding and skip them, so the visible
 *      block is still a valid `IMAGE_BASE_RELOCATION` with the
 *      same byte count — `DataDirectory[BASERELOC].Size` does
 *      not need updating.
 *
 * Blocks whose `page_rva` does not overlap any encrypted section
 * are left untouched. The mapper applies them to pointers in
 * `.data` / `.rdata` / header / etc., which are plaintext at rest
 * and therefore safe to relocate at load time.
 *
 * At runtime the packer stub walks the stub-private blob post-
 * decrypt via `emit_reloc_applier`, applying the same delta to
 * every entry it finds. The visible + stub-private blobs together
 * cover exactly the original entry set, with no double application.
 *
 * ### Granularity
 *
 * Partitioning is done per-block, not per-entry. A block covers a
 * single 4 KB page. Since PE sections are virtually page-aligned
 * in every real-world image this packer has been exercised on, a
 * block's page either lies wholly inside one section or wholly
 * inside another — mixed blocks do not occur. If a PE ever appears
 * whose sections are not page-aligned, the partition currently
 * treats the block as a single unit (follows the first section
 * match); documented here so any future hit on that edge is easy
 * to diagnose.
 *
 * ### Caller contract
 *
 * Call this function AFTER the target section list is finalised
 * (`collect_target_sections` in `packer_pass.cpp`) and BEFORE the
 * stub is emitted (`append_stub_artifacts` consumes the returned
 * blob). The function mutates the image's `.reloc` section bytes
 * in place; it does not touch the parsed `image.relocations()`
 * vector — that structure is a cache `PeBuilder` never consumes,
 * so keeping it untouched is a deliberate simplification.
 */

#pragma once

#include <cstdint>
#include <span>

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/packer_stub_patcher.hpp"

namespace mx {
class PeImage;
} // namespace mx

namespace mx::packer {

/**
 * @brief Output of `partition_encrypted_relocs`.
 */
struct RelocPartitionResult {
    /// Serialized `IMAGE_BASE_RELOCATION` blocks containing every
    /// reloc whose target page was inside an encrypted section.
    /// Empty when no such relocations existed (the image has no
    /// `.reloc` directory, or every block's page_rva is in a non-
    /// encrypted section).
    ///
    /// Format: identical to the on-disk `.reloc` directory — a
    /// sequence of 8-byte headers followed by 2-byte entries,
    /// preserving the original types. This is what
    /// `emit_reloc_applier` expects.
    ByteBuffer stub_private_blob;

    /// Number of non-absolute entries copied into the stub-private
    /// blob (and neutralised in the visible `.reloc`). Diagnostic.
    uint32_t   stub_private_entry_count = 0;

    /// Number of non-absolute entries left in the visible `.reloc`.
    /// Diagnostic.
    uint32_t   visible_entry_count = 0;

    /// Number of blocks that fell entirely inside an encrypted
    /// section range (neutralised in place, copied to stub-private).
    uint32_t   neutralised_block_count = 0;
};

/**
 * @brief Partition the image's `.reloc` directory.
 *
 * @param image               Image to mutate. If `.reloc` is absent
 *                            or empty, returns a zero-initialised
 *                            result.
 * @param encrypted_sections  Encrypted target sections. A block is
 *                            moved to stub-private iff its
 *                            `page_rva` overlaps any of these
 *                            sections' `[rva, rva + size)` ranges
 *                            — the `size` field is expected to be
 *                            the section's raw byte size
 *                            (`SectionInfo::data.size()`), which
 *                            is what `collect_target_sections`
 *                            already records.
 */
RelocPartitionResult partition_encrypted_relocs(
    PeImage&                         image,
    std::span<const TargetSection>   encrypted_sections);

} // namespace mx::packer
