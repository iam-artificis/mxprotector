/**
 * @file volatile_metadata_atom_source.hpp
 * @brief Pin the IMAGE_VOLATILE_METADATA structure pointed at by
 *        `LOAD_CONFIG.VolatileMetadataPointer` (B.4.10.4).
 *
 * Modern MSVC linkers can emit a volatile-metadata structure when
 * `/volatileMetadata` is enabled (default on for Windows 11 binaries
 * since 19H1). The CFG runtime reads this structure on
 * `__guard_check_icall_fptr`-style failure paths to decide between
 * crash and continue, so corruption manifests as random crashes.
 *
 * The structure layout starts with a 4-byte `Size` header that
 * gives the byte length of the directory itself (not counting the
 * pointed-to volatile-access / info-range tables, which are
 * separate atoms not currently emitted — they live in `.rdata` and
 * are typically just `IMAGE_REL_BASED_ABSOLUTE` paddings, immune
 * to RVA reshuffles).
 *
 * Source emits one atom covering the metadata block itself with
 * 4-byte alignment so the planner pins it at its original RVA.
 *
 * SOLID:
 *   * SRP — exactly one PE-format concern (volatile metadata block).
 *   * OCP — adding atom sources for sibling LOAD_CONFIG-pointed
 *     structures (DVRT, CHPE, enclave config) means new sibling
 *     classes; this one stays untouched.
 *
 * No-op when:
 *   * Image is not 64-bit (only PE32+ has a 64-bit pointer field).
 *   * `LOAD_CONFIG` directory is missing or smaller than the
 *     pointer-field offset.
 *   * `VolatileMetadataPointer` is zero.
 *   * The pointer's bytes can't be read or the resolved RVA is
 *     out of bounds.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Volatile metadata block atom source — see file header.
 */
class VolatileMetadataAtomSource final : public IAtomSource {
public:
    VolatileMetadataAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
