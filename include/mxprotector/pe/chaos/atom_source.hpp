/**
 * @file atom_source.hpp
 * @brief `IAtomSource` — the polymorphic seam through which the
 *        atomic chaos planner discovers indivisible byte ranges.
 *
 * One `IAtomSource` implementation per category of atom:
 *
 *   * `InstructionAtomSource` — disassembles code sections via Zydis.
 *   * `AsciiStringAtomSource` — finds ASCIIZ runs in data sections.
 *   * `Utf16StringAtomSource` — UTF-16 LE runs.
 *   * `ImportTableAtomSource` — IMAGE_IMPORT_DESCRIPTOR + thunk +
 *     IMAGE_IMPORT_BY_NAME records.
 *   * `PdataAtomSource` — RUNTIME_FUNCTION entries.
 *   * `RelocBlockAtomSource` — IMAGE_BASE_RELOCATION blocks.
 *   * `RelocPointerAtomSource` — 8-byte slots at DIR64 reloc targets.
 *   * `LoadConfigAtomSource` — IMAGE_LOAD_CONFIG_DIRECTORY + tables.
 *   * `TlsAtomSource` — IMAGE_TLS_DIRECTORY64 + callback array.
 *   * `ExportTableAtomSource` — IMAGE_EXPORT_DIRECTORY + EAT/Names.
 *   * `ResourceTreeAtomSource` — IMAGE_RESOURCE_DIRECTORY tree.
 *   * `DebugDirectoryAtomSource` — IMAGE_DEBUG_DIRECTORY entries.
 *   * `DelayImportAtomSource` — IMAGE_DELAYLOAD_DESCRIPTOR records.
 *
 * The planner aggregates all source outputs in one `AtomTable`, then
 * calls `normalize()` to coalesce overlaps before computing the
 * permutation.
 *
 * SOLID:
 *   * SRP — every source covers exactly one PE-format concept.
 *   * OCP — adding a new format coverage = new source class, no
 *     edits to existing sources or to `AtomicChunkPlanner`.
 *
 * Threading: every `emit_atoms` call is a pure read of the image —
 * concurrent invocations on the same image and disjoint tables are
 * safe. The pipeline is single-threaded by construction so this is
 * theoretical.
 */

#pragma once

#include "mxprotector/pe/chaos/atom.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::chaos {

/**
 * @brief Polymorphic seam for atom emitters — see file header.
 */
class IAtomSource {
public:
    virtual ~IAtomSource() = default;

    /**
     * @brief Walk `image` and append every discovered atom to `out`.
     *
     * Sources MUST NOT clear or otherwise mutate `out` beyond
     * `add()`. Atoms produced may overlap each other or atoms from
     * earlier sources; the planner's `normalize()` resolves overlaps.
     *
     * Sources MUST NOT throw — failures (decode errors, OOB reads)
     * are skipped, never surfaced.
     */
    virtual void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const = 0;
};

} // namespace mx::pe::chaos
