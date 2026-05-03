/**
 * @file atom.hpp
 * @brief Data model for the atom-level chaos planner (B.4.9).
 *
 * An **atom** is an indivisible byte range inside the image. Atoms
 * cover bytes that have semantic meaning when read together — an
 * x86 instruction, an ASCIIZ string, an `IMAGE_IMPORT_DESCRIPTOR`,
 * etc. The chaos shuffler may permute atoms among themselves but
 * must never split one across the layout boundary.
 *
 * Compared to the fixed-256B chunk model the earlier B.4.7 shuffler
 * used, atoms allow the shuffle to:
 *
 *   * Move individual instructions, so `.text` can interleave with
 *     `.data` byte-for-byte while preserving instruction boundaries.
 *
 *   * Move entire structures (descriptors, runtime-function entries,
 *     reloc blocks) without slicing them mid-record.
 *
 *   * Keep long ASCIIZ strings (DLL names, function names, format
 *     strings) intact even when they exceed the previous chunk size.
 *
 * Atoms are produced by `IAtomSource` implementations — one source
 * per category (instruction, string, import descriptor, …). Sources
 * append to a shared `AtomTable`; the `AtomicChunkPlanner` then
 * normalises the table (sort + merge overlaps) and builds the
 * permutation.
 *
 * Threading: `Atom` is a value type. `AtomTable` is move-only and
 * not safe for concurrent mutation. The chaos pipeline is single-
 * threaded by construction.
 */

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::pe::chaos {

/**
 * @brief Origin tag for an atom — diagnostic only, the planner does
 *        not branch on it. Used in logs and merge-priority decisions.
 */
enum class AtomOrigin : std::uint8_t {
    pe_header,                   ///< `[0, SizeOfHeaders)` — must stay at fixed RVA
    instruction,                 ///< Single x86 instruction (1-15 bytes)
    instruction_undecoded,        ///< Bytes Zydis could not decode (1B each)
    ascii_string,                ///< ASCIIZ string ≥ threshold + NUL
    utf16_string,                ///< UTF-16 LE string ≥ threshold + NUL
    import_descriptor,           ///< `IMAGE_IMPORT_DESCRIPTOR` (20B)
    import_thunk,                ///< `IMAGE_THUNK_DATA64` (8B)
    import_by_name,              ///< `IMAGE_IMPORT_BY_NAME` (Hint + Name)
    pdata_runtime_function,      ///< `RUNTIME_FUNCTION` (12B)
    reloc_block,                 ///< Single `IMAGE_BASE_RELOCATION` block
    reloc_pointer_slot,          ///< 8B slot at a DIR64 reloc target
    load_config_directory,       ///< `IMAGE_LOAD_CONFIG_DIRECTORY` (variable)
    load_config_table,           ///< CFG / SEH / longjmp / EH-cont table
    tls_directory,               ///< `IMAGE_TLS_DIRECTORY64` (40B)
    tls_callback_array,          ///< Null-terminated TLS callback VAs
    export_directory,            ///< `IMAGE_EXPORT_DIRECTORY` (40B)
    export_address_table,        ///< EAT — function/forwarder RVAs
    export_name_table,           ///< Name pointer table
    export_ordinal_table,        ///< Name ordinal table (2B per entry)
    resource_directory_node,     ///< `IMAGE_RESOURCE_DIRECTORY` + entries
    resource_data_entry,         ///< `IMAGE_RESOURCE_DATA_ENTRY` (16B)
    debug_directory_entry,       ///< `IMAGE_DEBUG_DIRECTORY` (28B)
    delay_import_descriptor,     ///< `IMAGE_DELAYLOAD_DESCRIPTOR` (32B)
};

[[nodiscard]] constexpr std::string_view atom_origin_name(
    AtomOrigin o) noexcept
{
    switch (o) {
        case AtomOrigin::pe_header:                return "pe-header";
        case AtomOrigin::instruction:              return "insn";
        case AtomOrigin::instruction_undecoded:     return "insn-und";
        case AtomOrigin::ascii_string:             return "ascii";
        case AtomOrigin::utf16_string:             return "utf16";
        case AtomOrigin::import_descriptor:        return "imp-desc";
        case AtomOrigin::import_thunk:             return "imp-thunk";
        case AtomOrigin::import_by_name:           return "imp-by-name";
        case AtomOrigin::pdata_runtime_function:   return "pdata-rfun";
        case AtomOrigin::reloc_block:              return "reloc-blk";
        case AtomOrigin::reloc_pointer_slot:       return "reloc-ptr";
        case AtomOrigin::load_config_directory:    return "lcfg-dir";
        case AtomOrigin::load_config_table:        return "lcfg-tab";
        case AtomOrigin::tls_directory:            return "tls-dir";
        case AtomOrigin::tls_callback_array:       return "tls-cbarr";
        case AtomOrigin::export_directory:         return "exp-dir";
        case AtomOrigin::export_address_table:     return "exp-eat";
        case AtomOrigin::export_name_table:        return "exp-names";
        case AtomOrigin::export_ordinal_table:     return "exp-ords";
        case AtomOrigin::resource_directory_node:  return "rsrc-node";
        case AtomOrigin::resource_data_entry:      return "rsrc-data";
        case AtomOrigin::debug_directory_entry:    return "dbg-entry";
        case AtomOrigin::delay_import_descriptor:  return "delay-desc";
    }
    return "unknown";
}

/**
 * @brief One indivisible byte range with a diagnostic origin tag.
 */
struct Atom {
    Rva           start_rva;
    std::uint32_t size;
    AtomOrigin    origin;

    /// Half-open end — the first byte *after* this atom.
    [[nodiscard]] constexpr Rva end_rva() const noexcept {
        return static_cast<Rva>(start_rva + size);
    }

    /// Strict-less ordering by `start_rva`.
    [[nodiscard]] constexpr bool operator<(const Atom& o) const noexcept {
        return start_rva < o.start_rva;
    }

    [[nodiscard]] constexpr bool operator==(const Atom&) const noexcept = default;
};

/**
 * @brief Append-only collection of atoms, with a normalisation pass
 *        that sorts and merges overlapping ranges.
 *
 * The chaos pipeline gathers atoms from multiple sources (one per
 * category). Sources may emit overlapping ranges — e.g. an ASCII
 * string scanner spotting bytes that the import scanner already
 * tagged as `IMAGE_IMPORT_BY_NAME`. After all sources have run,
 * `normalize()` sorts by `start_rva` and merges any overlapping or
 * adjacent atoms into one larger atom with the *first* origin tag
 * surviving as the merged atom's origin. Earlier-origin (lower enum
 * value) wins ties — purely for diagnostic clarity, the planner
 * does not depend on it.
 *
 * Move-only: an atom table is owned by exactly one pipeline run.
 */
class AtomTable {
public:
    AtomTable() = default;

    AtomTable(const AtomTable&)            = delete;
    AtomTable& operator=(const AtomTable&) = delete;
    AtomTable(AtomTable&&) noexcept            = default;
    AtomTable& operator=(AtomTable&&) noexcept = default;

    /// Append one atom. No normalisation — caller invokes
    /// `normalize()` after all sources have emitted.
    void add(Atom atom) { atoms_.push_back(atom); }

    /// Reserve capacity to avoid reallocations when the source
    /// knows the lower-bound count.
    void reserve(std::size_t n) { atoms_.reserve(n); }

    /**
     * @brief Sort by `start_rva` and merge overlapping / adjacent
     *        atoms into single ranges.
     *
     * Two atoms `A` and `B` (with `A.start_rva <= B.start_rva`) are
     * considered overlapping when `B.start_rva < A.end_rva()`. They
     * are merged into one atom covering
     * `[A.start_rva, max(A.end_rva, B.end_rva))`. The first atom's
     * origin is preserved.
     *
     * Pre-condition: every atom has `size > 0`. Zero-size atoms are
     * silently dropped.
     */
    void normalize();

    /// Read-only view of the atom list.
    [[nodiscard]] std::span<const Atom> atoms() const noexcept {
        return {atoms_.data(), atoms_.size()};
    }

    [[nodiscard]] std::size_t size() const noexcept { return atoms_.size(); }
    [[nodiscard]] bool        empty() const noexcept { return atoms_.empty(); }

private:
    std::vector<Atom> atoms_;
};

} // namespace mx::pe::chaos
