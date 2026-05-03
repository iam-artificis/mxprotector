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

/**
 * @brief Default alignment requirement keyed by `AtomOrigin`.
 *
 * Used by atom sources as a single source of truth: every atom's
 * alignment derives from its origin tag, so adding a new origin
 * means defining the right alignment in exactly one place. The
 * planner pins every atom whose alignment is > 1.
 *
 * Categories:
 *   * `1` — instructions, strings, import_by_name records, header
 *     bytes (handled separately by the planner). Movable.
 *   * `2` — UTF-16 codeunits, export ordinal table.
 *   * `4` — PE-format records walked linearly (descriptors, reloc
 *     blocks, RUNTIME_FUNCTION entries, debug directory, resource
 *     nodes, …).
 *   * `8` — slots the loader reads as 64-bit values: IAT thunks,
 *     LOAD_CONFIG body, TLS directory + callback array, DIR64 reloc
 *     target slots.
 */
[[nodiscard]] constexpr std::uint16_t default_alignment_for(
    AtomOrigin o) noexcept
{
    switch (o) {
        case AtomOrigin::pe_header:                 return 1;
        case AtomOrigin::instruction:               return 1;
        case AtomOrigin::instruction_undecoded:     return 1;
        case AtomOrigin::ascii_string:              return 1;
        case AtomOrigin::utf16_string:              return 2;
        case AtomOrigin::import_by_name:            return 1;

        case AtomOrigin::export_ordinal_table:      return 2;

        case AtomOrigin::import_descriptor:         return 4;
        case AtomOrigin::pdata_runtime_function:    return 4;
        case AtomOrigin::reloc_block:               return 4;
        case AtomOrigin::load_config_table:         return 4;
        case AtomOrigin::export_directory:          return 4;
        case AtomOrigin::export_address_table:      return 4;
        case AtomOrigin::export_name_table:         return 4;
        case AtomOrigin::resource_directory_node:   return 4;
        case AtomOrigin::resource_data_entry:       return 4;
        case AtomOrigin::debug_directory_entry:     return 4;
        case AtomOrigin::delay_import_descriptor:   return 4;

        case AtomOrigin::import_thunk:              return 8;
        case AtomOrigin::reloc_pointer_slot:        return 8;
        case AtomOrigin::load_config_directory:     return 8;
        case AtomOrigin::tls_directory:             return 8;
        case AtomOrigin::tls_callback_array:        return 8;
    }
    return 1;
}

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
 *
 * The `alignment` field controls planner behaviour:
 *
 *   * `alignment == 1` — the default for instructions, strings, and
 *     loose data: the atom may be placed at any RVA after shuffle.
 *
 *   * `alignment > 1` — the atom is **PINNED** at its original RVA.
 *     Used for PE structures that the Windows loader reads with
 *     alignment requirements (LOAD_CONFIG, TLS dir, IAT thunks,
 *     CFG/XFG function-pointer tables, .pdata RUNTIME_FUNCTION
 *     entries, etc). The planner does not attempt to find a new
 *     aligned RVA — it simply leaves these atoms in place and
 *     shuffles the bytes between them.
 *
 * The pin-on-alignment policy is a deliberate simplification: it
 * keeps the planner free of new-RVA alignment-search logic, yet
 * still permits up to ~85% of typical image bytes (instructions +
 * strings + plain data) to be permuted.
 *
 * ### Forward-compatibility fields
 *
 * Two optional fields support upcoming features without rippling
 * through every existing atom source — both default to zero, and
 * sources written before they were introduced continue to work
 * unchanged:
 *
 *   * `fall_through_to` — non-zero when the atom's last byte is the
 *     last byte of a basic block whose original successor lives at
 *     `fall_through_to`. After chaos shuffles the atom to a new RVA,
 *     a post-shuffle pass (`FallThroughJmpInserter`) writes a 5-byte
 *     `JMP rel32` into the atom's slack so control flow continues to
 *     reach the (now-moved) successor. Used by the future
 *     basic-block atom source. Set to 0 for atoms that already
 *     terminate with their own control transfer (`JMP`/`RET`/`UD2`)
 *     or for non-code atoms.
 *
 *   * `slack_after` — bytes the atom owns *beyond* its `size`-byte
 *     content payload. The planner treats `size + slack_after` as
 *     the atom's footprint when laying it out so subsequent atoms
 *     do not overlap the slack region. Slack is the cleanest hook
 *     for emerging mutation passes (MBA byte-insertion, fall-through
 *     fixups, instrumentation thunks) — they can write into the
 *     reserved bytes without renegotiating ranges with the planner.
 */
struct Atom {
    Rva           start_rva;
    std::uint32_t size;
    AtomOrigin    origin;
    std::uint16_t alignment{1};

    /// Reserved bytes appended after `size` content bytes. The
    /// planner reserves them at layout time; a post-shuffle pass
    /// fills them with the desired bytes (NOPs by default; `JMP
    /// rel32` when `fall_through_to != 0`). Default 0 — atoms with
    /// no upcoming-mutation needs simply ignore the field.
    std::uint32_t slack_after{0};

    /// Successor RVA when the atom ends with implicit fall-through.
    /// Default 0 — every existing atom source still produces atoms
    /// without explicit control-flow links (function granularity is
    /// "self-contained": the function ends with `RET`/`JMP`/`UD2`
    /// from MSVC's perspective, so no fall-through across atom
    /// boundaries is possible).
    Rva           fall_through_to{0};

    /// Half-open end of the *content* — the first byte after the
    /// atom's payload (NOT including slack). Existing planners and
    /// scanners reason about content ranges, so this is the
    /// default semantics retained by the function.
    [[nodiscard]] constexpr Rva end_rva() const noexcept {
        return static_cast<Rva>(start_rva + size);
    }

    /// Half-open end of the *footprint* — content + slack. The
    /// planner uses this when packing atoms back-to-back so slack
    /// regions stay reserved for the mutation pass that owns them.
    [[nodiscard]] constexpr Rva footprint_end_rva() const noexcept {
        return static_cast<Rva>(start_rva + size + slack_after);
    }

    /// `true` when the planner must keep this atom at its original RVA.
    [[nodiscard]] constexpr bool is_pinned() const noexcept {
        return alignment > 1;
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
 * The merged atom's `alignment` is `max` of the inputs', so a
 * pinned atom merged with a movable one stays pinned.
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
