/**
 * @file data_region.hpp
 * @brief Mark byte ranges inside a *code* section that are actually
 *        data (jump tables, bytecode, immediate pools).
 *
 * **Why this type exists.**
 *
 * The protector emits sections whose `IMAGE_SCN_CNT_CODE` bit is
 * set yet whose payload mixes real x86 instructions with structured
 * data — the VM blob is the canonical example: handler instructions
 * are interleaved with the obfuscated jump table and the encrypted
 * bytecode stream. Tools downstream of emit-time, in particular
 * `CodeReferenceScanner`, treat a code section as a single
 * instruction stream and walk it byte-by-byte through Zydis. Bytes
 * that *aren't* real instructions still decode to *something* — and
 * any rel32 / RIP-relative slot Zydis surfaces from those bytes is
 * a bogus reference whose `location_rva` lands inside the structured
 * data. If the chaos refmap patcher subsequently rewrites that slot
 * (because the bogus reference's "target" happened to fall in code
 * that moved), the data bytes get overwritten and the VM crashes the
 * moment its dispatcher reads the now-corrupt entry.
 *
 * Letting passes attach a `DataRegion` to the section they emit
 * makes the data-vs-code split explicit: every range registered here
 * is "patcher-keep-out". The chaos pipeline reads the union of all
 * sections' regions and adds them as additional hard byte ranges
 * for `ReferenceOverlapFilter` — bogus refs landing in data are
 * dropped before the patcher runs.
 *
 * **Why a separate header.**
 *
 *   * Lives next to `SectionInfo` so adding a new region kind is
 *     one place — no ripple through the refmap layer.
 *   * Refmap depends on PE types; PE types do not depend on refmap,
 *     so the type belongs in `pe/`.
 *   * The type is a plain value with no implementation, no out-of-
 *     line code; an inline header keeps it close to its data.
 */

#pragma once

#include <cstdint>
#include <string_view>

#include "mxprotector/core/types.hpp"

namespace mx::pe {

/**
 * @brief Diagnostic origin tag for a `DataRegion`. Carried through
 *        logs but never branched on by the chaos pipeline — the
 *        contract is uniform "do not write rel refs into these
 *        bytes" regardless of the kind.
 */
enum class DataRegionKind : std::uint8_t {
    /// Encrypted opcode stream consumed by the VM dispatcher
    /// (`r11` walks through it). Bytes are not x86 instructions.
    vm_bytecode,
    /// Obfuscated handler-table entries — 4 bytes per slot, each
    /// stores `(handler_offset_from_table_base) XOR build_key`.
    /// Bytes are not x86 instructions.
    vm_handler_table,
    /// String-protection sub-VM bytecode. Same shape as
    /// `vm_bytecode` but emitted by the string pass.
    string_vm_bytecode,
    /// String-protection sub-VM handler table.
    string_vm_handler_table,
    /// Packed `StringDescriptor` records inside the `.mxstr`
    /// section — one 8-byte struct per protected string.
    string_descriptor_table,
    /// Encrypted-string data pool — variable-length ciphertext
    /// runs followed by a per-string key byte that decrypts to
    /// the NUL terminator.
    string_data_pool,
    /// S3 ephemeral scratch ring — counter + N fixed-size slots
    /// the runtime decryptor copies plaintext into.
    string_scratch_ring,
};

/**
 * @brief Returns a short stable name for a `DataRegionKind`. Used
 *        only for logging; callers must not parse the result.
 */
[[nodiscard]] constexpr std::string_view data_region_kind_name(
    DataRegionKind k) noexcept
{
    switch (k) {
        case DataRegionKind::vm_bytecode:               return "vm-bytecode";
        case DataRegionKind::vm_handler_table:          return "vm-handler-table";
        case DataRegionKind::string_vm_bytecode:        return "str-bytecode";
        case DataRegionKind::string_vm_handler_table:   return "str-handler-table";
        case DataRegionKind::string_descriptor_table:   return "str-desc-tbl";
        case DataRegionKind::string_data_pool:          return "str-data-pool";
        case DataRegionKind::string_scratch_ring:       return "str-scratch";
    }
    return "data";
}

/**
 * @brief One half-open byte range inside a code section that the
 *        chaos pipeline must not interpret as instructions.
 *
 *   * `begin_rva` — RVA of the first byte of the region.
 *   * `size`      — number of bytes in the region (must be > 0).
 *   * `kind`      — diagnostic tag.
 *
 * Ranges may not overlap each other within the same section. The
 * chaos pipeline assumes ownership semantics: the section that
 * registers a region is the only writer of those bytes during
 * post-emit phases.
 */
struct DataRegion {
    Rva            begin_rva = 0;
    std::uint32_t  size      = 0;
    DataRegionKind kind      = DataRegionKind::vm_bytecode;

    /// Half-open end of the region.
    [[nodiscard]] constexpr Rva end_rva() const noexcept {
        return static_cast<Rva>(begin_rva + size);
    }
};

} // namespace mx::pe
