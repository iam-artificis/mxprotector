/**
 * @file section_info.hpp
 * @brief Builder-side high-level view of a PE section.
 *
 * @details `SectionInfo` is the parsed/owned representation of one
 *          PE section that protection passes operate on. It carries
 *          the raw header fields (RVA, size, characteristics, name)
 *          plus the chaos-pipeline metadata (data regions, movable
 *          blocks, pre-scanned reference slots) that emitting passes
 *          attach so downstream stages know what to do with each
 *          byte run.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/data_region.hpp"
#include "mxprotector/pe/pre_scanned_ref_slot.hpp"
#include "mxprotector/pe/types/constants.hpp"

namespace mx::pe {

/**
 * @brief Высокоуровневое описание секции PE.
 */
struct SectionInfo {
    std::string  name;                ///< Имя секции (декодированное из 8 байт)
    uint32_t     virtual_size = 0;    ///< Виртуальный размер
    uint32_t     virtual_address = 0; ///< RVA секции
    uint32_t     raw_size = 0;        ///< Размер на диске
    uint32_t     raw_offset = 0;      ///< Файловое смещение
    uint32_t     characteristics = 0; ///< Флаги (RWX и т.д.)
    ByteBuffer   data;                ///< Содержимое секции

    /// Byte ranges inside `data` that are *not* x86 instructions —
    /// jump tables, encrypted bytecode, immediate pools. The chaos
    /// pipeline reads this list to keep the reference patcher out of
    /// these bytes (see `pe/data_region.hpp` for the full rationale).
    /// Default empty: the section is pure code or pure data.
    std::vector<DataRegion> data_regions;

    /// Byte runs inside `data` that the emitting pass declares safe
    /// for chaos-shuffle to relocate as movable atoms (indirect-call
    /// stubs, CFF blocks). Default empty — sections without a
    /// natural sub-block carving stay pinned the way they always
    /// did. See `pe/data_region.hpp` for the contract a block must
    /// satisfy to be movable.
    std::vector<MovableBlock> movable_blocks;

    /// Reference-slot overrides emitted by passes that already know
    /// the right `(slot, target, K)` triple for a `rel32` slot whose
    /// effective displacement is `(target - slot - 4) - K`. The chaos
    /// pipeline appends these to its scanned reference table and
    /// drops any `rel` reference `CodeReferenceScanner` produced for
    /// the same slot (the scanner cannot know `K` from the on-disk
    /// disp32 alone). Used by non-balanced indirect-call stubs whose
    /// LEA carries a non-zero algebraic offset. Default empty.
    /// See `pe/pre_scanned_ref_slot.hpp` for the value type.
    std::vector<PreScannedRefSlot> pre_scanned_refs;

    /// Per-section 4-byte RVA-slot overrides for sections the
    /// existing structured scanners do not walk — currently the
    /// chained `UNWIND_INFO` blobs in `.mxchain` produced by
    /// `PdataChainEmitter` (B.4.23.1). The chaos pipeline turns
    /// each entry into a `Reference` with `ReferenceEncoding::rva`
    /// or `rva_end_exclusive` (per the `end_exclusive` flag) so
    /// the patcher remaps the stored value through the chunk
    /// planner. Default empty — sections without structured RVA
    /// content the scanners miss leave the field alone. See
    /// `pe/pre_scanned_ref_slot.hpp` for the value type.
    std::vector<ExtraRvaRefSlot> extra_rva_refs;

    /// @brief Проверяет, содержит ли секция код.
    [[nodiscard]] bool is_code() const noexcept {
        return (characteristics & IMAGE_SCN_CNT_CODE) != 0;
    }

    /// @brief Проверяет, исполняемая ли секция.
    [[nodiscard]] bool is_executable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    /// @brief Проверяет, записываемая ли секция.
    [[nodiscard]] bool is_writable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    /// @brief Проверяет, содержит ли секция указанный RVA.
    [[nodiscard]] bool contains_rva(uint32_t rva) const noexcept {
        return rva >= virtual_address &&
               rva < virtual_address + virtual_size;
    }
};

} // namespace mx::pe
