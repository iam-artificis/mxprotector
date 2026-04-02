/**
 * @file relocation_table.cpp
 * @brief [BUILDER] Реализация RelocationTableManager — парсинг, добавление и
 *        реконструкция таблицы базовых релокаций PE.
 *
 * @details Разбирает последовательность блоков IMAGE_BASE_RELOCATION в вектор
 *          RelocationBlock. Каждый блок содержит RVA страницы и массив записей
 *          (тип[4 бита] + смещение[12 бит]). Записи IMAGE_REL_BASED_ABSOLUTE
 *          игнорируются (используются как padding).
 *
 *          Реконструкция собирает блоки обратно с выравниванием до 4 байт
 *          (padding записями IMAGE_REL_BASED_ABSOLUTE).
 *
 * @note Размер каждого блока включает заголовок (8 байт).
 *       Максимальный размер таблицы ограничен 64 МБ для защиты от коррупции.
 */

#include "mxprotector/pe/relocation_table.hpp"

#include <cstring>
#include <algorithm>
#include <ranges>

namespace mx {

// ============================================================================
// RelocationTableManager::parse_relocations
// ============================================================================

MxResult<std::vector<pe::RelocationBlock>> RelocationTableManager::parse_relocations(
    ByteView data,
    Rva reloc_dir_rva,
    uint32_t reloc_dir_size,
    std::function<MxResult<FileOffset>(Rva)> rva_to_offset)
{
    if (reloc_dir_rva == 0 || reloc_dir_size == 0) {
        return std::vector<pe::RelocationBlock>{};
    }

    constexpr uint32_t max_reloc_size = 64 * 1024 * 1024;
    if (reloc_dir_size > max_reloc_size) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_relocation_table,
            "Размер таблицы релокаций (0x{:X}) превышает максимум (0x{:X})",
            reloc_dir_size, max_reloc_size));
    }

    auto base_off_result = rva_to_offset(reloc_dir_rva);
    if (!base_off_result) return std::unexpected(base_off_result.error());
    const auto base_offset = static_cast<size_t>(*base_off_result);

    if (base_offset + reloc_dir_size > data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_relocation_table,
            "Таблица релокаций (смещение 0x{:X}, размер 0x{:X}) выходит за пределы файла (0x{:X})",
            base_offset, reloc_dir_size, data.size()));
    }

    std::vector<pe::RelocationBlock> blocks;
    size_t offset = base_offset;
    const size_t end_offset = base_offset + reloc_dir_size;

    constexpr size_t block_header_size = sizeof(pe::IMAGE_BASE_RELOCATION);

    while (offset + block_header_size <= end_offset) {
        pe::IMAGE_BASE_RELOCATION block_hdr{};
        std::memcpy(&block_hdr, data.data() + offset, block_header_size);

        if (block_hdr.SizeOfBlock == 0) break;

        if (block_hdr.SizeOfBlock < block_header_size) {
            return std::unexpected(error::pe_fmt(
                PeErrorCode::invalid_relocation_table,
                "Блок релокаций по смещению 0x{:X}: SizeOfBlock ({}) < заголовок ({})",
                offset, block_hdr.SizeOfBlock, block_header_size));
        }

        if (offset + block_hdr.SizeOfBlock > end_offset) {
            return std::unexpected(error::pe_fmt(
                PeErrorCode::invalid_relocation_table,
                "Блок релокаций (смещение 0x{:X}, размер 0x{:X}) выходит за пределы таблицы",
                offset, block_hdr.SizeOfBlock));
        }

        pe::RelocationBlock block;
        block.page_rva = block_hdr.VirtualAddress;

        const uint32_t entries_size = block_hdr.SizeOfBlock - static_cast<uint32_t>(block_header_size);
        const uint32_t num_entries = entries_size / sizeof(uint16_t);

        block.entries.reserve(num_entries);

        for (uint32_t i = 0; i < num_entries; ++i) {
            const size_t entry_offset = offset + block_header_size + i * sizeof(uint16_t);
            if (entry_offset + sizeof(uint16_t) > data.size()) break;

            uint16_t entry = 0;
            std::memcpy(&entry, data.data() + entry_offset, sizeof(uint16_t));

            const uint16_t type = (entry >> 12) & 0x0F;
            const uint16_t page_offset = entry & 0x0FFF;

            if (type == pe::IMAGE_REL_BASED_ABSOLUTE) continue;

            pe::RelocationEntry reloc;
            reloc.rva = block_hdr.VirtualAddress + page_offset;
            reloc.type = type;
            block.entries.push_back(reloc);
        }

        if (!block.entries.empty()) {
            blocks.push_back(std::move(block));
        }

        offset += block_hdr.SizeOfBlock;
    }

    return blocks;
}

// ============================================================================
// RelocationTableManager::add_relocation
// ============================================================================

MxStatus RelocationTableManager::add_relocation(Rva target_rva, uint16_t type) {
    const uint32_t page_rva = target_rva & ~0xFFFu;
    auto& relocs = image_.relocations();

    auto block_it = std::ranges::find_if(relocs, [page_rva](const pe::RelocationBlock& b) {
        return b.page_rva == page_rva;
    });

    pe::RelocationEntry entry;
    entry.rva = target_rva;
    entry.type = type;

    if (block_it != relocs.end()) {
        auto dup = std::ranges::find_if(block_it->entries, [target_rva, type](const pe::RelocationEntry& e) {
            return e.rva == target_rva && e.type == type;
        });
        if (dup != block_it->entries.end()) {
            return {};
        }
        block_it->entries.push_back(entry);
    }
    else {
        pe::RelocationBlock block;
        block.page_rva = page_rva;
        block.entries.push_back(entry);

        auto insert_pos = std::ranges::lower_bound(relocs, page_rva, {},
            &pe::RelocationBlock::page_rva);
        relocs.insert(insert_pos, std::move(block));
    }

    return {};
}

// ============================================================================
// RelocationTableManager::rebuild_relocation_table
// ============================================================================

MxResult<ByteBuffer> RelocationTableManager::rebuild_relocation_table(
    const std::vector<pe::RelocationBlock>& blocks)
{
    if (blocks.empty()) {
        return ByteBuffer{};
    }

    size_t total_size = 0;
    for (const auto& block : blocks) {
        const size_t num_entries = block.entries.size();
        const bool needs_padding = (num_entries % 2 != 0);
        const size_t entries_count = num_entries + (needs_padding ? 1 : 0);
        total_size += sizeof(pe::IMAGE_BASE_RELOCATION) + entries_count * sizeof(uint16_t);
    }

    ByteBuffer buffer(total_size, 0);
    size_t offset = 0;

    for (const auto& block : blocks) {
        const size_t num_entries = block.entries.size();
        const bool needs_padding = (num_entries % 2 != 0);
        const size_t entries_count = num_entries + (needs_padding ? 1 : 0);

        pe::IMAGE_BASE_RELOCATION hdr{};
        hdr.VirtualAddress = block.page_rva;
        hdr.SizeOfBlock = static_cast<uint32_t>(
            sizeof(pe::IMAGE_BASE_RELOCATION) + entries_count * sizeof(uint16_t));

        std::memcpy(buffer.data() + offset, &hdr, sizeof(pe::IMAGE_BASE_RELOCATION));
        offset += sizeof(pe::IMAGE_BASE_RELOCATION);

        for (const auto& entry : block.entries) {
            const uint16_t page_offset = static_cast<uint16_t>(entry.rva - block.page_rva);
            const uint16_t encoded = static_cast<uint16_t>((entry.type << 12) | (page_offset & 0x0FFF));
            std::memcpy(buffer.data() + offset, &encoded, sizeof(uint16_t));
            offset += sizeof(uint16_t);
        }

        if (needs_padding) {
            uint16_t padding = 0;
            std::memcpy(buffer.data() + offset, &padding, sizeof(uint16_t));
            offset += sizeof(uint16_t);
        }
    }

    return buffer;
}

} // namespace mx
