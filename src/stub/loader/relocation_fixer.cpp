/**
 * @file relocation_fixer.cpp
 * @brief [STUB] Пересчёт базовых релокаций PE-образа.
 *
 * @details Если образ загружен не по предпочтительному ImageBase,
 *          необходимо применить релокации (base relocation fixups):
 *          delta = actual_base - original_base.
 *          Для каждой записи релокации: *(target_va) += delta.
 *
 *          Поддерживаемые типы:
 *          - IMAGE_REL_BASED_DIR64 (type 10): 64-битная абсолютная адресация
 *          - IMAGE_REL_BASED_HIGHLOW (type 3): 32-битная абсолютная адресация
 *          - IMAGE_REL_BASED_ABSOLUTE (type 0): заполнитель (пропуск)
 *
 * @note PIC, без CRT/STL. Работает с сырыми указателями.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"

namespace mx::stub::pic {

#pragma pack(push, 1)

/// @brief Заголовок блока базовых релокаций.
struct BaseRelocationBlock {
    uint32_t PageRVA;      ///< RVA страницы
    uint32_t BlockSize;    ///< Размер блока (включая заголовок)
};

#pragma pack(pop)

/**
 * @brief Применяет базовые релокации к PE-образу в памяти.
 *
 * @param image_base   Фактический VA базы загрузки.
 * @param config       Конфигурация STUB (содержит оригинальный ImageBase и RVA релокаций).
 * @return Количество применённых релокаций.
 *
 * @details Алгоритм:
 *          1. delta = image_base - config->reloc_info.original_image_base
 *          2. Если delta == 0 — релокации не нужны
 *          3. Итерация по блокам релокаций:
 *             - Каждый блок начинается с BaseRelocationBlock (8 байт)
 *             - За ним следует массив uint16_t entries
 *             - Старшие 4 бита entry = тип, младшие 12 = смещение от PageRVA
 *          4. Для DIR64: прибавляем delta к 64-битному значению по адресу
 *          5. Для HIGHLOW: прибавляем delta к 32-битному значению
 */
uint32_t fix_relocations(
    uint64_t                   image_base,
    const StubRuntimeConfig*   config) noexcept
{
    if (!config) return 0;

    const int64_t delta = static_cast<int64_t>(image_base)
                        - static_cast<int64_t>(config->reloc_info.original_image_base);

    if (delta == 0) return 0;

    const uint32_t reloc_rva = config->reloc_info.reloc_dir_rva;
    const uint32_t reloc_size = config->reloc_info.reloc_dir_size;

    if (reloc_rva == 0 || reloc_size == 0) return 0;

    const auto* base = va_to_ptr<uint8_t>(image_base);
    const auto* reloc_data = base + reloc_rva;
    const auto* reloc_end = reloc_data + reloc_size;

    uint32_t fixup_count = 0;
    const auto* current = reloc_data;

    while (current + sizeof(BaseRelocationBlock) <= reloc_end) {
        const auto* block = reinterpret_cast<const BaseRelocationBlock*>(current);

        if (block->BlockSize == 0) break;
        if (block->BlockSize < sizeof(BaseRelocationBlock)) break;

        const uint32_t entry_count =
            (block->BlockSize - sizeof(BaseRelocationBlock)) / sizeof(uint16_t);
        const auto* entries = reinterpret_cast<const uint16_t*>(
            current + sizeof(BaseRelocationBlock));

        for (uint32_t i = 0; i < entry_count; ++i) {
            const uint16_t entry = entries[i];
            const uint16_t type = entry >> 12;
            const uint16_t offset = entry & 0x0FFF;

            auto* target = const_cast<uint8_t*>(base + block->PageRVA + offset);

            switch (type) {
                case 10: {
                    auto* addr64 = reinterpret_cast<uint64_t*>(target);
                    *addr64 += static_cast<uint64_t>(delta);
                    ++fixup_count;
                    break;
                }
                case 3: {
                    auto* addr32 = reinterpret_cast<uint32_t*>(target);
                    *addr32 += static_cast<uint32_t>(delta);
                    ++fixup_count;
                    break;
                }
                case 0:
                    break;
                default:
                    break;
            }
        }

        current += block->BlockSize;
    }

    return fixup_count;
}

} // namespace mx::stub::pic
