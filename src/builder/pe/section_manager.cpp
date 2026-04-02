/**
 * @file section_manager.cpp
 * @brief [BUILDER] Реализация SectionManager — управление секциями PE-образа.
 *
 * @details Операции над секциями PeImage: добавление, удаление, изменение размера,
 *          поиск code caves (незанятых участков), заполнение промежутков,
 *          пересчёт выравнивания. Все изменения корректно обновляют метаданные
 *          в NT-заголовках (NumberOfSections, SizeOfImage).
 *
 * @note Code caves ищутся как последовательности байтов 0x00 или 0xCC внутри
 *       данных секций. Минимальный размер cave задаётся параметром.
 *       Удаление секции сдвигает все последующие секции.
 */

#include "mxprotector/pe/section_manager.hpp"

#include <cstring>
#include <algorithm>
#include <ranges>

namespace mx {

// ============================================================================
// SectionManager::add_section
// ============================================================================

MxResult<uint32_t> SectionManager::add_section(
    std::string_view name,
    ByteView data,
    uint32_t characteristics)
{
    pe::SectionInfo section;

    section.name = std::string(name.substr(0, pe::IMAGE_SIZEOF_SHORT_NAME));
    section.data.assign(data.begin(), data.end());
    section.characteristics = characteristics;
    section.virtual_size = static_cast<uint32_t>(data.size());

    return image_.add_section(std::move(section));
}

// ============================================================================
// SectionManager::remove_section
// ============================================================================

MxStatus SectionManager::remove_section(uint32_t index) {
    auto& sections = image_.sections();

    if (index >= sections.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Индекс секции {} за пределами (всего секций: {})",
            index, sections.size()));
    }

    sections.erase(sections.begin() + index);

    std::visit([&sections](auto& nt) {
        nt.FileHeader.NumberOfSections = static_cast<uint16_t>(sections.size());
    }, image_.nt_headers());

    if (index < sections.size()) {
        recalculate_layout(index);
    }

    return {};
}

// ============================================================================
// SectionManager::resize_section
// ============================================================================

MxStatus SectionManager::resize_section(uint32_t index, uint32_t new_size) {
    auto& sections = image_.sections();

    if (index >= sections.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Индекс секции {} за пределами (всего секций: {})",
            index, sections.size()));
    }

    auto& sec = sections[index];

    if (new_size > sec.data.size()) {
        sec.data.resize(new_size, 0);
    }
    else {
        sec.data.resize(new_size);
    }

    sec.virtual_size = new_size;
    sec.raw_size = static_cast<uint32_t>(
        align_up(new_size, image_.file_alignment()));

    if (index + 1 < sections.size()) {
        recalculate_layout(index + 1);
    }

    return {};
}

// ============================================================================
// SectionManager::find_code_caves
// ============================================================================

std::vector<AddressRange> SectionManager::find_code_caves(uint32_t min_size) const {
    std::vector<AddressRange> caves;

    for (const auto& sec : image_.sections()) {
        if (sec.data.empty()) continue;

        uint32_t cave_start = 0;
        bool in_cave = false;

        for (uint32_t i = 0; i < sec.data.size(); ++i) {
            const uint8_t byte = sec.data[i];
            const bool is_filler = (byte == 0x00 || byte == 0xCC);

            if (is_filler && !in_cave) {
                cave_start = i;
                in_cave = true;
            }
            else if (!is_filler && in_cave) {
                const uint32_t cave_size = i - cave_start;
                if (cave_size >= min_size) {
                    AddressRange range;
                    range.start = static_cast<Va>(
                        image_.image_base() + sec.virtual_address + cave_start);
                    range.size = cave_size;
                    caves.push_back(range);
                }
                in_cave = false;
            }
        }

        if (in_cave) {
            const auto cave_size = static_cast<uint32_t>(sec.data.size()) - cave_start;
            if (cave_size >= min_size) {
                AddressRange range;
                range.start = static_cast<Va>(
                    image_.image_base() + sec.virtual_address + cave_start);
                range.size = cave_size;
                caves.push_back(range);
            }
        }
    }

    return caves;
}

// ============================================================================
// SectionManager::fill_section_gaps
// ============================================================================

MxStatus SectionManager::fill_section_gaps(uint8_t fill_byte) {
    auto& raw = image_.raw_data_buffer();
    const auto& sections = image_.sections();

    for (size_t i = 0; i + 1 < sections.size(); ++i) {
        const auto& current = sections[i];
        const auto& next = sections[i + 1];

        const size_t gap_start = static_cast<size_t>(current.raw_offset) + current.raw_size;
        const size_t gap_end = next.raw_offset;

        if (gap_start < gap_end && gap_end <= raw.size()) {
            const size_t fill_end = std::min(gap_end, raw.size());
            const size_t fill_start = std::min(gap_start, raw.size());
            std::memset(raw.data() + fill_start, fill_byte, fill_end - fill_start);
        }
    }

    return {};
}

// ============================================================================
// SectionManager::align_sections
// ============================================================================

MxStatus SectionManager::align_sections(uint32_t file_alignment, uint32_t section_alignment) {
    if (file_alignment == 0 || section_alignment == 0) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_alignment_violation,
            "Выравнивание не может быть нулевым: FileAlignment=0x{:X}, SectionAlignment=0x{:X}",
            file_alignment, section_alignment));
    }

    image_.set_file_alignment(file_alignment);
    image_.set_section_alignment(section_alignment);

    auto& sections = image_.sections();
    if (sections.empty()) return {};

    uint32_t current_va = static_cast<uint32_t>(
        align_up(sections.front().virtual_address, section_alignment));
    uint32_t current_raw = static_cast<uint32_t>(
        align_up(sections.front().raw_offset, file_alignment));

    for (auto& sec : sections) {
        sec.virtual_address = current_va;
        sec.raw_offset = current_raw;
        sec.raw_size = static_cast<uint32_t>(
            align_up(sec.data.size(), file_alignment));

        current_va = static_cast<uint32_t>(
            align_up(current_va + std::max(sec.virtual_size, sec.raw_size), section_alignment));
        current_raw = static_cast<uint32_t>(
            align_up(current_raw + sec.raw_size, file_alignment));
    }

    return {};
}

// ============================================================================
// SectionManager::recalculate_layout
// ============================================================================

void SectionManager::recalculate_layout(uint32_t starting_from) {
    auto& sections = image_.sections();
    const uint32_t fa = image_.file_alignment();
    const uint32_t sa = image_.section_alignment();

    if (starting_from == 0 || sections.empty()) return;

    for (uint32_t i = starting_from; i < sections.size(); ++i) {
        auto& sec = sections[i];
        const auto& prev = sections[i - 1];

        sec.virtual_address = static_cast<uint32_t>(
            align_up(prev.virtual_address + prev.virtual_size, sa));
        sec.raw_offset = static_cast<uint32_t>(
            align_up(prev.raw_offset + prev.raw_size, fa));
        sec.raw_size = static_cast<uint32_t>(
            align_up(sec.data.size(), fa));
    }
}

} // namespace mx
