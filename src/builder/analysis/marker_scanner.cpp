/**
 * @file marker_scanner.cpp
 * @brief [BUILDER] Реализация сканера SDK-маркеров в PE-образе.
 *
 * @details Сканирует code-секции PE на наличие 9-байтных сигнатур
 *          (8 байт magic + 1 байт MarkerType). Найденные маркеры
 *          валидируются на парность (begin↔end) и преобразуются
 *          в MarkedRegion с указанием RVA начала и конца защищаемого кода.
 *
 * @note RVA маркированного региона (start_rva) указывает на первый байт
 *       ПОСЛЕ begin-маркера. end_rva указывает на первый байт end-маркера.
 *       Таким образом регион [start_rva, end_rva) содержит только защищаемый код.
 */

#include "mxprotector/analysis/marker_scanner.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace mx::analysis {

// ============================================================================
// find_markers — основной публичный метод
// ============================================================================

MxResult<std::vector<MarkedRegion>> MarkerScanner::find_markers(const PeImage& image) {
    std::vector<RawMarker> all_raw_markers;

    const auto& sections = image.sections();
    for (uint32_t i = 0; i < sections.size(); ++i) {
        const auto& sec = sections[i];

        if (!sec.is_code()) continue;

        const ByteView sec_data{sec.data.data(), sec.data.size()};
        auto markers = scan_section(sec_data, sec.virtual_address, i);

        all_raw_markers.insert(all_raw_markers.end(),
            std::make_move_iterator(markers.begin()),
            std::make_move_iterator(markers.end()));
    }

    if (all_raw_markers.empty()) {
        return std::vector<MarkedRegion>{};
    }

    std::ranges::sort(all_raw_markers, [](const RawMarker& a, const RawMarker& b) {
        return a.rva < b.rva;
    });

    return validate_and_pair(all_raw_markers);
}

// ============================================================================
// scan_section — поиск магических сигнатур в одной секции
// ============================================================================

std::vector<MarkerScanner::RawMarker> MarkerScanner::scan_section(
    ByteView section_data, Rva section_rva, uint32_t section_index)
{
    std::vector<RawMarker> result;

    if (section_data.size() < marker_size) {
        return result;
    }

    const size_t scan_limit = section_data.size() - marker_size + 1;

    for (size_t offset = 0; offset < scan_limit; ++offset) {
        uint64_t candidate_magic = 0;
        std::memcpy(&candidate_magic, section_data.data() + offset, sizeof(uint64_t));

        if (candidate_magic != marker_magic) continue;

        const uint8_t type_byte = section_data[offset + sizeof(uint64_t)];

        if (type_byte > static_cast<uint8_t>(MarkerType::obfuscate_end)) continue;

        const auto marker_type = static_cast<MarkerType>(type_byte);
        const Rva marker_rva = section_rva + static_cast<Rva>(offset);

        result.push_back(RawMarker{
            .type = marker_type,
            .rva = marker_rva,
            .section_index = section_index
        });

        offset += marker_size - 1;
    }

    return result;
}

// ============================================================================
// validate_and_pair — проверка парности и формирование MarkedRegion
// ============================================================================

MxResult<std::vector<MarkedRegion>> MarkerScanner::validate_and_pair(
    std::vector<RawMarker>& raw_markers)
{
    std::vector<MarkedRegion> regions;

    struct PendingBegin {
        RawMarker marker;
    };

    std::vector<PendingBegin> pending_begins;

    for (const auto& raw : raw_markers) {
        if (is_begin_marker(raw.type)) {
            pending_begins.push_back(PendingBegin{raw});
        } else {
            bool found_match = false;

            for (auto it = pending_begins.rbegin(); it != pending_begins.rend(); ++it) {
                if (matching_end_type(it->marker.type) == raw.type) {
                    const Rva region_start = it->marker.rva + static_cast<Rva>(marker_size);
                    const Rva region_end   = raw.rva;

                    if (region_end <= region_start) {
                        return std::unexpected(MxError(
                            ErrorCategory::marker,
                            static_cast<uint16_t>(ProtectionErrorCode::region_too_small),
                            std::format(
                                "Маркированный регион {} по RVA 0x{:08X} имеет нулевой или отрицательный размер "
                                "(start_rva=0x{:08X}, end_rva=0x{:08X})",
                                marker_type_name(it->marker.type),
                                it->marker.rva,
                                region_start, region_end)));
                    }

                    regions.push_back(MarkedRegion{
                        .type = it->marker.type,
                        .start_rva = region_start,
                        .end_rva = region_end,
                        .section_index = it->marker.section_index
                    });

                    pending_begins.erase(std::next(it).base());
                    found_match = true;
                    break;
                }
            }

            if (!found_match) {
                return std::unexpected(MxError(
                    ErrorCategory::marker,
                    static_cast<uint16_t>(ProtectionErrorCode::marker_mismatch),
                    std::format(
                        "Найден end-маркер {} по RVA 0x{:08X} без соответствующего begin-маркера",
                        marker_type_name(raw.type), raw.rva)));
            }
        }
    }

    if (!pending_begins.empty()) {
        const auto& orphan = pending_begins.front().marker;
        return std::unexpected(MxError(
            ErrorCategory::marker,
            static_cast<uint16_t>(ProtectionErrorCode::marker_mismatch),
            std::format(
                "Найден begin-маркер {} по RVA 0x{:08X} без соответствующего end-маркера",
                marker_type_name(orphan.type), orphan.rva)));
    }

    std::ranges::sort(regions, [](const MarkedRegion& a, const MarkedRegion& b) {
        return a.start_rva < b.start_rva;
    });

    return regions;
}

} // namespace mx::analysis
