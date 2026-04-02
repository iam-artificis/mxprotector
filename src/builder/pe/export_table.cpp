/**
 * @file export_table.cpp
 * @brief [BUILDER] Реализация ExportTableManager — парсинг и реконструкция таблицы экспортов PE.
 *
 * @details Разбирает IMAGE_EXPORT_DIRECTORY и связанные массивы (EAT, имена, ординалы)
 *          в высокоуровневую структуру ExportTable. Поддерживает forwarded exports
 *          (определяются по попаданию RVA функции в диапазон директории экспортов).
 *          Реконструкция собирает все компоненты обратно в бинарный буфер.
 *
 * @note Именованные экспорты отсортированы по имени (бинарный поиск загрузчика).
 *       Ординалы нормализуются вычитанием Base из Export Directory.
 */

#include "mxprotector/pe/export_table.hpp"
#include "mxprotector/pe/pe_types.hpp"

#include <cstring>
#include <algorithm>
#include <ranges>

namespace mx {

namespace {

/**
 * @brief Безопасно читает структуру T из буфера.
 * @tparam T Тип структуры.
 * @param data Буфер.
 * @param offset Смещение.
 * @return Структура или ошибка.
 */
template <typename T>
[[nodiscard]] MxResult<T> safe_read(ByteView data, size_t offset) {
    if (offset + sizeof(T) > data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_export_table,
            "Чтение структуры {} байт по смещению 0x{:X} за пределами (0x{:X})",
            sizeof(T), offset, data.size()));
    }
    T result{};
    std::memcpy(&result, data.data() + offset, sizeof(T));
    return result;
}

} // anonymous namespace

// ============================================================================
// ExportTableManager::parse_exports
// ============================================================================

MxResult<pe::ExportTable> ExportTableManager::parse_exports(
    ByteView data,
    Rva export_dir_rva,
    uint32_t export_dir_size,
    std::function<MxResult<FileOffset>(Rva)> rva_to_offset)
{
    if (export_dir_rva == 0 || export_dir_size == 0) {
        return pe::ExportTable{};
    }

    auto dir_offset_result = rva_to_offset(export_dir_rva);
    if (!dir_offset_result) return std::unexpected(dir_offset_result.error());
    const auto dir_offset = static_cast<size_t>(*dir_offset_result);

    auto exp_dir = safe_read<pe::IMAGE_EXPORT_DIRECTORY>(data, dir_offset);
    if (!exp_dir) return std::unexpected(exp_dir.error());
    const auto& edir = *exp_dir;

    pe::ExportTable table;
    table.base = edir.Base;

    if (edir.Name != 0) {
        auto name_off = rva_to_offset(edir.Name);
        if (name_off) {
            auto name_result = read_ascii_string(data, *name_off);
            if (name_result) {
                table.dll_name = std::move(*name_result);
            }
        }
    }

    auto eat_off_result = rva_to_offset(edir.AddressOfFunctions);
    if (!eat_off_result) return std::unexpected(eat_off_result.error());
    const auto eat_offset = static_cast<size_t>(*eat_off_result);

    if (eat_offset + static_cast<size_t>(edir.NumberOfFunctions) * sizeof(uint32_t) > data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_export_table,
            "EAT ({} записей) по смещению 0x{:X} выходит за пределы файла",
            edir.NumberOfFunctions, eat_offset));
    }

    std::vector<uint32_t> name_ordinals;
    std::vector<std::string> names;

    if (edir.NumberOfNames > 0 && edir.AddressOfNames != 0 && edir.AddressOfNameOrdinals != 0) {
        auto names_rva_off = rva_to_offset(edir.AddressOfNames);
        auto ordinals_off = rva_to_offset(edir.AddressOfNameOrdinals);

        if (names_rva_off && ordinals_off) {
            const auto names_array_off = static_cast<size_t>(*names_rva_off);
            const auto ords_array_off = static_cast<size_t>(*ordinals_off);

            if (names_array_off + edir.NumberOfNames * sizeof(uint32_t) <= data.size() &&
                ords_array_off + edir.NumberOfNames * sizeof(uint16_t) <= data.size())
            {
                names.resize(edir.NumberOfNames);
                name_ordinals.resize(edir.NumberOfNames);

                for (uint32_t i = 0; i < edir.NumberOfNames; ++i) {
                    uint32_t name_rva = 0;
                    std::memcpy(&name_rva, data.data() + names_array_off + i * sizeof(uint32_t),
                                sizeof(uint32_t));

                    uint16_t ordinal_idx = 0;
                    std::memcpy(&ordinal_idx, data.data() + ords_array_off + i * sizeof(uint16_t),
                                sizeof(uint16_t));

                    name_ordinals[i] = ordinal_idx;

                    if (name_rva != 0) {
                        auto noff = rva_to_offset(name_rva);
                        if (noff) {
                            auto nr = read_ascii_string(data, *noff);
                            if (nr) names[i] = std::move(*nr);
                        }
                    }
                }
            }
        }
    }

    const Rva export_end = export_dir_rva + export_dir_size;
    table.functions.reserve(edir.NumberOfFunctions);

    for (uint32_t i = 0; i < edir.NumberOfFunctions; ++i) {
        uint32_t func_rva = 0;
        std::memcpy(&func_rva, data.data() + eat_offset + i * sizeof(uint32_t),
                     sizeof(uint32_t));

        if (func_rva == 0) continue;

        pe::ExportFunction efunc;
        efunc.ordinal = static_cast<uint16_t>(edir.Base + i);
        efunc.rva = func_rva;

        if (func_rva >= export_dir_rva && func_rva < export_end) {
            efunc.is_forwarder = true;
            auto fwd_off = rva_to_offset(func_rva);
            if (fwd_off) {
                auto fwd = read_ascii_string(data, *fwd_off);
                if (fwd) efunc.forwarder = std::move(*fwd);
            }
        }

        for (size_t ni = 0; ni < name_ordinals.size(); ++ni) {
            if (name_ordinals[ni] == i) {
                efunc.name = names[ni];
                break;
            }
        }

        table.functions.push_back(std::move(efunc));
    }

    return table;
}

// ============================================================================
// ExportTableManager::rebuild_export_table
// ============================================================================

MxResult<ByteBuffer> ExportTableManager::rebuild_export_table(
    const pe::ExportTable& exports)
{
    if (exports.functions.empty()) {
        return ByteBuffer{};
    }

    uint32_t max_ordinal = 0;
    uint32_t min_ordinal = UINT32_MAX;
    uint32_t num_names = 0;

    for (const auto& func : exports.functions) {
        if (func.ordinal > max_ordinal) max_ordinal = func.ordinal;
        if (func.ordinal < min_ordinal) min_ordinal = func.ordinal;
        if (!func.name.empty()) ++num_names;
    }

    const uint32_t base = exports.base;
    const uint32_t num_functions = max_ordinal - base + 1;

    const size_t dir_size = sizeof(pe::IMAGE_EXPORT_DIRECTORY);
    const size_t eat_size = num_functions * sizeof(uint32_t);
    const size_t name_ptrs_size = num_names * sizeof(uint32_t);
    const size_t ordinals_size = num_names * sizeof(uint16_t);

    size_t strings_size = exports.dll_name.size() + 1;
    for (const auto& func : exports.functions) {
        if (!func.name.empty()) {
            strings_size += func.name.size() + 1;
        }
        if (func.is_forwarder && !func.forwarder.empty()) {
            strings_size += func.forwarder.size() + 1;
        }
    }

    const size_t total = dir_size + eat_size + name_ptrs_size + ordinals_size + strings_size;
    ByteBuffer buffer(total, 0);

    const size_t eat_off = dir_size;
    const size_t name_ptrs_off = eat_off + eat_size;
    const size_t ordinals_off = name_ptrs_off + name_ptrs_size;
    size_t strings_off = ordinals_off + ordinals_size;

    pe::IMAGE_EXPORT_DIRECTORY edir{};
    edir.Base = base;
    edir.NumberOfFunctions = num_functions;
    edir.NumberOfNames = num_names;
    edir.AddressOfFunctions = static_cast<uint32_t>(eat_off);
    edir.AddressOfNames = static_cast<uint32_t>(name_ptrs_off);
    edir.AddressOfNameOrdinals = static_cast<uint32_t>(ordinals_off);

    edir.Name = static_cast<uint32_t>(strings_off);
    std::memcpy(buffer.data() + strings_off,
                 exports.dll_name.c_str(), exports.dll_name.size() + 1);
    strings_off += exports.dll_name.size() + 1;

    for (const auto& func : exports.functions) {
        const uint32_t idx = func.ordinal - base;
        if (idx < num_functions) {
            uint32_t rva = func.rva;
            if (func.is_forwarder && !func.forwarder.empty()) {
                rva = static_cast<uint32_t>(strings_off);
                std::memcpy(buffer.data() + strings_off,
                             func.forwarder.c_str(), func.forwarder.size() + 1);
                strings_off += func.forwarder.size() + 1;
            }
            std::memcpy(buffer.data() + eat_off + idx * sizeof(uint32_t),
                         &rva, sizeof(uint32_t));
        }
    }

    std::vector<std::pair<std::string, uint16_t>> named_exports;
    for (const auto& func : exports.functions) {
        if (!func.name.empty()) {
            named_exports.emplace_back(func.name,
                                       static_cast<uint16_t>(func.ordinal - base));
        }
    }
    std::ranges::sort(named_exports, {}, &std::pair<std::string, uint16_t>::first);

    for (size_t i = 0; i < named_exports.size(); ++i) {
        const auto& [name, ordinal_idx] = named_exports[i];

        auto name_rva = static_cast<uint32_t>(strings_off);
        std::memcpy(buffer.data() + name_ptrs_off + i * sizeof(uint32_t),
                     &name_rva, sizeof(uint32_t));

        std::memcpy(buffer.data() + ordinals_off + i * sizeof(uint16_t),
                     &ordinal_idx, sizeof(uint16_t));

        std::memcpy(buffer.data() + strings_off, name.c_str(), name.size() + 1);
        strings_off += name.size() + 1;
    }

    std::memcpy(buffer.data(), &edir, sizeof(pe::IMAGE_EXPORT_DIRECTORY));

    return buffer;
}

// ============================================================================
// ExportTableManager::read_ascii_string
// ============================================================================

MxResult<std::string> ExportTableManager::read_ascii_string(
    ByteView data, FileOffset offset, size_t max_len)
{
    if (static_cast<size_t>(offset) >= data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_export_table,
            "Смещение строки 0x{:X} за пределами файла (0x{:X})",
            offset, data.size()));
    }

    const size_t available = data.size() - offset;
    const size_t limit = std::min(available, max_len);
    const auto* start = reinterpret_cast<const char*>(data.data() + offset);

    size_t len = 0;
    while (len < limit && start[len] != '\0') {
        ++len;
    }

    return std::string(start, len);
}

} // namespace mx
