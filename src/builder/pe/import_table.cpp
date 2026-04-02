/**
 * @file import_table.cpp
 * @brief [BUILDER] Реализация ImportTableManager — парсинг, модификация и реконструкция
 *        таблицы импортов PE.
 *
 * @details Полный цикл работы с Import Directory Table:
 *          - parse_imports: последовательный разбор IMAGE_IMPORT_DESCRIPTOR → thunks → имена
 *          - add_import/remove_import: модификация высокоуровневого представления
 *          - rebuild_import_table: сериализация ImportEntry → бинарные структуры
 *
 *          Поддерживает PE32 (32-bit thunks) и PE32+ (64-bit thunks).
 *          Импорт по ординалу определяется по старшему биту thunk-значения.
 *
 * @note Все чтения из буфера строго валидируются по границам.
 *       ASCIIZ-строки читаются с ограничением максимальной длины.
 */

#include "mxprotector/pe/import_table.hpp"

#include <cstring>
#include <algorithm>
#include <ranges>

namespace mx {

namespace {

/**
 * @brief Безопасно читает структуру T из буфера по указанному смещению.
 * @tparam T Тип читаемой структуры.
 * @param data Буфер данных.
 * @param offset Смещение.
 * @return Копия структуры или ошибка.
 */
template <typename T>
[[nodiscard]] MxResult<T> safe_read(ByteView data, size_t offset) {
    if (offset + sizeof(T) > data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_import_table,
            "Чтение структуры {} байт по смещению 0x{:X} выходит за пределы (0x{:X})",
            sizeof(T), offset, data.size()));
    }
    T result{};
    std::memcpy(&result, data.data() + offset, sizeof(T));
    return result;
}

} // anonymous namespace

// ============================================================================
// ImportTableManager::parse_imports
// ============================================================================

MxResult<std::vector<pe::ImportEntry>> ImportTableManager::parse_imports(
    ByteView data,
    Rva import_dir_rva,
    uint32_t import_dir_size,
    bool is_64,
    std::function<MxResult<FileOffset>(Rva)> rva_to_offset)
{
    if (import_dir_rva == 0 || import_dir_size == 0) {
        return std::vector<pe::ImportEntry>{};
    }

    auto dir_offset_result = rva_to_offset(import_dir_rva);
    if (!dir_offset_result) return std::unexpected(dir_offset_result.error());
    const auto dir_offset = static_cast<size_t>(*dir_offset_result);

    std::vector<pe::ImportEntry> imports;

    constexpr size_t desc_size = sizeof(pe::IMAGE_IMPORT_DESCRIPTOR);
    constexpr size_t max_descriptors = 4096;

    for (size_t i = 0; i < max_descriptors; ++i) {
        const size_t desc_offset = dir_offset + i * desc_size;

        auto desc_result = safe_read<pe::IMAGE_IMPORT_DESCRIPTOR>(data, desc_offset);
        if (!desc_result) break;
        const auto& desc = *desc_result;

        if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0) {
            break;
        }

        pe::ImportEntry entry;
        entry.descriptor_rva = static_cast<uint32_t>(import_dir_rva + i * desc_size);

        if (desc.Name != 0) {
            auto name_offset_result = rva_to_offset(desc.Name);
            if (!name_offset_result) continue;

            auto name_result = read_ascii_string(data, *name_offset_result);
            if (name_result) {
                entry.dll_name = std::move(*name_result);
            }
        }

        if (entry.dll_name.empty()) continue;

        Rva thunk_rva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
        auto functions_result = parse_thunks(data, thunk_rva, is_64, rva_to_offset);
        if (functions_result) {
            entry.functions = std::move(*functions_result);

            if (desc.FirstThunk != 0) {
                auto iat_offset_result = rva_to_offset(desc.FirstThunk);
                if (iat_offset_result) {
                    const size_t thunk_size = is_64 ? sizeof(uint64_t) : sizeof(uint32_t);
                    for (size_t j = 0; j < entry.functions.size(); ++j) {
                        entry.functions[j].thunk_rva =
                            desc.FirstThunk + static_cast<uint32_t>(j * thunk_size);
                    }
                }
            }
        }

        imports.push_back(std::move(entry));
    }

    return imports;
}

// ============================================================================
// ImportTableManager::parse_thunks
// ============================================================================

MxResult<std::vector<pe::ImportFunction>> ImportTableManager::parse_thunks(
    ByteView data,
    Rva thunk_rva,
    bool is_64,
    const std::function<MxResult<FileOffset>(Rva)>& rva_to_offset)
{
    auto base_offset_result = rva_to_offset(thunk_rva);
    if (!base_offset_result) return std::unexpected(base_offset_result.error());
    const auto base_offset = static_cast<size_t>(*base_offset_result);

    std::vector<pe::ImportFunction> functions;
    constexpr size_t max_thunks = 65536;

    const size_t thunk_size = is_64 ? sizeof(uint64_t) : sizeof(uint32_t);

    for (size_t i = 0; i < max_thunks; ++i) {
        const size_t offset = base_offset + i * thunk_size;

        if (offset + thunk_size > data.size()) break;

        pe::ImportFunction func;

        if (is_64) {
            uint64_t thunk_val = 0;
            std::memcpy(&thunk_val, data.data() + offset, sizeof(uint64_t));

            if (thunk_val == 0) break;

            if (thunk_val & pe::IMAGE_ORDINAL_FLAG64) {
                func.by_ordinal = true;
                func.ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
            }
            else {
                auto hint_offset_result = rva_to_offset(static_cast<Rva>(thunk_val));
                if (!hint_offset_result) {
                    functions.push_back(func);
                    continue;
                }

                const auto hint_off = static_cast<size_t>(*hint_offset_result);
                if (hint_off + sizeof(uint16_t) <= data.size()) {
                    std::memcpy(&func.hint, data.data() + hint_off, sizeof(uint16_t));

                    auto name_result = read_ascii_string(
                        data, static_cast<FileOffset>(hint_off + sizeof(uint16_t)));
                    if (name_result) {
                        func.name = std::move(*name_result);
                    }
                }
            }
        }
        else {
            uint32_t thunk_val = 0;
            std::memcpy(&thunk_val, data.data() + offset, sizeof(uint32_t));

            if (thunk_val == 0) break;

            if (thunk_val & pe::IMAGE_ORDINAL_FLAG32) {
                func.by_ordinal = true;
                func.ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
            }
            else {
                auto hint_offset_result = rva_to_offset(thunk_val);
                if (!hint_offset_result) {
                    functions.push_back(func);
                    continue;
                }

                const auto hint_off = static_cast<size_t>(*hint_offset_result);
                if (hint_off + sizeof(uint16_t) <= data.size()) {
                    std::memcpy(&func.hint, data.data() + hint_off, sizeof(uint16_t));

                    auto name_result = read_ascii_string(
                        data, static_cast<FileOffset>(hint_off + sizeof(uint16_t)));
                    if (name_result) {
                        func.name = std::move(*name_result);
                    }
                }
            }
        }

        functions.push_back(std::move(func));
    }

    return functions;
}

// ============================================================================
// ImportTableManager::add_import
// ============================================================================

MxStatus ImportTableManager::add_import(
    std::string_view dll_name,
    std::string_view function_name)
{
    auto& imports = image_.imports();

    auto it = std::ranges::find_if(imports, [&](const pe::ImportEntry& e) {
        return e.dll_name == dll_name;
    });

    if (it != imports.end()) {
        auto func_it = std::ranges::find_if(it->functions, [&](const pe::ImportFunction& f) {
            return f.name == function_name;
        });
        if (func_it != it->functions.end()) {
            return {};
        }

        pe::ImportFunction func;
        func.name = std::string(function_name);
        it->functions.push_back(std::move(func));
    }
    else {
        pe::ImportEntry entry;
        entry.dll_name = std::string(dll_name);

        pe::ImportFunction func;
        func.name = std::string(function_name);
        entry.functions.push_back(std::move(func));

        imports.push_back(std::move(entry));
    }

    return {};
}

// ============================================================================
// ImportTableManager::remove_import
// ============================================================================

MxStatus ImportTableManager::remove_import(
    std::string_view dll_name,
    std::string_view function_name)
{
    auto& imports = image_.imports();

    auto dll_it = std::ranges::find_if(imports, [&](const pe::ImportEntry& e) {
        return e.dll_name == dll_name;
    });

    if (dll_it == imports.end()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_import_table,
            "DLL '{}' не найдена в таблице импортов", dll_name));
    }

    auto func_it = std::ranges::find_if(dll_it->functions, [&](const pe::ImportFunction& f) {
        return f.name == function_name;
    });

    if (func_it == dll_it->functions.end()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_import_table,
            "Функция '{}' не найдена в DLL '{}'", function_name, dll_name));
    }

    dll_it->functions.erase(func_it);

    if (dll_it->functions.empty()) {
        imports.erase(dll_it);
    }

    return {};
}

// ============================================================================
// ImportTableManager::rebuild_import_table
// ============================================================================

MxResult<ByteBuffer> ImportTableManager::rebuild_import_table(
    const std::vector<pe::ImportEntry>& imports,
    uint32_t file_alignment)
{
    if (imports.empty()) {
        return ByteBuffer{};
    }

    const size_t num_descriptors = imports.size() + 1;
    const size_t descriptors_size = num_descriptors * sizeof(pe::IMAGE_IMPORT_DESCRIPTOR);

    size_t total_thunks_size = 0;
    for (const auto& entry : imports) {
        total_thunks_size += (entry.functions.size() + 1) * sizeof(uint64_t) * 2;
    }

    size_t total_names_size = 0;
    for (const auto& entry : imports) {
        total_names_size += entry.dll_name.size() + 1;
        for (const auto& func : entry.functions) {
            if (!func.by_ordinal) {
                total_names_size += sizeof(uint16_t) + func.name.size() + 1;
                if (total_names_size % 2 != 0) total_names_size++;
            }
        }
    }

    const size_t total_size = descriptors_size + total_thunks_size + total_names_size;
    const size_t aligned_size = static_cast<size_t>(
        align_up(total_size, file_alignment));

    ByteBuffer buffer(aligned_size, 0);

    size_t int_offset = descriptors_size;
    size_t iat_offset = int_offset + total_thunks_size / 2;
    size_t name_offset = descriptors_size + total_thunks_size;

    for (size_t i = 0; i < imports.size(); ++i) {
        const auto& entry = imports[i];

        pe::IMAGE_IMPORT_DESCRIPTOR desc{};
        desc.OriginalFirstThunk = static_cast<uint32_t>(int_offset);
        desc.FirstThunk = static_cast<uint32_t>(iat_offset);

        desc.Name = static_cast<uint32_t>(name_offset);
        std::memcpy(buffer.data() + name_offset,
                     entry.dll_name.c_str(), entry.dll_name.size() + 1);
        name_offset += entry.dll_name.size() + 1;

        for (size_t j = 0; j < entry.functions.size(); ++j) {
            const auto& func = entry.functions[j];

            uint64_t thunk_value = 0;
            if (func.by_ordinal) {
                thunk_value = pe::IMAGE_ORDINAL_FLAG64 | func.ordinal;
            }
            else {
                thunk_value = static_cast<uint64_t>(name_offset);

                uint16_t hint = func.hint;
                std::memcpy(buffer.data() + name_offset, &hint, sizeof(uint16_t));
                name_offset += sizeof(uint16_t);

                std::memcpy(buffer.data() + name_offset,
                             func.name.c_str(), func.name.size() + 1);
                name_offset += func.name.size() + 1;
                if (name_offset % 2 != 0) {
                    buffer[name_offset++] = 0;
                }
            }

            std::memcpy(buffer.data() + int_offset, &thunk_value, sizeof(uint64_t));
            int_offset += sizeof(uint64_t);

            std::memcpy(buffer.data() + iat_offset, &thunk_value, sizeof(uint64_t));
            iat_offset += sizeof(uint64_t);
        }

        uint64_t null_thunk = 0;
        std::memcpy(buffer.data() + int_offset, &null_thunk, sizeof(uint64_t));
        int_offset += sizeof(uint64_t);

        std::memcpy(buffer.data() + iat_offset, &null_thunk, sizeof(uint64_t));
        iat_offset += sizeof(uint64_t);

        std::memcpy(buffer.data() + i * sizeof(pe::IMAGE_IMPORT_DESCRIPTOR),
                     &desc, sizeof(pe::IMAGE_IMPORT_DESCRIPTOR));
    }

    pe::IMAGE_IMPORT_DESCRIPTOR null_desc{};
    std::memcpy(buffer.data() + imports.size() * sizeof(pe::IMAGE_IMPORT_DESCRIPTOR),
                 &null_desc, sizeof(pe::IMAGE_IMPORT_DESCRIPTOR));

    return buffer;
}

// ============================================================================
// ImportTableManager::read_ascii_string
// ============================================================================

MxResult<std::string> ImportTableManager::read_ascii_string(
    ByteView data, FileOffset offset, size_t max_len)
{
    if (static_cast<size_t>(offset) >= data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_import_table,
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

    if (len == 0) {
        return std::string{};
    }

    return std::string(start, len);
}

} // namespace mx
