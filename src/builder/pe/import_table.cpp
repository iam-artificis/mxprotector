/**
 * @file import_table.cpp
 * @brief [BUILDER] Modify + rebuild side of `ImportTableManager`.
 *
 * Owns the high-level mutation API (`add_import` /
 * `remove_import`) and the binary serialiser
 * (`rebuild_import_table`) that turns the in-memory
 * `std::vector<ImportEntry>` back into the on-disk Import Directory
 * table layout (descriptors → INT/IAT thunks → name pool).
 *
 * The byte-level parse path (`parse_imports`, `parse_thunks`,
 * `read_ascii_string`) lives in the sibling
 * `import_table_parser.cpp`. Both files contribute methods to the
 * same `ImportTableManager` class declared in import_table.hpp.
 *
 * Supports PE32 (32-bit thunks) and PE32+ (64-bit thunks) — but
 * the rebuilder always emits 64-bit thunks because every
 * downstream caller is x64.
 */

#include "mxprotector/pe/import_table.hpp"

#include <cstring>
#include <algorithm>
#include <ranges>

namespace mx {

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

} // namespace mx
