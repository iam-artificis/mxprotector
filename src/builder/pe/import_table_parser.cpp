/**
 * @file import_table_parser.cpp
 * @brief [BUILDER] Read-side of `ImportTableManager`.
 *
 * Owns the byte-level parse path (extracted from import_table.cpp
 * during R10): walks IMAGE_IMPORT_DESCRIPTOR table, decodes the
 * matching INT/IAT thunks for both PE32 and PE32+, and reads the
 * embedded ASCIIZ DLL / function names safely (length-capped).
 *
 * Modification (`add_import` / `remove_import`) and serialization
 * (`rebuild_import_table`) live in the sibling import_table.cpp.
 */

#include "mxprotector/pe/import_table.hpp"

#include <cstring>

namespace mx {

namespace {

/**
 * @brief Bounds-checked memcpy of a trivially-copyable struct.
 *
 * Returns an `invalid_import_table` error when the requested
 * `offset + sizeof(T)` walks past the end of the buffer instead
 * of returning bogus zero-initialised data — every caller expects
 * a fail-closed read, never a silent zero.
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
