/**
 * @file map_parser.hpp
 * @brief [BUILDER] Парсер .map файлов формата MSVC для автоматического обнаружения функций.
 *
 * @details MapParser анализирует .map файл, сгенерированный MSVC-линкером,
 *          и извлекает список пользовательских функций из секции .text,
 *          пригодных для CFF-трансформации.
 *
 *          Правила фильтрации:
 *          - Whitelist: только функции из .text (секция 0001).
 *          - Blacklist: функции из CRT-библиотек (libucrt, libvcruntime, MSVCRT и т.д.).
 *          - Blacklist: экспортные thunk-функции (содержат только jmp/call).
 *          - Размер: пропускаются < 32 байт и > 9192 байт.
 *
 *          SOLID (SRP): отвечает только за парсинг .map файлов.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"

namespace mx {

/**
 * @brief Запись о функции, извлечённой из .map файла.
 */
struct MapFunctionEntry {
    std::string name;
    Rva         rva          = 0;
    uint32_t    size         = 0;
    uint32_t    section_index = 0;
    std::string object_file;
    bool        is_library   = false;
};

/**
 * @brief Результат парсинга .map файла.
 */
struct MapParseResult {
    Va                           image_base = 0;
    std::vector<MapFunctionEntry> all_functions;
    std::vector<MapFunctionEntry> cff_candidates;
};

/**
 * @brief Парсер MSVC .map файлов для обнаружения CFF-целей.
 *
 * @details Читает .map файл, извлекает публичные символы из .text секции,
 *          фильтрует CRT/Library функции и экспортные thunks,
 *          вычисляет размеры функций и возвращает список кандидатов для CFF.
 */
class MapParser final {
public:
    static constexpr uint32_t kMinFunctionSize = 32;
    static constexpr uint32_t kMaxFunctionSize = 9192;

    MapParser() = delete;

    /**
     * @brief Парсит .map файл и возвращает список функций.
     * @param map_path Путь к .map файлу.
     * @return Результат парсинга или ошибка.
     */
    [[nodiscard]] static MxResult<MapParseResult> parse(
        const std::filesystem::path& map_path);

    /**
     * @brief Фильтрует функции для CFF-трансформации.
     * @param functions Все функции из .map файла.
     * @param pe_code Код секции .text для детекции thunks.
     * @param text_rva RVA начала .text секции.
     * @param text_size Размер .text секции.
     * @return Отфильтрованные кандидаты для CFF.
     */
    [[nodiscard]] static std::vector<MapFunctionEntry> filter_candidates(
        const std::vector<MapFunctionEntry>& functions,
        ByteView pe_code,
        Rva text_rva,
        uint32_t text_size);

private:
    [[nodiscard]] static bool is_library_object(const std::string& obj_name);
    [[nodiscard]] static bool is_crt_function_name(const std::string& name);
    [[nodiscard]] static bool is_export_thunk(ByteView func_code);
};

} // namespace mx
