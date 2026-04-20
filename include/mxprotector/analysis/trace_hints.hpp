/**
 * @file trace_hints.hpp
 * @brief [BUILDER] Source-linked labels emitted by builder for the
 *        tracing MCP (see MCP_TRACING.md).
 *
 * @details TraceHints хранит метаданные сборки и имена добавленных
 *          MxProtector-секций, которые MCP-трассировщик использует
 *          для привязки runtime-событий к исходным сущностям.
 *
 *          Phase 1 API ограничен `set_build_info` + `add_section` +
 *          `to_json`. Остальные слоты схемы (`cff`/`vm`/`guard`/
 *          `strings`/`iat`) эмитятся `to_json()` пустыми: схема v1
 *          заморожена с Phase 1, последующие фазы только заполняют
 *          уже существующие поля.
 *
 * @note Объект — чисто data + сериализация. Никакого файлового I/O;
 *       запись `.mxtrace.json` лежит в `main.cpp` за
 *       `config.emit_trace_hints`.
 *
 * @note Schema v1 (contract with `mcp-tools/tracing/src/mx_tracing/
 *       sidecar.py` — pydantic отклонит неизвестные мажоры):
 *       `schema_version`, `build`, `sections`, `cff`, `vm`, `guard`,
 *       `strings`, `iat`.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mx::analysis {

/**
 * @brief Запись об одной секции финального PE.
 *
 * @details `role` — логическая роль секции в MxProtector (`vm`, `cff`,
 *          `packer`, `strings`, `guard`) либо исходное имя секции
 *          (`.text`, `.rdata`, …), если она не добавлена протектором.
 *          `name` — фактическое runtime-имя в PE (рандомизируется
 *          per-build для протекторных секций).
 */
struct TraceHintsSection {
    std::string role;
    std::string name;
    std::uint32_t rva             = 0;
    std::uint32_t size            = 0;
    std::uint32_t characteristics = 0;
};

/**
 * @brief Метаданные сборки, сериализуемые в поле `build` sidecar'а.
 */
struct TraceHintsBuild {
    std::string input;
    std::string output;
    std::string level;
    std::string timestamp; ///< ISO-8601 UTC, `YYYY-MM-DDThh:mm:ssZ`.
};

/**
 * @brief Контейнер source-linked labels для sidecar `.mxtrace.json`.
 *
 * @details SOLID/SRP: хранит данные и сериализует в JSON. Не владеет
 *          путями и не пишет на диск.
 */
class TraceHints final {
public:
    TraceHints()                             = default;
    TraceHints(const TraceHints&)            = delete;
    TraceHints& operator=(const TraceHints&) = delete;
    TraceHints(TraceHints&&) noexcept        = default;
    TraceHints& operator=(TraceHints&&) noexcept = default;
    ~TraceHints()                            = default;

    /**
     * @brief Устанавливает блок метаданных сборки.
     *
     * @param input     Путь к входному PE.
     * @param output    Путь к защищённому PE.
     * @param level     Текстовое имя уровня защиты (`strong`, …).
     * @param timestamp ISO-8601 UTC, формируется вызывающим кодом.
     */
    void set_build_info(std::string_view input,
                        std::string_view output,
                        std::string_view level,
                        std::string_view timestamp);

    /**
     * @brief Добавляет секцию в массив `sections`.
     *
     * @param role            Логическая роль (`vm`/`cff`/`packer`/
     *                        `strings`/`guard` или исходное имя).
     * @param name            Runtime-имя секции в PE.
     * @param rva             Virtual address секции (RVA).
     * @param size            Virtual size секции.
     * @param characteristics PE `Characteristics` (IMAGE_SCN_*).
     */
    void add_section(std::string_view role,
                     std::string_view name,
                     std::uint32_t rva,
                     std::uint32_t size,
                     std::uint32_t characteristics);

    /**
     * @brief Сериализует labels в JSON согласно schema v1.
     *
     * @return UTF-8 текст sidecar-документа с финальным `\n`.
     *
     * @note Даже пустой контейнер возвращает валидный documento с
     *       `schema_version: 1` — это контракт pydantic-схемы на
     *       стороне MCP.
     */
    [[nodiscard]] std::string to_json() const;

    /**
     * @brief Истина если не задан `build`-блок и нет секций.
     *
     * @note Используется `trace_hints_test.cpp` для leak-guard:
     *       выключенный флаг `--trace-hints` не должен ничего
     *       аккумулировать.
     */
    [[nodiscard]] bool empty() const noexcept;

private:
    TraceHintsBuild                 build_{};
    std::vector<TraceHintsSection>  sections_{};
};

} // namespace mx::analysis
