/**
 * @file trace_hints.hpp
 * @brief [BUILDER] Source-linked labels emitted by builder for the
 *        tracing MCP (see MCP_TRACING.md).
 *
 * @details TraceHints хранит метаданные сборки + per-pass labels,
 *          которые MCP-трассировщик использует для привязки runtime-
 *          событий к исходным сущностям (CFF states, VM handlers,
 *          guard regions, string slots, IAT range).
 *
 *          Phase 1: `build` + `sections`.
 *          Phase 4A: API расширен слотами `cff`/`vm`/`guard`/`strings`
 *                    /`iat` (реальное заполнение из pass'ов — в 4B/4C).
 *
 * @note Объект — чисто data + сериализация. Никакого файлового I/O;
 *       запись `.mxtrace.json` лежит в `main.cpp` за
 *       `config.emit_trace_hints`.
 *
 * @note Schema v1 (contract с `mcp-tools/tracing/src/mx_tracing/
 *       sidecar.py`). Аддитивные изменения в пределах мажора —
 *       без бампа версии (pydantic принимает расширенные поля
 *       через default `extra='ignore'`).
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mx::analysis {

// ============================================================================
// Enums — kind указывает происхождение label'а (почему он появился).
// Имена отражают термины builder'а; MCP мапит их 1:1.
// ============================================================================

/// Происхождение CFF-state'а в dispatcher-таблице.
enum class CffStateKind : std::uint8_t {
    original,   ///< Handler исходного базового блока.
    predicate,  ///< Блок-предикат (opaque / hash-based).
    mba,        ///< Блок MBA-перехода между state'ами.
    bogus,      ///< Bogus-блок (ложный путь).
};

/// Форма opaque predicate'а.
enum class PredicateKind : std::uint8_t {
    opaque_hash,      ///< Predicate через hash-инвариант.
    mba_transition,  ///< Predicate внутри MBA-перехода state.
};

/// Форма мутации (заполняется в Phase 4D — сейчас объявлена для
/// единого контракта enum'ов, хранение появится вместе с `mutation`-
/// slot в pydantic Sidecar).
enum class MutationSiteKind : std::uint8_t {
    substitution,
    split,
    reassign,
};

/// String → JSON-строка для enum'ов (используется to_json).
[[nodiscard]] std::string_view cff_state_kind_name(CffStateKind k) noexcept;
[[nodiscard]] std::string_view predicate_kind_name(PredicateKind k) noexcept;

// ============================================================================
// Leaf label structs
// ============================================================================

struct TraceHintsSection {
    std::string   role;
    std::string   name;
    std::uint32_t rva             = 0;
    std::uint32_t size            = 0;
    std::uint32_t characteristics = 0;
};

struct TraceHintsBuild {
    std::string input;
    std::string output;
    std::string level;
    std::string timestamp;
};

struct CffStateLabel {
    std::uint32_t id                   = 0;
    std::uint32_t dispatcher_entry_rva = 0;
    std::uint32_t source_bb_rva        = 0;
    CffStateKind  kind                 = CffStateKind::original;
};

struct CffPredicateLabel {
    std::uint32_t id   = 0;
    std::uint32_t rva  = 0;
    PredicateKind kind = PredicateKind::opaque_hash;
};

struct VmHandlerLabel {
    std::uint32_t id     = 0;
    std::uint32_t rva    = 0;
    std::uint32_t size   = 0;
    std::string   opcode;
};

struct GuardRegionLabel {
    std::uint32_t id   = 0;
    std::uint32_t rva  = 0;
    std::uint32_t size = 0;
};

struct StringSlotLabel {
    std::uint32_t id            = 0;
    std::uint32_t desc_rva      = 0;
    std::uint32_t plaintext_len = 0;
};

// ============================================================================
// Grouped hint sections (mirror the JSON schema v1 top-level shape)
// ============================================================================

struct CffHints {
    std::uint32_t                  dispatcher_rva = 0;
    std::uint32_t                  state_var_rva  = 0;
    std::vector<CffStateLabel>     states;
    std::vector<CffPredicateLabel> predicates;
};

struct VmHints {
    std::uint32_t                dispatcher_rva    = 0;
    std::uint32_t                handler_table_rva = 0;
    std::vector<VmHandlerLabel>  handlers;
};

struct GuardHints {
    std::vector<GuardRegionLabel> regions;
};

struct StringHints {
    std::vector<StringSlotLabel> slots;
};

struct IatHints {
    std::uint32_t rva  = 0;
    std::uint32_t size = 0;
};

// ============================================================================
// TraceHints — контейнер + сериализация
// ============================================================================

/**
 * @brief Контейнер source-linked labels для sidecar `.mxtrace.json`.
 *
 * @details SOLID/SRP: хранит данные и сериализует в JSON. Не владеет
 *          путями и не пишет на диск.
 */
class TraceHints final {
public:
    TraceHints()                                 = default;
    TraceHints(const TraceHints&)                = delete;
    TraceHints& operator=(const TraceHints&)     = delete;
    TraceHints(TraceHints&&) noexcept            = default;
    TraceHints& operator=(TraceHints&&) noexcept = default;
    ~TraceHints()                                = default;

    // ------------------------------------------------------------------
    // Phase 1 — build info + sections
    // ------------------------------------------------------------------

    void set_build_info(std::string_view input,
                        std::string_view output,
                        std::string_view level,
                        std::string_view timestamp);

    void add_section(std::string_view role,
                     std::string_view name,
                     std::uint32_t    rva,
                     std::uint32_t    size,
                     std::uint32_t    characteristics);

    // ------------------------------------------------------------------
    // Phase 4A — CFF / VM / Guard / Strings / IAT
    // ------------------------------------------------------------------

    /// Устанавливает runtime RVA dispatcher'а CFF и state-переменной.
    /// Для функций в trampoline-секции — RVA входа dispatcher'а.
    void set_cff_dispatcher(std::uint32_t dispatcher_rva,
                            std::uint32_t state_var_rva) noexcept;

    /// Добавляет один state в dispatcher-таблицу CFF.
    void add_cff_state(std::uint32_t id,
                       std::uint32_t dispatcher_entry_rva,
                       std::uint32_t source_bb_rva,
                       CffStateKind  kind);

    /// Добавляет один opaque predicate, созданный CFF или obfuscation.
    void add_opaque_predicate(std::uint32_t id,
                              std::uint32_t rva,
                              PredicateKind kind);

    /// Устанавливает RVA VM dispatcher'а и handler table.
    void set_vm_dispatcher(std::uint32_t dispatcher_rva,
                           std::uint32_t handler_table_rva) noexcept;

    /// Добавляет один VM handler body.
    void add_vm_handler(std::uint32_t    id,
                        std::uint32_t    rva,
                        std::uint32_t    size,
                        std::string_view opcode);

    /// Добавляет один relocated guard region.
    void add_guard_region(std::uint32_t id,
                          std::uint32_t rva,
                          std::uint32_t size);

    /// Добавляет один string slot (desc + plaintext_len из метаданных).
    void add_string_slot(std::uint32_t id,
                         std::uint32_t desc_rva,
                         std::uint32_t plaintext_len);

    /// Устанавливает диапазон IAT в защищённом PE.
    void set_iat(std::uint32_t rva, std::uint32_t size) noexcept;

    // ------------------------------------------------------------------
    // Сериализация
    // ------------------------------------------------------------------

    /// Возвращает UTF-8 текст sidecar'а по schema v1 (завершается '\n').
    [[nodiscard]] std::string to_json() const;

    /// Истина если ни один slot не заполнен (leak-guard для `--trace-
    /// hints` выключенного флага).
    [[nodiscard]] bool empty() const noexcept;

    // ------------------------------------------------------------------
    // Доступ read-only для unit-тестов
    // ------------------------------------------------------------------

    [[nodiscard]] const TraceHintsBuild&             build()    const noexcept { return build_; }
    [[nodiscard]] const std::vector<TraceHintsSection>& sections() const noexcept { return sections_; }
    [[nodiscard]] const CffHints&                    cff()      const noexcept { return cff_; }
    [[nodiscard]] const VmHints&                     vm()       const noexcept { return vm_; }
    [[nodiscard]] const GuardHints&                  guard()    const noexcept { return guard_; }
    [[nodiscard]] const StringHints&                 strings()  const noexcept { return strings_; }
    [[nodiscard]] const IatHints&                    iat()      const noexcept { return iat_; }

private:
    TraceHintsBuild                 build_{};
    std::vector<TraceHintsSection>  sections_{};
    CffHints                        cff_{};
    VmHints                         vm_{};
    GuardHints                      guard_{};
    StringHints                     strings_{};
    IatHints                        iat_{};
};

} // namespace mx::analysis
