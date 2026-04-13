/**
 * @file protection_config.hpp
 * @brief [BUILDER] Конфигурация защиты — набор параметров для пайплайна протектора.
 *
 * @details ProtectionConfig описывает все настройки процесса защиты PE-файла:
 *          пути ввода/вывода, уровень защиты, включённые/отключённые проходы,
 *          глубину VM-вложенности и т.д. Может быть создана фабричным методом
 *          from_level() или заполнена вручную из CLI-аргументов.
 *
 * @note Выходной путь (output_path) автоматически генерируется как file.mx.ext
 *       если не задан явно.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "mxprotector/core/types.hpp"

namespace mx {

/**
 * @brief Режим строковой защиты (S2 pass).
 *
 * `disabled` — проход полностью пропускается, строки остаются plaintext в
 * `.rdata`. Нужен для targets где любой overhead неприемлем (minimal level,
 * benchmarks, a/b баз).
 *
 * `stub` — декриптор эмитится как обычный x64 код в отдельной секции. Каждый
 * XREF рерайтится на call trampoline → common decryptor. Первый вызов xor-decodes
 * строку на месте и ставит sticky flag, последующие возвращают кэшированный
 * pointer. Дёшево в runtime (hot path ~без overhead после первого вызова),
 * но сам декриптор — plain asm, symbolically executable.
 *
 * `virtualized` — тот же декриптор, но проход инжектит его в `ctx.markers()`
 * как VM region, и `VirtualizationPass` лифтит его в bytecode. Reverser
 * должен сначала победить VM (handler table, dispatcher, rolling key),
 * потом разобрать логику декриптора внутри bytecode — две дорогостоящих
 * фазы вместо одной. Overhead на первом вызове каждой строки равен одному
 * VM entry (~50×), hot path после кэширования тот же.
 *
 * `ephemeral` — S3. The decryptor never caches. Every call allocates a
 * fresh scratch-ring slot via `lock xadd`, copies the ciphertext in,
 * XOR-decrypts into the slot, and returns the slot pointer. The data
 * pool stays encrypted at rest and a memory dump catches at most
 * `kEphemeralRingSlots` concurrently decrypted strings (per process),
 * not all of them forever. Slower than `stub` for hot-path strings
 * (full decrypt per call) and doesn't combine with `virtualized` in
 * MVP — the S3 body has a different shape and patch offsets than the
 * sticky-flag S2b body the VM lifter knows about.
 *
 * Auto-fallback: если выбран `virtualized` но `enable_vm=false`, проход
 * откатывается на `stub` с предупреждением. Комбинация не имеет смысла
 * и скорее всего ошибка конфигурации.
 */
enum class StringProtectionMode : uint8_t {
    disabled    = 0,
    stub        = 1,
    virtualized = 2,
    ephemeral   = 3,
};

[[nodiscard]] constexpr std::string_view
string_protection_mode_name(StringProtectionMode m) noexcept {
    switch (m) {
        case StringProtectionMode::disabled:    return "disabled";
        case StringProtectionMode::stub:        return "stub";
        case StringProtectionMode::virtualized: return "virtualized";
        case StringProtectionMode::ephemeral:   return "ephemeral";
    }
    return "unknown";
}

/**
 * @brief Конфигурация защиты PE-файла.
 *
 * @details Агрегат всех параметров, управляющих пайплайном защиты.
 *          Каждый булевый флаг включает/отключает конкретный проход.
 *          Уровень защиты (ProtectionLevel) определяет предустановку.
 */
struct ProtectionConfig {
    std::filesystem::path input_path;     ///< Путь к входному PE-файлу
    std::filesystem::path output_path;    ///< Путь к выходному файлу (auto: file.mx.ext)
    std::filesystem::path map_file_path;  ///< Путь к .map файлу (опциональный, для CFF)

    ProtectionLevel level = ProtectionLevel::standard; ///< Уровень защиты

    bool enable_vm              = true;   ///< Виртуализация маркированного кода
    bool enable_mutation        = true;   ///< Мутация инструкций
    bool enable_obfuscation     = true;   ///< Обфускация (opaque predicates, MBA)
    bool enable_cfg_flattening  = true;   ///< Выравнивание потока управления
    bool enable_anti_debug      = true;   ///< Анти-отладка (inline в packer stub)
    bool enable_anti_sandbox    = true;   ///< Анти-песочница / анти-VM
    bool enable_packer          = false;  ///< Self-unpacking packer (multi-section XOR)
    bool enable_nanomites       = false;  ///< Наномиты (только maximum)
    bool enable_code_interleaving = false;///< Перемешивание кода (только maximum)
    bool strip_debug_info       = true;   ///< Удаление отладочной информации
    bool enable_header_erasure  = true;   ///< Стирание PE-заголовков в рантайме (anti-dump)
    bool debug_section_names    = false;  ///< Use fixed .mxvm/.mxprot1/.mxpack names

    StringProtectionMode string_protection = StringProtectionMode::disabled;
                                          ///< `.rdata` string transform (S2/S4, см. enum)

    uint32_t vm_nesting_depth   = 1;      ///< Глубина VM-вложенности (1 = однослойная)

    /**
     * @brief Фабричный метод: создаёт конфигурацию по уровню защиты.
     *
     * Раскладка уровней:
     *   - minimal:  только мутация (для быстрой разработки)
     *   - standard: + обфускация + CFG flattening
     *   - strong:   + VM + anti-debug + anti-sandbox + packer
     *   - maximum:  всё вышеперечисленное, VM nesting=2, nanomites, code interleaving
     */
    [[nodiscard]] static ProtectionConfig from_level(ProtectionLevel level) {
        ProtectionConfig cfg;
        cfg.level = level;

        switch (level) {
            case ProtectionLevel::minimal:
                cfg.enable_vm              = false;
                cfg.enable_mutation        = true;
                cfg.enable_obfuscation     = false;
                cfg.enable_cfg_flattening  = false;
                cfg.enable_anti_debug      = false;
                cfg.enable_anti_sandbox    = false;
                cfg.enable_packer          = false;
                cfg.enable_nanomites       = false;
                cfg.enable_code_interleaving = false;
                cfg.strip_debug_info       = true;
                cfg.string_protection      = StringProtectionMode::disabled;
                cfg.vm_nesting_depth       = 1;
                break;

            case ProtectionLevel::standard:
                cfg.enable_vm              = false;
                cfg.enable_mutation        = true;
                cfg.enable_obfuscation     = true;
                cfg.enable_cfg_flattening  = true;
                cfg.enable_anti_debug      = false;
                cfg.enable_anti_sandbox    = false;
                cfg.enable_packer          = false;
                cfg.enable_nanomites       = false;
                cfg.enable_code_interleaving = false;
                cfg.strip_debug_info       = true;
                cfg.string_protection      = StringProtectionMode::stub;
                cfg.vm_nesting_depth       = 1;
                break;

            case ProtectionLevel::strong:
                cfg.enable_vm              = true;
                cfg.enable_mutation        = true;
                cfg.enable_obfuscation     = true;
                cfg.enable_cfg_flattening  = true;
                cfg.enable_anti_debug      = true;
                cfg.enable_anti_sandbox    = true;
                cfg.enable_packer          = true;
                cfg.enable_nanomites       = false;
                cfg.enable_code_interleaving = false;
                cfg.strip_debug_info       = true;
                cfg.string_protection      = StringProtectionMode::virtualized;
                cfg.vm_nesting_depth       = 1;
                break;

            case ProtectionLevel::maximum:
                cfg.enable_vm              = true;
                cfg.enable_mutation        = true;
                cfg.enable_obfuscation     = true;
                cfg.enable_cfg_flattening  = true;
                cfg.enable_anti_debug      = true;
                cfg.enable_anti_sandbox    = true;
                cfg.enable_packer          = true;
                cfg.enable_nanomites       = true;
                cfg.enable_code_interleaving = true;
                cfg.strip_debug_info       = true;
                cfg.string_protection      = StringProtectionMode::virtualized;
                cfg.vm_nesting_depth       = 2;
                break;
        }

        return cfg;
    }

    /**
     * @brief Возвращает строковое представление уровня защиты.
     * @return Строка с названием уровня.
     */
    [[nodiscard]] std::string_view level_name() const noexcept {
        switch (level) {
            case ProtectionLevel::minimal:  return "minimal";
            case ProtectionLevel::standard: return "standard";
            case ProtectionLevel::strong:   return "strong";
            case ProtectionLevel::maximum:  return "maximum";
            default:                        return "unknown";
        }
    }
};

} // namespace mx
