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
