/**
 * @file cli_handler.cpp
 * @brief [BUILDER] Реализация обработчика аргументов командной строки.
 *
 * @details Содержит парсинг CLI-аргументов, вывод баннера, справки и версии.
 *          Аргументы обрабатываются последовательно с поддержкой коротких
 *          (-i, -o, -l) и длинных (--input, --output, --level) форм.
 *          Флаги --no-* отключают конкретные проходы защиты.
 *
 * @note При отсутствии обязательного --input возвращается ошибка.
 *       При отсутствии --output путь генерируется автоматически.
 */

#include "cli_handler.hpp"

#include "mxprotector/pe/pe_builder.hpp"

#include <format>
#include <iostream>
#include <string>

namespace mx {

// ============================================================================
// Константы версии
// ============================================================================

static constexpr std::string_view kVersion   = "1.0.0";
static constexpr std::string_view kBuildDate = __DATE__;

// ============================================================================
// parse_args
// ============================================================================

MxResult<ProtectionConfig> CliHandler::parse_args(int argc, char** argv) {
    if (argc < 2) {
        return std::unexpected(error::config(
            "Не указаны аргументы. Используйте --help для справки."));
    }

    ProtectionConfig config = ProtectionConfig::from_level(ProtectionLevel::standard);
    bool has_input = false;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);

        if (arg == "--help" || arg == "-h") {
            print_banner();
            print_usage();
            return std::unexpected(error::config("--help"));
        }

        if (arg == "--version" || arg == "-v") {
            print_version();
            return std::unexpected(error::config("--version"));
        }

        if ((arg == "--input" || arg == "-i") && i + 1 < argc) {
            config.input_path = argv[++i];
            has_input = true;
            continue;
        }

        if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
            config.output_path = argv[++i];
            continue;
        }

        if ((arg == "--level" || arg == "-l") && i + 1 < argc) {
            auto level_result = parse_level(argv[++i]);
            if (!level_result) {
                return std::unexpected(level_result.error());
            }
            config = ProtectionConfig::from_level(*level_result);
            config.input_path.clear();
            config.output_path.clear();
            has_input = false;

            for (int j = 1; j < i; ++j) {
                const std::string_view prev_arg(argv[j]);
                if ((prev_arg == "--input" || prev_arg == "-i") && j + 1 < argc) {
                    config.input_path = argv[j + 1];
                    has_input = true;
                }
                if ((prev_arg == "--output" || prev_arg == "-o") && j + 1 < argc) {
                    config.output_path = argv[j + 1];
                }
            }
            continue;
        }

        if (arg == "--no-vm")              { config.enable_vm = false; continue; }
        if (arg == "--no-mutation")         { config.enable_mutation = false; continue; }
        if (arg == "--no-obfuscation")      { config.enable_obfuscation = false; continue; }
        if (arg == "--no-cfg-flattening")   { config.enable_cfg_flattening = false; continue; }
        if (arg == "--no-anti-debug")       { config.enable_anti_debug = false; continue; }
        if (arg == "--no-anti-sandbox")     { config.enable_anti_sandbox = false; continue; }
        if (arg == "--no-encryption")       { config.enable_encryption = false; continue; }
        if (arg == "--no-strip-debug")      { config.strip_debug_info = false; continue; }
        if (arg == "--nanomites")           { config.enable_nanomites = true; continue; }
        if (arg == "--code-interleaving")   { config.enable_code_interleaving = true; continue; }

        if (arg.starts_with("--vm-depth=") && arg.size() > 11) {
            const auto depth_str = arg.substr(11);
            uint32_t depth = 0;
            for (const auto c : depth_str) {
                if (c < '0' || c > '9') {
                    return std::unexpected(error::config(
                        std::format("Невалидное значение --vm-depth: '{}'", depth_str)));
                }
                depth = depth * 10 + static_cast<uint32_t>(c - '0');
            }
            if (depth == 0 || depth > 5) {
                return std::unexpected(error::config(
                    std::format("Глубина VM должна быть от 1 до 5, получено: {}", depth)));
            }
            config.vm_nesting_depth = depth;
            continue;
        }

        return std::unexpected(error::config(
            std::format("Неизвестный аргумент: '{}'", arg)));
    }

    if (!has_input) {
        return std::unexpected(error::config(
            "Не указан входной файл. Используйте --input <путь> или -i <путь>."));
    }

    if (config.output_path.empty()) {
        config.output_path = PeBuilder::generate_output_path(config.input_path);
    }

    return config;
}

// ============================================================================
// print_banner
// ============================================================================

void CliHandler::print_banner() {
    std::cout <<
        "\n"
        "  ╔══════════════════════════════════════════════╗\n"
        "  ║           MxProtector Builder                ║\n"
        "  ║    Windows x64 Binary Protection Suite       ║\n"
        "  ╚══════════════════════════════════════════════╝\n"
        "\n";
}

// ============================================================================
// print_usage
// ============================================================================

void CliHandler::print_usage() {
    std::cout <<
        "Использование: mxprotector_builder [опции]\n"
        "\n"
        "Обязательные:\n"
        "  -i, --input <путь>          Входной PE-файл (.exe, .dll, .sys)\n"
        "\n"
        "Опциональные:\n"
        "  -o, --output <путь>         Выходной файл (по умолчанию: file.mx.ext)\n"
        "  -l, --level <уровень>       Уровень защиты:\n"
        "                                minimal  — мутация + шифрование\n"
        "                                standard — + обфускация + CFG flattening\n"
        "                                strong   — + VM + анти-анализ\n"
        "                                maximum  — все проходы (по умолчанию: standard)\n"
        "\n"
        "Управление проходами:\n"
        "  --no-vm                     Отключить виртуализацию\n"
        "  --no-mutation               Отключить мутацию инструкций\n"
        "  --no-obfuscation            Отключить обфускацию\n"
        "  --no-cfg-flattening         Отключить CFG flattening\n"
        "  --no-anti-debug             Отключить анти-отладку\n"
        "  --no-anti-sandbox           Отключить анти-песочницу\n"
        "  --no-encryption             Отключить шифрование\n"
        "  --no-strip-debug            Не удалять отладочную информацию\n"
        "  --nanomites                 Включить наномиты\n"
        "  --code-interleaving         Включить перемешивание кода\n"
        "  --vm-depth=<N>              Глубина VM-вложенности (1-5, по умолчанию: 1)\n"
        "\n"
        "Информация:\n"
        "  -h, --help                  Показать эту справку\n"
        "  -v, --version               Показать версию\n"
        "\n";
}

// ============================================================================
// print_version
// ============================================================================

void CliHandler::print_version() {
    std::cout << std::format("MxProtector Builder v{} (сборка: {})\n", kVersion, kBuildDate);
}

// ============================================================================
// parse_level
// ============================================================================

MxResult<ProtectionLevel> CliHandler::parse_level(std::string_view level_str) {
    if (level_str == "minimal")  return ProtectionLevel::minimal;
    if (level_str == "standard") return ProtectionLevel::standard;
    if (level_str == "strong")   return ProtectionLevel::strong;
    if (level_str == "maximum")  return ProtectionLevel::maximum;

    return std::unexpected(error::config(
        std::format("Неизвестный уровень защиты: '{}'. "
                    "Допустимые: minimal, standard, strong, maximum", level_str)));
}

} // namespace mx
