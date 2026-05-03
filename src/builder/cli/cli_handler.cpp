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

        if ((arg == "--map" || arg == "-m") && i + 1 < argc) {
            config.map_file_path = argv[++i];
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
                if ((prev_arg == "--map" || prev_arg == "-m") && j + 1 < argc) {
                    config.map_file_path = argv[j + 1];
                }
            }
            continue;
        }

        if (arg == "--no-vm")               { config.enable_vm = false; continue; }
        if (arg == "--no-mutation")         { config.enable_mutation = false; continue; }
        if (arg == "--no-obfuscation")      { config.enable_obfuscation = false; continue; }
        if (arg == "--no-cfg-flattening")   { config.enable_cfg_flattening = false; continue; }
        if (arg == "--no-anti-debug")       { config.enable_anti_debug = false; continue; }
        if (arg == "--no-anti-sandbox")     { config.enable_anti_sandbox = false; continue; }
        if (arg == "--packer")              { config.enable_packer = true; continue; }
        if (arg == "--no-packer")           { config.enable_packer = false; continue; }
        if (arg == "--no-strip-debug")      { config.strip_debug_info = false; continue; }
        if (arg == "--nanomites")           { config.enable_nanomites = true; continue; }
        if (arg == "--code-interleaving")   { config.enable_code_interleaving = true; continue; }
        if (arg == "--no-header-erasure")   { config.enable_header_erasure = false; continue; }
        if (arg == "--debug-sections")      { config.debug_section_names = true; continue; }
        if (arg == "--anti-tamper-veh")     { config.enable_veh_anti_tamper = true; continue; }
        if (arg == "--chaos")               { config.chaos_layout = true; continue; }
        if (arg == "--chaos-shuffle")       { config.chaos_layout = true; config.chaos_shuffle = true; continue; }
        if (arg == "--trace-hints")         { config.emit_trace_hints = true; continue; }

        if (arg.starts_with("--load-mode=") && arg.size() > 12) {
            const auto mode_str = arg.substr(12);
            if (mode_str == "os") {
                config.load_mode = target::LoadMode::os_loaded;
                continue;
            }
            if (mode_str == "manual") {
                config.load_mode = target::LoadMode::manual_mapped;
                continue;
            }
            return std::unexpected(error::config(
                std::format("--load-mode: ожидается os|manual, получено '{}'",
                            mode_str)));
        }

        if (arg.starts_with("--strings=") && arg.size() > 10) {
            const auto mode_str = arg.substr(10);
            if (mode_str == "off" || mode_str == "disabled") {
                config.string_protection = StringProtectionMode::disabled;
                continue;
            }
            if (mode_str == "stub" || mode_str == "plain") {
                config.string_protection = StringProtectionMode::stub;
                continue;
            }
            if (mode_str == "vm" || mode_str == "virtualized") {
                config.string_protection = StringProtectionMode::virtualized;
                continue;
            }
            if (mode_str == "ephemeral" || mode_str == "eph") {
                config.string_protection = StringProtectionMode::ephemeral;
                continue;
            }
            return std::unexpected(error::config(
                std::format("--strings: ожидается off|stub|vm|ephemeral, получено '{}'",
                            mode_str)));
        }

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
        "  -m, --map <путь>            .map файл (MSVC) для точной фильтрации CFF\n"
        "  -l, --level <уровень>       Уровень защиты:\n"
        "                                minimal  — только мутация инструкций\n"
        "                                standard — + обфускация + CFG flattening\n"
        "                                strong   — + VM + packer + anti-debug/anti-sandbox\n"
        "                                maximum  — все проходы (по умолчанию: standard)\n"
        "\n"
        "Управление проходами:\n"
        "  --no-vm                     Отключить виртуализацию\n"
        "  --no-mutation               Отключить мутацию инструкций\n"
        "  --no-obfuscation            Отключить обфускацию\n"
        "  --no-cfg-flattening         Отключить CFG flattening\n"
        "  --no-anti-debug             Отключить анти-отладку в packer stub\n"
        "  --no-anti-sandbox           Отключить анти-песочницу\n"
        "  --packer                    Включить self-unpacking packer\n"
        "  --no-packer                 Отключить self-unpacking packer\n"
        "  --no-strip-debug            Не удалять отладочную информацию\n"
        "  --nanomites                 Включить наномиты\n"
        "  --code-interleaving         Включить перемешивание кода\n"
        "  --no-header-erasure         Не стирать PE-заголовки (anti-dump)\n"
        "  --debug-sections            Use fixed section names (.mxvm/.mxprot1/.mxpack)\n"
        "  --anti-tamper-veh           Install VEH INT3 trap in packer stub (EXE-only, G3 Phase 2)\n"
        "  --chaos                     Force every section to RWX / mixed code+data (Feature B)\n"
        "                                 + collapse the section table into one unified section.\n"
        "  --chaos-shuffle             --chaos + atomic-cluster shuffle inside the unified\n"
        "                                 section (B.4.10): instructions are grouped into\n"
        "                                 4-15-insn movable clusters, data is carved into\n"
        "                                 50-100 B chunks, every PE-format structure stays\n"
        "                                 pinned. Auto-disables --packer (incompatible).\n"
        "  --trace-hints               Emit <output>.mxtrace.json sidecar for the tracing MCP\n"
        "                                (test-only — must not ship in production builds)\n"
        "  --strings=<режим>           Защита строк в .rdata:\n"
        "                                off       — оставить plaintext\n"
        "                                stub      — decryptor как обычный x64 asm\n"
        "                                vm        — decryptor лифтится в VM bytecode\n"
        "                                ephemeral — S3 scratch-ring, no sticky cache\n"
        "                                (auto-fallback vm→stub при --no-vm)\n"
        "  --vm-depth=<N>              Глубина VM-вложенности (1-5, по умолчанию: 1)\n"
        "  --load-mode=<режим>         Как загружается защищённый бинарь:\n"
        "                                os     — стандартный OS-loader (по умолчанию)\n"
        "                                manual — manual-map (kdmapper / DLL-инжектор)\n"
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
