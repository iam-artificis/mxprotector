/**
 * @file main.cpp
 * @brief [BUILDER] Точка входа MxProtector Builder.
 *
 * @details Основной пайплайн:
 *          1. Парсинг аргументов CLI → ProtectionConfig
 *          2. Чтение входного PE-файла → ByteBuffer
 *          3. PeParser::parse() → PeImage
 *          4. Создание ProtectionContext (PeImage + конфиг + дизассемблер)
 *          5. MarkerScanner::find_markers() → маркированные регионы
 *          6. PassManager::execute_all() — выполнение зарегистрированных проходов
 *          7. PeBuilder::build() → ByteBuffer
 *          8. Запись выходного файла с именем .mx.ext
 *          9. Вывод итоговой сводки
 *
 * @note Пайплайн: MutationPass (100) → ObfuscationPass (200) →
 *       VirtualizationPass (300) → CfgFlatteningPass (400) →
 *       PackerPass (800).
 */

#include "cli/cli_handler.hpp"
#include "cli/section_name_pool.hpp"

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/config/protection_config.hpp"
#include "mxprotector/pe/pe_parser.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_builder.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/marker_scanner.hpp"
#include "mxprotector/analysis/trace_hints.hpp"
#include "mxprotector/target/target_info.hpp"
#include "mxprotector/arch/arch_info.hpp"       // Phase 1 arch foundation (unused yet)
#include "mxprotector/arch/code_emitter.hpp"    // Phase 1 arch foundation (unused yet)
#include "mxprotector/arch/vm_backend.hpp"      // Phase 1 arch foundation (unused yet)
#include "mxprotector/protection/pass_manager.hpp"
#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/vm/virtualization_pass.hpp"
#include "mxprotector/protection/guard/guard_pass.hpp"
#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/protection/string/string_protection_pass.hpp"

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

/**
 * @brief Читает файл целиком в ByteBuffer.
 * @param path Путь к файлу.
 * @return ByteBuffer с содержимым файла или ошибка.
 */
[[nodiscard]] mx::MxResult<mx::ByteBuffer> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::unexpected(mx::error::io(
            std::format("Не удалось открыть файл: '{}'", path.string())));
    }

    const auto file_size = static_cast<size_t>(file.tellg());
    if (file_size == 0) {
        return std::unexpected(mx::error::io(
            std::format("Файл пуст: '{}'", path.string())));
    }

    file.seekg(0, std::ios::beg);

    mx::ByteBuffer buffer(file_size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()),
                   static_cast<std::streamsize>(file_size)))
    {
        return std::unexpected(mx::error::io(
            std::format("Ошибка чтения файла: '{}'", path.string())));
    }

    return buffer;
}

/**
 * @brief Записывает ByteBuffer в файл.
 * @param path Путь к выходному файлу.
 * @param data Данные для записи.
 * @return Успех или ошибка.
 */
[[nodiscard]] mx::MxStatus write_file(const std::filesystem::path& path, mx::ByteView data) {
    if (const auto parent = path.parent_path(); !parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(mx::error::io(
                std::format("Не удалось создать директорию '{}': {}",
                    parent.string(), ec.message())));
        }
    }

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return std::unexpected(mx::error::io(
            std::format("Не удалось создать выходной файл: '{}'", path.string())));
    }

    if (!file.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size())))
    {
        return std::unexpected(mx::error::io(
            std::format("Ошибка записи в файл: '{}'", path.string())));
    }

    return {};
}

/**
 * @brief Формирует ISO-8601 UTC timestamp текущего момента.
 *
 * @return Строка формата `YYYY-MM-DDThh:mm:ssZ`.
 *
 * @note `std::chrono::system_clock`'s epoch is Unix UTC in C++20+,
 *       and std::format with chrono specifiers yields UTC, so no
 *       timezone conversion is required.
 */
[[nodiscard]] std::string iso8601_utc_now() {
    const auto now = std::chrono::floor<std::chrono::seconds>(
        std::chrono::system_clock::now());
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", now);
}

/**
 * @brief Сопоставляет имя секции с её логической ролью.
 *
 * @details Роль — это стабильный идентификатор, который MCP-
 *          трассировщик использует вместо рандомизированного
 *          per-build имени секции. Для секций, добавленных
 *          MxProtector, роль берётся из `SectionNameMap`; для
 *          исходных секций роль равна самому имени.
 */
[[nodiscard]] std::string_view section_role_for(
    const std::string& section_name,
    const mx::SectionNameMap& names)
{
    if (section_name == names.vm)     return "vm";
    if (section_name == names.cff)    return "cff";
    if (section_name == names.packer) return "packer";
    if (section_name == names.str)    return "strings";
    if (section_name == names.guard)  return "guard";
    return section_name;
}

/**
 * @brief Записывает sidecar `<output>.mxtrace.json` рядом с защищённым PE.
 *
 * @param output_pe_path Путь к защищённому PE.
 * @param json           Содержимое sidecar (TraceHints::to_json()).
 * @return Успех или ошибка I/O.
 */
[[nodiscard]] mx::MxStatus write_trace_hints_sidecar(
    const std::filesystem::path& output_pe_path,
    std::string_view json)
{
    auto sidecar_path = output_pe_path;
    sidecar_path += ".mxtrace.json";

    std::ofstream file(sidecar_path, std::ios::binary);
    if (!file.is_open()) {
        return std::unexpected(mx::error::io(std::format(
            "Не удалось создать sidecar: '{}'", sidecar_path.string())));
    }

    if (!file.write(json.data(), static_cast<std::streamsize>(json.size()))) {
        return std::unexpected(mx::error::io(std::format(
            "Ошибка записи sidecar: '{}'", sidecar_path.string())));
    }

    std::cout << std::format("[*] Trace hints: {}\n", sidecar_path.string());
    return {};
}

/**
 * @brief Выводит итоговую сводку защиты.
 * @param config Конфигурация.
 * @param ctx Контекст пайплайна.
 * @param input_size Размер входного файла.
 * @param output_size Размер выходного файла.
 * @param elapsed_ms Время выполнения в миллисекундах.
 */
void print_summary(
    const mx::ProtectionConfig& config,
    const mx::ProtectionContext& ctx,
    size_t input_size,
    size_t output_size,
    int64_t elapsed_ms)
{
    std::cout << "\n";
    std::cout << "═══════════════════════════════════════════════\n";
    std::cout << "  Итоги защиты\n";
    std::cout << "═══════════════════════════════════════════════\n";
    std::cout << std::format("  Входной файл:   {}\n", config.input_path.string());
    std::cout << std::format("  Выходной файл:  {}\n", config.output_path.string());
    std::cout << std::format("  Уровень:        {}\n", config.level_name());
    std::cout << std::format("  Архитектура:    {}\n",
        ctx.pe_image().is_64bit() ? "x64 (PE32+)" : "x86 (PE32)");
    std::cout << std::format("  Маркеров:       {}\n", ctx.markers().size());
    std::cout << std::format("  Размер (вход):  {} байт\n", input_size);
    std::cout << std::format("  Размер (выход): {} байт\n", output_size);
    std::cout << std::format("  Время:          {} мс\n", elapsed_ms);
    std::cout << "═══════════════════════════════════════════════\n";

    if (!ctx.log_messages().empty()) {
        std::cout << "\n  Журнал:\n";
        for (const auto& msg : ctx.log_messages()) {
            std::cout << "    " << msg << "\n";
        }
    }

    std::cout << "\n";
}

} // anonymous namespace

// ============================================================================
// main
// ============================================================================

int main(int argc, char** argv) {
    mx::CliHandler::print_banner();

    auto config_result = mx::CliHandler::parse_args(argc, argv);
    if (!config_result) {
        const auto& err = config_result.error();
        if (err.message() == "--help" || err.message() == "--version") {
            return 0;
        }
        std::cerr << std::format("[ОШИБКА] {}\n", err.message());
        return 1;
    }

    auto config = std::move(*config_result);

    // Auto-fallback: virtualized string protection requires the VM backend.
    // If the user disabled VM explicitly (or the level preset has it off)
    // the virtualized decryptor has nothing to lift into, so we drop to
    // stub mode and tell the user why.
    if (config.string_protection == mx::StringProtectionMode::virtualized &&
        !config.enable_vm)
    {
        std::cout <<
            "[!] --strings=vm требует включённый VM, но VM отключён — "
            "откат на --strings=stub\n";
        config.string_protection = mx::StringProtectionMode::stub;
    }

    const auto pipeline_start = std::chrono::high_resolution_clock::now();

    std::cout << std::format("[*] Чтение файла: {}\n", config.input_path.string());
    auto file_data = read_file(config.input_path);
    if (!file_data) {
        std::cerr << std::format("[ОШИБКА] {}\n", file_data.error().message());
        return 1;
    }

    const size_t input_size = file_data->size();
    std::cout << std::format("[*] Размер файла: {} байт\n", input_size);

    std::cout << "[*] Парсинг PE-файла...\n";
    auto pe_result = mx::PeParser::parse(
        mx::ByteView{file_data->data(), file_data->size()});
    if (!pe_result) {
        std::cerr << std::format("[ОШИБКА] Парсинг PE: {}\n", pe_result.error().format());
        return 1;
    }

    auto pe_image = std::make_unique<mx::PeImage>(std::move(*pe_result));
    std::cout << std::format("[*] PE: {} ({}), {} секций, entry_point=0x{:08X}\n",
        pe_image->is_64bit() ? "PE32+" : "PE32",
        pe_image->pe_type() == mx::PeType::executable ? "EXE" :
        pe_image->pe_type() == mx::PeType::dynamic_library ? "DLL" : "SYS",
        pe_image->sections().size(),
        pe_image->entry_point_rva());

    auto disasm = std::make_shared<mx::analysis::ZydisDisassembler>(pe_image->architecture());

    auto ctx = mx::ProtectionContext(std::move(pe_image), config, disasm);

    // Record the target platform. Today the pipeline is PE-only so we know
    // it's Windows PE; the architecture comes from the parsed image. When
    // ELF / Mach-O parsers are added, this is the one place that changes.
    {
        const auto& img = ctx.pe_image();
        const auto kind = [&] {
            switch (img.pe_type()) {
                case mx::PeType::executable:      return mx::target::BinaryKind::executable;
                case mx::PeType::dynamic_library: return mx::target::BinaryKind::dynamic_library;
                case mx::PeType::kernel_driver:   return mx::target::BinaryKind::kernel_driver;
                case mx::PeType::efi_application: return mx::target::BinaryKind::efi_application;
            }
            return mx::target::BinaryKind::unknown;
        }();
        mx::target::TargetInfo info{
            .os        = mx::target::Os::windows,
            .container = mx::target::ContainerFormat::pe,
            .arch      = img.is_64bit() ? mx::target::Arch::x64
                                         : mx::target::Arch::x86,
            .kind      = kind,
            .load_mode = config.load_mode,
        };
        ctx.set_target(info);
        std::cout << std::format("[*] Target: {}/{}/{} kind={} load={}\n",
            mx::target::os_name(info.os),
            mx::target::container_name(info.container),
            mx::target::arch_name(info.arch),
            mx::target::binary_kind_name(info.kind),
            mx::target::load_mode_name(info.load_mode));
    }

    // Pick per-build section names. The pool is target-kind aware
    // so a kernel driver gets kernel-flavoured names
    // (`PAGEBGFX`, `PAGEKD`, ...) instead of user-mode MSVC idioms
    // (`.rdata2`, `.CRT$XC`, ...) — the latter would stand out in a
    // kernel debugger's module list. See `cli/section_name_pool.hpp`.
    {
        mx::Randomizer name_rng;
        auto names = mx::pick_section_names(
            ctx.target().kind,
            ctx.config().debug_section_names,
            name_rng);
        std::cout << std::format(
            "[*] Секции: vm='{}' cff='{}' pack='{}' "
            "str='{}' guard='{}'\n",
            names.vm, names.cff, names.packer, names.str, names.guard);
        ctx.set_section_names(std::move(names));
    }

    std::cout << "[*] Сканирование SDK-маркеров...\n";
    auto markers_result = mx::analysis::MarkerScanner::find_markers(ctx.pe_image());
    if (!markers_result) {
        std::cerr << std::format("[ОШИБКА] Маркеры: {}\n", markers_result.error().format());
        return 1;
    }

    ctx.set_markers(std::move(*markers_result));
    std::cout << std::format("[*] Найдено маркированных регионов: {}\n", ctx.markers().size());

    for (const auto& region : ctx.markers()) {
        const char* type_name = "???";
        switch (region.type) {
            case mx::MarkerType::vm_begin:        type_name = "VM"; break;
            case mx::MarkerType::mutate_begin:    type_name = "MUTATE"; break;
            case mx::MarkerType::obfuscate_begin: type_name = "OBFUSCATE"; break;
            case mx::MarkerType::guard_begin:     type_name = "GUARD"; break;
            default: break;
        }
        std::cout << std::format("    {} : RVA [0x{:08X} - 0x{:08X}] ({} байт)\n",
            type_name, region.start_rva, region.end_rva,
            region.end_rva - region.start_rva);
    }

    std::cout << std::format("[*] Запуск пайплайна защиты (уровень: {})...\n",
        config.level_name());

    mx::PassManager pass_manager;
    pass_manager.register_pass(std::make_unique<mx::MutationPass>());
    pass_manager.register_pass(std::make_unique<mx::ObfuscationPass>());
    pass_manager.register_pass(std::make_unique<mx::VirtualizationPass>());
    pass_manager.register_pass(std::make_unique<mx::GuardPass>());
    pass_manager.register_pass(std::make_unique<mx::CfgFlatteningPass>());
    pass_manager.register_pass(std::make_unique<mx::StringProtectionPass>());
    pass_manager.register_pass(std::make_unique<mx::PackerPass>());

    auto pass_result = pass_manager.execute_all(ctx);
    if (!pass_result) {
        std::cerr << std::format("[ОШИБКА] Пайплайн: {}\n", pass_result.error().format());
        return 1;
    }

    std::cout << "[*] Сборка выходного PE-файла...\n";
    auto build_result = mx::PeBuilder::build(ctx.pe_image());
    if (!build_result) {
        std::cerr << std::format("[ОШИБКА] Сборка PE: {}\n", build_result.error().format());
        return 1;
    }

    const size_t output_size = build_result->size();

    std::cout << std::format("[*] Запись: {}\n", config.output_path.string());
    auto write_result = write_file(config.output_path,
        mx::ByteView{build_result->data(), build_result->size()});
    if (!write_result) {
        std::cerr << std::format("[ОШИБКА] {}\n", write_result.error().message());
        return 1;
    }

    // Optional: emit the source-linked labels sidecar for the tracing
    // MCP. Flag-gated so production builds never produce it. See
    // MCP_TRACING.md and `include/mxprotector/analysis/trace_hints.hpp`.
    if (config.emit_trace_hints) {
        auto& hints = ctx.trace_hints();
        hints.set_build_info(
            config.input_path.string(),
            config.output_path.string(),
            std::string(config.level_name()),
            iso8601_utc_now());

        const auto& names = ctx.section_names();
        for (const auto& sec : ctx.pe_image().sections()) {
            hints.add_section(
                section_role_for(sec.name, names),
                sec.name,
                sec.virtual_address,
                sec.virtual_size,
                sec.characteristics);
        }

        // IAT range — from DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].
        // Many MSVC-built binaries populate this summary directory;
        // when it's 0/0 we leave the label as the schema default
        // (already zero after set_iat is not called).
        std::visit([&](const auto& nt) {
            const auto& dir = nt.OptionalHeader.DataDirectory[
                mx::pe::IMAGE_DIRECTORY_ENTRY_IAT];
            if (dir.VirtualAddress != 0 || dir.Size != 0) {
                hints.set_iat(dir.VirtualAddress, dir.Size);
            }
        }, ctx.pe_image().nt_headers());

        if (auto sidecar_result = write_trace_hints_sidecar(
                config.output_path, hints.to_json());
            !sidecar_result)
        {
            std::cerr << std::format("[ОШИБКА] {}\n",
                sidecar_result.error().message());
            return 1;
        }
    }

    const auto pipeline_end = std::chrono::high_resolution_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        pipeline_end - pipeline_start).count();

    print_summary(config, ctx, input_size, output_size, elapsed_ms);

    std::cout << "[+] Защита выполнена успешно!\n\n";
    return 0;
}
