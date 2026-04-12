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
 * @note Зарегистрированные проходы (Phase 2+3):
 *       MutationPass (100), ObfuscationPass (200), EncryptionPass (600).
 *       Пайплайн: парсинг → маркеры → мутация → обфускация → шифрование → сборка.
 */

#include "cli/cli_handler.hpp"

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/config/protection_config.hpp"
#include "mxprotector/pe/pe_parser.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_builder.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/marker_scanner.hpp"
#include "mxprotector/protection/pass_manager.hpp"
#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/encryption/encryption_pass.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/vm/virtualization_pass.hpp"
#include "mxprotector/protection/packer/packer_pass.hpp"

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <string>
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
    pass_manager.register_pass(std::make_unique<mx::CfgFlatteningPass>());
    pass_manager.register_pass(std::make_unique<mx::EncryptionPass>());
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

    const auto pipeline_end = std::chrono::high_resolution_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        pipeline_end - pipeline_start).count();

    print_summary(config, ctx, input_size, output_size, elapsed_ms);

    std::cout << "[+] Защита выполнена успешно!\n\n";
    return 0;
}
