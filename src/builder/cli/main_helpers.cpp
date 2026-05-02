/**
 * @file main_helpers.cpp
 * @brief Implementation of `main.cpp` helpers — see header.
 */

#include "cli/main_helpers.hpp"

#include <chrono>
#include <format>
#include <fstream>
#include <iostream>

#include "mxprotector/config/protection_config.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::cli {

MxResult<ByteBuffer> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::unexpected(error::io(
            std::format("Не удалось открыть файл: '{}'", path.string())));
    }

    const auto file_size = static_cast<std::size_t>(file.tellg());
    if (file_size == 0) {
        return std::unexpected(error::io(
            std::format("Файл пуст: '{}'", path.string())));
    }

    file.seekg(0, std::ios::beg);

    ByteBuffer buffer(file_size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()),
                   static_cast<std::streamsize>(file_size)))
    {
        return std::unexpected(error::io(
            std::format("Ошибка чтения файла: '{}'", path.string())));
    }

    return buffer;
}

MxStatus write_file(const std::filesystem::path& path, ByteView data) {
    if (const auto parent = path.parent_path(); !parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(error::io(
                std::format("Не удалось создать директорию '{}': {}",
                    parent.string(), ec.message())));
        }
    }

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return std::unexpected(error::io(
            std::format("Не удалось создать выходной файл: '{}'", path.string())));
    }

    if (!file.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size())))
    {
        return std::unexpected(error::io(
            std::format("Ошибка записи в файл: '{}'", path.string())));
    }

    return {};
}

std::string iso8601_utc_now() {
    // `std::chrono::system_clock`'s epoch is Unix UTC in C++20+,
    // and `std::format` with chrono specifiers yields UTC, so no
    // timezone conversion is required.
    const auto now = std::chrono::floor<std::chrono::seconds>(
        std::chrono::system_clock::now());
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", now);
}

std::string_view section_role_for(
    const std::string&    section_name,
    const SectionNameMap& names)
{
    if (section_name == names.vm)     return "vm";
    if (section_name == names.cff)    return "cff";
    if (section_name == names.packer) return "packer";
    if (section_name == names.str)    return "strings";
    if (section_name == names.guard)  return "guard";
    return section_name;
}

MxStatus write_trace_hints_sidecar(
    const std::filesystem::path& output_pe_path,
    std::string_view             json)
{
    auto sidecar_path = output_pe_path;
    sidecar_path += ".mxtrace.json";

    std::ofstream file(sidecar_path, std::ios::binary);
    if (!file.is_open()) {
        return std::unexpected(error::io(std::format(
            "Не удалось создать sidecar: '{}'", sidecar_path.string())));
    }

    if (!file.write(json.data(),
                    static_cast<std::streamsize>(json.size())))
    {
        return std::unexpected(error::io(std::format(
            "Ошибка записи sidecar: '{}'", sidecar_path.string())));
    }

    std::cout << std::format("[*] Trace hints: {}\n", sidecar_path.string());
    return {};
}

void print_summary(const ProtectionConfig&  config,
                   const ProtectionContext& ctx,
                   std::size_t              input_size,
                   std::size_t              output_size,
                   std::int64_t             elapsed_ms)
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

} // namespace mx::cli
