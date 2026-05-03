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
 * @note Малые помощники (read_file/write_file/iso8601/print_summary/
 *       trace-hints sidecar) вынесены в `cli/main_helpers.{hpp,cpp}`
 *       (R5.1) — этот файл оркестратор пайплайна.
 */

#include "cli/cli_handler.hpp"
#include "cli/main_helpers.hpp"
#include "cli/section_name_pool.hpp"

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/marker_scanner.hpp"
#include "mxprotector/analysis/trace_hints.hpp"
#include "mxprotector/config/protection_config.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/layout/chaos_layout.hpp"
#include "mxprotector/pe/pe_builder.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_parser.hpp"
#include "mxprotector/protection/anti_static/indirect_call_encoder_pass.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/guard/guard_pass.hpp"
#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/protection/pass_manager.hpp"
#include "mxprotector/protection/string/string_protection_pass.hpp"
#include "mxprotector/protection/vm/virtualization_pass.hpp"
#include "mxprotector/target/target_info.hpp"

#include <chrono>
#include <format>
#include <iostream>
#include <variant>

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

    // Auto-fallback: virtualized string protection requires the VM
    // backend. If the user disabled VM explicitly (or the level
    // preset has it off) the virtualized decryptor has nothing to
    // lift into, so we drop to stub mode and tell the user why.
    if (config.string_protection == mx::StringProtectionMode::virtualized &&
        !config.enable_vm)
    {
        std::cout <<
            "[!] --strings=vm требует включённый VM, но VM отключён — "
            "откат на --strings=stub\n";
        config.string_protection = mx::StringProtectionMode::stub;
    }

    // Auto-disable: --chaos-shuffle and the self-unpacking packer are
    // structurally incompatible. The packer encrypts whole sections
    // and re-applies relocations on unpack; the chaos shuffle's
    // unified RWX section + post-shuffle reloc rebuild contradict
    // both assumptions. Run-time symptoms range from "fails to
    // unpack" to silent slot corruption. The user is explicitly
    // expected to favour shuffle over packer when both are
    // requested (B.4.10.5).
    if (config.chaos_shuffle && config.enable_packer) {
        std::cout <<
            "[!] --chaos-shuffle несовместим с self-unpacking packer — "
            "packer отключён\n";
        config.enable_packer = false;
    }

    const auto pipeline_start = std::chrono::high_resolution_clock::now();

    std::cout << std::format("[*] Чтение файла: {}\n", config.input_path.string());
    auto file_data = mx::cli::read_file(config.input_path);
    if (!file_data) {
        std::cerr << std::format("[ОШИБКА] {}\n", file_data.error().message());
        return 1;
    }

    const std::size_t input_size = file_data->size();
    std::cout << std::format("[*] Размер файла: {} байт\n", input_size);

    std::cout << "[*] Парсинг PE-файла...\n";
    auto pe_result = mx::PeParser::parse(
        mx::ByteView{file_data->data(), file_data->size()});
    if (!pe_result) {
        std::cerr << std::format("[ОШИБКА] Парсинг PE: {}\n",
            pe_result.error().format());
        return 1;
    }

    auto pe_image = std::make_unique<mx::PeImage>(std::move(*pe_result));
    std::cout << std::format("[*] PE: {} ({}), {} секций, entry_point=0x{:08X}\n",
        pe_image->is_64bit() ? "PE32+" : "PE32",
        pe_image->pe_type() == mx::PeType::executable      ? "EXE" :
        pe_image->pe_type() == mx::PeType::dynamic_library ? "DLL" :
        pe_image->pe_type() == mx::PeType::kernel_driver   ? "SYS" : "EFI",
        pe_image->sections().size(),
        pe_image->entry_point_rva());

    auto disasm = std::make_shared<mx::analysis::ZydisDisassembler>(
        pe_image->architecture());

    auto ctx = mx::ProtectionContext(std::move(pe_image), config, disasm);

    // Feature B — swap the layout policy to `ChaosLayout` when
    // `--chaos` was set. Default is `StandardLayout`, installed by
    // the `ProtectionContext` constructor; the swap must happen
    // before any pass executes so every emission seam sees the
    // overridden intent.
    if (config.chaos_layout) {
        ctx.set_layout_policy(std::make_unique<mx::pe::ChaosLayout>(
            /*enable_fragment_shuffle=*/config.chaos_shuffle));
        std::cout << std::format(
            "[*] Layout policy: chaos (RWX / mixed code+data{})\n",
            config.chaos_shuffle ? " + fragment shuffle" : "");
    }

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
        const mx::target::TargetInfo info{
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

    {
        mx::Randomizer name_rng;
        auto names = mx::pick_section_names(
            ctx.target().kind,
            ctx.config().debug_section_names,
            name_rng);
        std::cout << std::format(
            "[*] Секции: vm='{}' cff='{}' pack='{}' "
            "str='{}' guard='{}' mut='{}'\n",
            names.vm, names.cff, names.packer,
            names.str, names.guard, names.mut);
        ctx.set_section_names(std::move(names));
    }

    std::cout << "[*] Сканирование SDK-маркеров...\n";
    auto markers_result = mx::analysis::MarkerScanner::find_markers(
        ctx.pe_image());
    if (!markers_result) {
        std::cerr << std::format("[ОШИБКА] Маркеры: {}\n",
            markers_result.error().format());
        return 1;
    }

    ctx.set_markers(std::move(*markers_result));
    std::cout << std::format("[*] Найдено маркированных регионов: {}\n",
        ctx.markers().size());

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
    pass_manager.register_pass(
        std::make_unique<mx::protection::anti_static::IndirectCallEncoderPass>());
    pass_manager.register_pass(std::make_unique<mx::VirtualizationPass>());
    pass_manager.register_pass(std::make_unique<mx::GuardPass>());
    pass_manager.register_pass(std::make_unique<mx::CfgFlatteningPass>());
    pass_manager.register_pass(std::make_unique<mx::StringProtectionPass>());
    pass_manager.register_pass(std::make_unique<mx::PackerPass>());

    auto pass_result = pass_manager.execute_all(ctx);
    if (!pass_result) {
        std::cerr << std::format("[ОШИБКА] Пайплайн: {}\n",
            pass_result.error().format());
        return 1;
    }

    std::cout << "[*] Сборка выходного PE-файла...\n";
    auto build_result = mx::PeBuilder::build(
        ctx.pe_image(), ctx.layout_policy());
    if (!build_result) {
        std::cerr << std::format("[ОШИБКА] Сборка PE: {}\n",
            build_result.error().format());
        return 1;
    }

    const std::size_t output_size = build_result->size();

    std::cout << std::format("[*] Запись: {}\n", config.output_path.string());
    auto write_result = mx::cli::write_file(
        config.output_path,
        mx::ByteView{build_result->data(), build_result->size()});
    if (!write_result) {
        std::cerr << std::format("[ОШИБКА] {}\n",
            write_result.error().message());
        return 1;
    }

    if (config.emit_trace_hints) {
        auto& hints = ctx.trace_hints();
        hints.set_build_info(
            config.input_path.string(),
            config.output_path.string(),
            std::string(config.level_name()),
            mx::cli::iso8601_utc_now());

        const auto& names = ctx.section_names();
        for (const auto& sec : ctx.pe_image().sections()) {
            hints.add_section(
                mx::cli::section_role_for(sec.name, names),
                sec.name,
                sec.virtual_address,
                sec.virtual_size,
                sec.characteristics);
        }

        std::visit([&](const auto& nt) {
            const auto& dir = nt.OptionalHeader.DataDirectory[
                mx::pe::IMAGE_DIRECTORY_ENTRY_IAT];
            if (dir.VirtualAddress != 0 || dir.Size != 0) {
                hints.set_iat(dir.VirtualAddress, dir.Size);
            }
        }, ctx.pe_image().nt_headers());

        if (auto sidecar_result = mx::cli::write_trace_hints_sidecar(
                config.output_path, hints.to_json());
            !sidecar_result)
        {
            std::cerr << std::format("[ОШИБКА] {}\n",
                sidecar_result.error().message());
            return 1;
        }
    }

    const auto pipeline_end = std::chrono::high_resolution_clock::now();
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            pipeline_end - pipeline_start).count();

    mx::cli::print_summary(
        config, ctx, input_size, output_size, elapsed_ms);

    std::cout << "[+] Защита выполнена успешно!\n\n";
    return 0;
}
