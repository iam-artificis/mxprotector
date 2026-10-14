/**
 * @file cli_handler.cpp
 * @brief [BUILDER] Command-line argument handler implementation.
 *
 * @details Parses CLI arguments and prints the banner, usage, and
 *          version. Arguments are processed sequentially with both
 *          short (-i, -o, -l) and long (--input, --output, --level)
 *          forms. The --no-* flags disable individual protection
 *          passes.
 *
 * @note A missing --input returns an error. A missing --output is
 *       filled in automatically from the input path.
 */

#include "cli_handler.hpp"

#include "mxprotector/pe/pe_builder.hpp"

#include <format>
#include <iostream>
#include <string>

namespace mx {

// ============================================================================
// Version constants
// ============================================================================

static constexpr std::string_view kVersion   = "1.0.0";
static constexpr std::string_view kBuildDate = __DATE__;

// ============================================================================
// parse_args
// ============================================================================

MxResult<ProtectionConfig> CliHandler::parse_args(int argc, char** argv) {
    if (argc < 2) {
        return std::unexpected(error::config(
            "No arguments given. Use --help for usage."));
    }

    // Pass 1 — find `-l <level>`. The level seeds the per-pass
    // defaults, so it must be resolved before any flag is applied.
    // Multiple `-l` arguments: the last one wins (matches earlier
    // implicit behaviour where a later `-l` reset the config).
    ProtectionLevel level = ProtectionLevel::standard;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a(argv[i]);
        if ((a == "--level" || a == "-l") && i + 1 < argc) {
            auto r = parse_level(argv[i + 1]);
            if (!r) return std::unexpected(r.error());
            level = *r;
            ++i;
        }
    }

    ProtectionConfig config = ProtectionConfig::from_level(level);
    bool has_input = false;

    // Pass 2 — apply every flag on top of the level defaults. This
    // makes flag/level ordering irrelevant: `--chaos-shuffle -l strong`
    // and `-l strong --chaos-shuffle` produce the same config.
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
            // Already resolved in pass 1; skip the value.
            ++i;
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
        if (arg == "--indirect-calls")      { config.enable_indirect_calls = true; continue; }
        if (arg == "--no-indirect-calls")   { config.enable_indirect_calls = false; continue; }
        if (arg == "--mba-substitution")    { config.enable_mba_substitution = true; continue; }
        if (arg == "--no-mba-substitution") { config.enable_mba_substitution = false; continue; }
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
                std::format("--load-mode: expected os|manual, got '{}'",
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
                std::format("--strings: expected off|stub|vm|ephemeral, got '{}'",
                            mode_str)));
        }

        if (arg.starts_with("--vm-depth=") && arg.size() > 11) {
            const auto depth_str = arg.substr(11);
            uint32_t depth = 0;
            for (const auto c : depth_str) {
                if (c < '0' || c > '9') {
                    return std::unexpected(error::config(
                        std::format("Invalid --vm-depth value: '{}'", depth_str)));
                }
                depth = depth * 10 + static_cast<uint32_t>(c - '0');
            }
            if (depth == 0 || depth > 5) {
                return std::unexpected(error::config(
                    std::format("VM depth must be 1..5, got: {}", depth)));
            }
            config.vm_nesting_depth = depth;
            continue;
        }

        return std::unexpected(error::config(
            std::format("Unknown argument: '{}'", arg)));
    }

    if (!has_input) {
        return std::unexpected(error::config(
            "No input file. Use --input <path> or -i <path>."));
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
        "Usage: mxprotector_builder [options]\n"
        "\n"
        "Required:\n"
        "  -i, --input <path>          Input PE file (.exe, .dll, .sys)\n"
        "\n"
        "Optional:\n"
        "  -o, --output <path>         Output file (default: file.mx.ext)\n"
        "  -m, --map <path>            .map file (MSVC) for precise CFF filtering\n"
        "  -l, --level <level>         Protection level:\n"
        "                                minimal  - instruction mutation only\n"
        "                                standard - + obfuscation + CFG flattening\n"
        "                                strong   - + VM + packer + anti-debug/anti-sandbox\n"
        "                                maximum  - every pass (default: standard)\n"
        "\n"
        "Pass toggles:\n"
        "  --no-vm                     Disable virtualization\n"
        "  --no-mutation               Disable instruction mutation\n"
        "  --no-obfuscation            Disable obfuscation\n"
        "  --no-cfg-flattening         Disable CFG flattening\n"
        "  --no-anti-debug             Disable anti-debug in the packer stub\n"
        "  --no-anti-sandbox           Disable anti-sandbox\n"
        "  --packer                    Enable the self-unpacking packer\n"
        "  --no-packer                 Disable the self-unpacking packer\n"
        "  --no-strip-debug            Keep debug information\n"
        "  --nanomites                 Enable nanomites\n"
        "  --code-interleaving         Enable code interleaving\n"
        "  --no-header-erasure         Keep PE headers (anti-dump off)\n"
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
        "                                (test-only - must not ship in production builds)\n"
        "  --strings=<mode>            .rdata string protection:\n"
        "                                off       - leave strings plaintext\n"
        "                                stub      - decryptor emitted as plain x64 asm\n"
        "                                vm        - decryptor lifted into VM bytecode\n"
        "                                ephemeral - S3 scratch-ring, no sticky cache\n"
        "                                (auto-fallback vm->stub when --no-vm is set)\n"
        "  --vm-depth=<N>              VM nesting depth (1-5, default: 1)\n"
        "  --load-mode=<mode>          How the protected binary is loaded:\n"
        "                                os     - standard OS loader (default)\n"
        "                                manual - manual-map (kdmapper / DLL injector)\n"
        "\n"
        "Info:\n"
        "  -h, --help                  Show this help\n"
        "  -v, --version               Show version\n"
        "\n";
}

// ============================================================================
// print_version
// ============================================================================

void CliHandler::print_version() {
    std::cout << std::format("MxProtector Builder v{} (build: {})\n", kVersion, kBuildDate);
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
        std::format("Unknown protection level: '{}'. "
                    "Allowed: minimal, standard, strong, maximum", level_str)));
}

} // namespace mx
