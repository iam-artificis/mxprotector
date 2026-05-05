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
#include "mxprotector/target/target_info.hpp"

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
    bool enable_indirect_calls  = false;  ///< Replace `call rel32` with stub-dispatched
                                          ///< indirect calls (B.4.20). Off by default
                                          ///< while the encoder set is curated; once
                                          ///< stable across all binaries the level
                                          ///< presets will switch it on for `strong`+.
    bool enable_mba_substitution = true;  ///< Mixed-Boolean-Arithmetic rewriting
                                          ///< (`add/sub/xor/or/and r, imm32` →
                                          ///< multi-step boolean+arithmetic body,
                                          ///< plus `mov r32, imm32` → permutation
                                          ///< polynomial). Defeats SMT solvers and
                                          ///< angr/Triton symbolic tactics.
                                          ///<
                                          ///< Safe by default — three engine-level
                                          ///< guards align: (1) the mutation
                                          ///< engine's lookahead
                                          ///< (`analysis::safe_to_clobber_flags_after`)
                                          ///< suppresses MBA when the next
                                          ///< instruction reads EFLAGS, (2)
                                          ///< `MutationEngine::set_excluded_
                                          ///< redirect_ranges` excludes
                                          ///< VM / Guard regions so their
                                          ///< lifters see original ops, and (3)
                                          ///< the sink chain plants spilled
                                          ///< bytes in a dedicated overflow
                                          ///< section so the source `.text`
                                          ///< never grows past its alignment
                                          ///< slack — RIP-relative references
                                          ///< from `.text` to `.rdata`/`.data`
                                          ///< stay valid. Disable via
                                          ///< `--no-mba-substitution` for A/B
                                          ///< measurement of the obfuscation
                                          ///< strength versus binary size.
    bool enable_packer          = false;  ///< Self-unpacking packer (multi-section XOR)
    bool enable_nanomites       = false;  ///< Наномиты (только maximum)
    bool enable_code_interleaving = false;///< Перемешивание кода (только maximum)
    bool strip_debug_info       = true;   ///< Удаление отладочной информации
    bool enable_header_erasure  = true;   ///< Стирание PE-заголовков в рантайме (anti-dump)
    bool debug_section_names    = false;  ///< Use fixed .mxvm/.mxprot1/.mxpack names

    StringProtectionMode string_protection = StringProtectionMode::disabled;
                                          ///< `.rdata` string transform (S2/S4, см. enum)

    /**
     * @brief How the protected binary will be loaded at runtime.
     *
     * `os_loaded` (default) — standard deployment: the Windows image
     * loader applies base relocations, resolves the IAT, and invokes
     * TLS callbacks before the entry point. The packer stub may assume
     * any of these.
     *
     * `manual_mapped` — a third-party mapper drops the image into
     * memory and jumps to the entry (kdmapper for drivers, manual DLL
     * injectors for DLLs). Nothing the OS loader normally does is
     * guaranteed: imports may be unresolved, relocations may not be
     * applied, TLS callbacks will not fire. The packer must be
     * self-sufficient.
     *
     * Set by `--load-mode=os|manual` on the command line. Forwarded
     * into `TargetInfo::load_mode` in `main()` so passes read it via
     * `ctx.target().is_manually_mapped()`.
     */
    target::LoadMode load_mode = target::LoadMode::os_loaded;

    uint32_t vm_nesting_depth   = 1;      ///< Глубина VM-вложенности (1 = однослойная)

    /**
     * @brief Количество RC4-раундов в packer-стабе (P2 multi-layer unpack).
     *
     * 1 — single-layer (один ключ, один KSA, один PRGA проход). Исторически
     *     соответствует всему, что было до P2.
     * 2+ — multi-layer: runtime сначала расшифровывает самый внешний слой,
     *     затем каждый следующий, последним — слой 0 (innermost, привязан
     *     к anti-debug bias). Каждый слой имеет собственный 32-байтный
     *     ключ и собственный PRGA loop внутри packer-стаба. S-box scratch
     *     делится между слоями (каждый KSA перестраивает его).
     *
     * Полезно для усложнения трассировки и статического анализа packer
     * stub'а: reverser'у приходится проходить N × (KSA+PRGA) вместо одного.
     * XOR-эквивалентность: N RC4-раундов с фиксированными ключами
     * математически сводятся к одному XOR с `⊕ks_k`, так что защита
     * от runtime-dumping'а этим не достигается; для этого нужен
     * отдельный механизм (chained keys / runtime-derived).
     */
    uint32_t packer_cipher_layers = 1;

    /**
     * @brief G3 Phase 2 — VEH-based INT3 trap (EXE-only, opt-in).
     *
     * When enabled, the packer entry stub:
     *   1. Registers a Vectored Exception Handler via a Hell's Gate
     *      resolution of `ntdll!RtlAddVectoredExceptionHandler`.
     *   2. Plants an `int3` followed by 6 bytes of per-build random
     *      junk, and relies on the VEH to advance `CONTEXT.Rip` past
     *      the whole 7-byte block at runtime.
     *
     * The junk bytes are never executed on a clean host but are still
     * reachable in the binary, so linear disassemblers decode them
     * and produce bogus instructions that confuse their control-flow
     * recovery. A debugger that swallows first-chance exceptions
     * disrupts the reverser's workflow when the int3 fires.
     *
     * The VEH's address filter is strict: it only acts on an
     * exception whose `ExceptionRecord->ExceptionAddress` matches
     * the exact runtime VA of our planted int3. Every other
     * exception — including C++ `throw` (code `0xE06D7363`) — gets
     * `EXCEPTION_CONTINUE_SEARCH` so try/catch and SEH still work
     * unchanged. A C++ exception smoke test (`test_exception.cpp`)
     * guards this property.
     *
     * **EXE-only** — a DLL-installed VEH outlives the DLL's unload
     * (there is no cleanup hook in our DllMain forwarding stub), so
     * any subsequent exception in the host process would reach a
     * freed handler body and crash the host. The packer's EXE path
     * enables this check only when `pe_type == executable` **and**
     * this flag is true; the DLL path ignores the flag entirely.
     *
     * Default: false. Set via `--anti-tamper-veh` on the command line.
     */
    bool enable_veh_anti_tamper = false;

    /**
     * @brief Feature B — `--chaos` layout mode.
     *
     * When true, `main()` swaps `ProtectionContext`'s active
     * `ILayoutPolicy` from `pe::StandardLayout` to `pe::ChaosLayout`.
     * Every emitted section's intent gets rewritten to
     * `{mixed_code_data, rwx}`, and a post-pass `finalize` sweep
     * stamps every existing section's `characteristics` with the
     * chaos bit-mask plus collapses the entire section table into
     * one unified RWX/mixed section spanning the image's RVA range.
     * RVAs of every byte stay identical, so the binary still loads
     * and runs.
     *
     * Default: false. Set via `--chaos` on the command line.
     */
    bool chaos_layout = false;

    /**
     * @brief Feature B.4 — opt-in byte-level fragment shuffle inside
     *        the unified chaos section.
     *
     * When true (and `chaos_layout` is also true), `ChaosLayout::
     * finalize` additionally cuts free RVA ranges into chunks and
     * randomly permutes their positions inside the merged section.
     * Every reference in the rebuilt reference table (code rel32 /
     * RIP-relative, `.pdata` RUNTIME_FUNCTION fields, `.reloc`-applied
     * absolute VAs, `DataDirectory` entries) is patched to point at
     * the post-shuffle target.
     *
     * Coverage caveat: deep internal directory references — IMPORT
     * descriptor `Name`/`OriginalFirstThunk`/`FirstThunk`,
     * EXPORT name table, `LOAD_CONFIG_DIRECTORY` CFG function table,
     * resource-tree internals, TLS callback array — are *not yet*
     * scanned. Enabling this flag on a binary that uses any of those
     * structures will produce a non-loadable image. Treat as a
     * test-only knob until the deep scanners land.
     *
     * Default: false. Set via `--chaos-shuffle` on the command line.
     */
    bool chaos_shuffle = false;

    /**
     * @brief Emit the `<output>.mxtrace.json` sidecar for the tracing
     *        MCP (see MCP_TRACING.md).
     *
     * When true, passes populate `ProtectionContext::trace_hints()`
     * with source-linked labels (section names, and — from Phase 4
     * onward — CFF states, VM handlers, guard regions, string slots,
     * IAT range), and `main()` writes the aggregated JSON next to the
     * output PE. Default: false.
     *
     * **Test-only flag.** Must not ship in production builds — the
     * sidecar reveals randomized section roles + future label metadata
     * that negates the per-build variance defence. CLI: `--trace-hints`.
     */
    bool emit_trace_hints = false;

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
                cfg.packer_cipher_layers   = 2;
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
                cfg.packer_cipher_layers   = 3;
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
