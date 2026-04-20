/**
 * @file mutation_pass.cpp
 * @brief [BUILDER] Реализация MutationEngine и MutationPass.
 *
 * @details MutationEngine координирует подстановку инструкций и вставку junk-кода
 *          для одного региона кода. MutationPass реализует IProtectionPass:
 *          1. Находит все MX_MUTATE_BEGIN/END регионы (или все кодовые секции).
 *          2. Создаёт MutationEngine и мутирует каждый регион.
 *          3. Сканирует NOP/INT3 padding между функциями и заполняет его
 *             junk-кодом и opaque predicates.
 *
 * @note Мутация выполняется in-place: размер региона не изменяется.
 *       Подстановки заменяют инструкции байтами той же длины.
 *       Padding (мёртвый код) заменяется на junk + opaque predicates.
 */

#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <algorithm>
#include <format>

namespace mx {

// ============================================================================
// MutationEngine — конструктор и деструктор
// ============================================================================

MutationEngine::MutationEngine(SubstitutionRuleRegistry rules,
                               std::unique_ptr<JunkGenerator> junk,
                               Randomizer& rng)
    : rules_(std::move(rules))
    , junk_gen_(std::move(junk))
    , rng_(rng)
{}

MutationEngine::~MutationEngine() = default;

// ============================================================================
// MutationEngine::mutate_region — мутация одного региона кода
// ============================================================================

MxResult<uint32_t> MutationEngine::mutate_region(
    MutableByteView code,
    Va base_address,
    analysis::IDisassembler& disasm,
    ProtectionContext& ctx)
{
    if (code.empty()) {
        ctx.log("  MutationEngine: пустой регион, пропуск");
        return uint32_t{0};
    }

    auto decode_result = disasm.decode_buffer(
        ByteView{code.data(), code.size()}, base_address);

    if (!decode_result) {
        ctx.log_fmt("  MutationEngine: ошибка декодирования по VA 0x{:016X}: {}",
            base_address, decode_result.error().message());
        return std::unexpected(decode_result.error());
    }

    const auto& instructions = *decode_result;
    if (instructions.empty()) {
        ctx.log("  MutationEngine: декодировано 0 инструкций, пропуск");
        return uint32_t{0};
    }

    uint32_t mutations_applied = 0;
    uint32_t junk_inserted = 0;

    for (const auto& insn : instructions) {
        if (insn.is_branch() || insn.is_call() || insn.is_return()) {
            continue;
        }

        auto matching_rules = rules_.find_matching(insn);
        if (matching_rules.empty()) continue;

        if (!rng_.next_bool(substitution_probability_)) continue;

        const uint32_t rule_idx = rng_.next_range(0,
            static_cast<uint32_t>(matching_rules.size() - 1));
        const auto* rule = matching_rules[rule_idx];

        auto replacement = rule->apply(insn, rng_);

        if (replacement.size() != insn.length()) {
            ctx.log_fmt("  MutationEngine: ВНИМАНИЕ: правило '{}' вернуло {} байт вместо {} для '{}' по VA 0x{:016X}",
                rule->name(), replacement.size(), insn.length(),
                insn.to_string(), insn.address());
            continue;
        }

        const auto offset = static_cast<size_t>(insn.address() - base_address);
        if (offset + replacement.size() > code.size()) {
            ctx.log_fmt("  MutationEngine: запись за пределами буфера для '{}' по VA 0x{:016X}",
                insn.to_string(), insn.address());
            continue;
        }

        std::copy(replacement.begin(), replacement.end(), code.data() + offset);
        ++mutations_applied;

        // Source-linked labels for the tracing MCP (flag-gated).
        // `insn.address()` is a VA at the base_address it was decoded
        // with, so subtracting image_base yields the RVA of the
        // substituted instruction in the final PE.
        if (ctx.config().emit_trace_hints) {
            const auto rva = static_cast<std::uint32_t>(
                insn.address() - ctx.pe_image().image_base());
            ctx.trace_hints().add_mutation_site(
                rva,
                static_cast<std::uint32_t>(insn.length()),
                static_cast<std::uint32_t>(replacement.size()),
                analysis::MutationSiteKind::substitution);
        }
    }

    total_substitutions_ += mutations_applied;
    total_junk_insertions_ += junk_inserted;

    return mutations_applied;
}

// ============================================================================
// Padding detection and filling (anonymous namespace)
// ============================================================================

namespace {

/**
 * @brief Проверяет, является ли инструкция padding-байтом (NOP или INT3).
 */
bool is_padding_instruction(const analysis::Instruction& insn) {
    return insn.mnemonic() == "nop" || insn.mnemonic() == "int3";
}

/**
 * @brief Проверяет, что padding-область — мёртвый код (безопасно для замены).
 *
 * @details Мёртвый padding определяется если:
 *          - Состоит из INT3 (линкерный padding между функциями)
 *          - Расположен сразу после RET или JMP (после возврата/перехода)
 *          - Находится в самом начале секции (pre-entry padding)
 */
bool is_dead_padding(
    const std::vector<analysis::Instruction>& insns,
    size_t run_start_idx)
{
    if (insns[run_start_idx].mnemonic() == "int3") return true;
    if (run_start_idx == 0) return true;

    const auto& prev = insns[run_start_idx - 1];
    return prev.is_return() || prev.is_unconditional_jump();
}

struct PaddingRun {
    size_t byte_offset;
    size_t byte_size;
};

/**
 * @brief Находит все мёртвые padding-области в потоке инструкций.
 */
std::vector<PaddingRun> find_dead_padding(
    const std::vector<analysis::Instruction>& instructions,
    Va base_address,
    size_t min_size = 2)
{
    std::vector<PaddingRun> runs;

    for (size_t i = 0; i < instructions.size(); ) {
        if (!is_padding_instruction(instructions[i])) {
            ++i;
            continue;
        }

        const size_t run_start = i;
        const size_t byte_offset =
            static_cast<size_t>(instructions[i].address() - base_address);
        size_t byte_size = 0;

        while (i < instructions.size() && is_padding_instruction(instructions[i])) {
            byte_size += instructions[i].length();
            ++i;
        }

        if (byte_size >= min_size && is_dead_padding(instructions, run_start)) {
            runs.push_back({byte_offset, byte_size});
        }
    }

    return runs;
}

struct PaddingFillStats {
    uint32_t regions_filled = 0;
    uint32_t predicates_inserted = 0;
    uint32_t junk_bytes = 0;
};

/**
 * @brief Заполняет мёртвые padding-области junk-кодом и opaque predicates.
 *
 * @details Для больших областей (≥14 байт) с вероятностью 50% вставляет
 *          opaque predicate (always-true) + junk в мёртвой ветви.
 *          Остальные области заполняются junk-кодом.
 */
PaddingFillStats fill_section_padding(
    MutableByteView code,
    Va base_address,
    analysis::IDisassembler& disasm,
    JunkGenerator& junk_gen,
    OpaquePredicateGenerator& pred_gen,
    Randomizer& rng)
{
    PaddingFillStats stats;

    auto decode_result = disasm.decode_buffer(
        ByteView{code.data(), code.size()}, base_address);
    if (!decode_result || decode_result->empty()) return stats;

    auto runs = find_dead_padding(*decode_result, base_address);

    for (const auto& run : runs) {
        if (run.byte_offset + run.byte_size > code.size()) continue;

        uint8_t* dst = code.data() + run.byte_offset;

        if (run.byte_size >= 14 && rng.next_bool(0.5)) {
            auto predicate = pred_gen.generate_always_true(rng, 0);

            if (!predicate.code.empty() &&
                predicate.total_size < run.byte_size &&
                (run.byte_size - predicate.total_size) <= 127)
            {
                const auto junk_size =
                    static_cast<uint8_t>(run.byte_size - predicate.total_size);

                predicate.code[predicate.true_branch_offset + 1] = junk_size;

                std::copy(predicate.code.begin(), predicate.code.end(), dst);

                auto junk = junk_gen.generate(junk_size, rng);
                std::copy(junk.begin(), junk.end(), dst + predicate.total_size);

                stats.junk_bytes += static_cast<uint32_t>(run.byte_size);
                ++stats.regions_filled;
                ++stats.predicates_inserted;
                continue;
            }
        }

        auto junk = junk_gen.generate(run.byte_size, rng);
        std::copy(junk.begin(), junk.end(), dst);
        stats.junk_bytes += static_cast<uint32_t>(run.byte_size);
        ++stats.regions_filled;
    }

    return stats;
}

} // anonymous namespace

// ============================================================================
// MutationPass::is_applicable
// ============================================================================

bool MutationPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    return ctx.config().enable_mutation;
}

// ============================================================================
// MutationPass::execute — главный метод прохода
// ============================================================================

MxStatus MutationPass::execute(ProtectionContext& ctx) {
    ctx.log("MutationPass: начало мутации маркированных регионов");

    std::vector<const MarkedRegion*> mutation_regions;
    for (const auto& marker : ctx.markers()) {
        if (marker.type == MarkerType::mutate_begin) {
            mutation_regions.push_back(&marker);
        }
    }

    Randomizer rng;
    auto rules = SubstitutionRuleRegistry::create_default();
    auto junk = std::make_unique<JunkGenerator>(ctx.pe_image().architecture());
    MutationEngine engine(std::move(rules), std::move(junk), rng);

    uint32_t total_mutations = 0;

    // ====================================================================
    // Phase 1: Instruction substitution
    // ====================================================================

    if (mutation_regions.empty()) {
        ctx.log("MutationPass: маркеров MX_MUTATE не найдено");

        bool has_code_sections = false;
        for (const auto& sec : ctx.pe_image().sections()) {
            if (sec.is_code() && sec.virtual_size > 0) {
                has_code_sections = true;
                break;
            }
        }

        if (!has_code_sections) {
            ctx.log("MutationPass: нет кодовых секций, пропуск");
            return {};
        }

        ctx.log("MutationPass: мутация всех кодовых секций (нет маркеров)");

        for (auto& sec : ctx.pe_image().sections()) {
            if (!sec.is_code() || sec.data.empty()) continue;

            const Va section_va = ctx.pe_image().image_base() + sec.virtual_address;
            MutableByteView code_view(sec.data.data(), sec.data.size());

            auto result = engine.mutate_region(
                code_view, section_va, *ctx.disassembler(), ctx);

            if (result) {
                total_mutations += *result;
            } else {
                ctx.log_fmt("MutationPass: ошибка мутации секции '{}': {}",
                    sec.name, result.error().message());
            }
        }
    } else {
        uint32_t regions_processed = 0;

        for (const auto* region : mutation_regions) {
            const Rva start_rva = region->start_rva;
            const Rva end_rva = region->end_rva;
            const uint32_t region_size = end_rva - start_rva;

            if (region_size == 0) {
                ctx.log_fmt("MutationPass: пустой регион [0x{:08X}-0x{:08X}], пропуск",
                    start_rva, end_rva);
                continue;
            }

            ctx.log_fmt("MutationPass: обработка региона [0x{:08X}-0x{:08X}] ({} байт)",
                start_rva, end_rva, region_size);

            const auto* section = ctx.pe_image().section_by_rva(start_rva);
            if (!section) {
                ctx.log_fmt("MutationPass: ОШИБКА: не найдена секция для RVA 0x{:08X}", start_rva);
                continue;
            }

            const uint32_t offset_in_section = start_rva - section->virtual_address;
            if (offset_in_section + region_size > section->data.size()) {
                ctx.log_fmt("MutationPass: ОШИБКА: регион выходит за пределы секции '{}'",
                    section->name);
                continue;
            }

            auto& mutable_sections = ctx.pe_image().sections();
            pe::SectionInfo* mutable_section = nullptr;
            for (auto& s : mutable_sections) {
                if (s.name == section->name && s.virtual_address == section->virtual_address) {
                    mutable_section = &s;
                    break;
                }
            }

            if (!mutable_section) {
                ctx.log_fmt("MutationPass: ОШИБКА: не найдена мутабельная секция '{}'",
                    section->name);
                continue;
            }

            MutableByteView code_view(
                mutable_section->data.data() + offset_in_section,
                region_size);

            const Va region_va = ctx.pe_image().image_base() + start_rva;

            auto result = engine.mutate_region(code_view, region_va, *ctx.disassembler(), ctx);

            if (result) {
                total_mutations += *result;
                ++regions_processed;
                ctx.log_fmt("  Регион: {} мутаций применено", *result);
            } else {
                ctx.log_fmt("  Регион: ошибка мутации: {}", result.error().message());
            }
        }

        ctx.log_fmt("MutationPass: маркерных регионов: {}/{}",
            regions_processed, mutation_regions.size());
    }

    // ====================================================================
    // Phase 2: Fill NOP/INT3 padding with junk + opaque predicates
    // ====================================================================

    uint32_t total_padding_filled = 0;
    uint32_t total_predicates = 0;
    uint32_t total_junk_bytes = 0;

    {
        JunkGenerator padding_gen(ctx.pe_image().architecture());
        OpaquePredicateGenerator pred_gen(ctx.pe_image().architecture());

        for (auto& sec : ctx.pe_image().sections()) {
            if (!sec.is_code() || sec.data.empty()) continue;

            const Va section_va = ctx.pe_image().image_base() + sec.virtual_address;
            MutableByteView code_view(sec.data.data(), sec.data.size());

            auto stats = fill_section_padding(
                code_view, section_va, *ctx.disassembler(),
                padding_gen, pred_gen, rng);

            total_padding_filled += stats.regions_filled;
            total_predicates += stats.predicates_inserted;
            total_junk_bytes += stats.junk_bytes;
        }
    }

    ctx.log_fmt("MutationPass: завершено. Подстановок: {}, правил: {}, "
                "padding→junk: {} ({} байт), opaque predicates: {}",
        total_mutations,
        SubstitutionRuleRegistry::create_default().rule_count(),
        total_padding_filled, total_junk_bytes, total_predicates);

    return {};
}

} // namespace mx
