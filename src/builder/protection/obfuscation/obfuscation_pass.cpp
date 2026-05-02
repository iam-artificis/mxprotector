/**
 * @file obfuscation_pass.cpp
 * @brief [BUILDER] Реализация прохода обфускации (ObfuscationPass).
 *
 * @details Координирует применение opaque predicates и constant unfolding
 *          к регионам, помеченным MX_OBFUSCATE_BEGIN/END. Для каждого региона:
 *          1. Дизассемблирует код.
 *          2. Для инструкций MOV reg, imm — применяет constant unfolding.
 *          3. Генерирует opaque predicates (метаданные для Phase 5 CFG transforms).
 *          4. Записывает модифицированные байты обратно в PE-образ.
 *
 * @note Constant unfolding увеличивает размер кода (2 инструкции вместо 1).
 *       В Phase 2 развёртка применяется только если после инструкции есть
 *       достаточно NOP/padding для размещения дополнительных байтов.
 *       Opaque predicates в Phase 2 подготавливаются, но не инжектируются
 *       (требуют расширения секции или code cave — Phase 5).
 */

#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/obfuscation/constant_unfolding.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <algorithm>
#include <format>

namespace mx {

// ============================================================================
// ObfuscationPass::is_applicable
// ============================================================================

bool ObfuscationPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    if (!ctx.config().enable_obfuscation)  return false;
    // Opaque predicates, MBA transforms and constant unfolding emit
    // x86/x64 instruction sequences. Same target rationale as
    // MutationPass: gate on `is_windows_pe_x64()` so non-PE / non-x64
    // inputs do not engage the rewriter. EXE / DLL / SYS / EFI all
    // work — the transforms are pure byte-level and have no runtime
    // infra dependency.
    if (!ctx.target().is_windows_pe_x64()) return false;
    return true;
}

// ============================================================================
// ObfuscationPass::execute
// ============================================================================

MxStatus ObfuscationPass::execute(ProtectionContext& ctx) {
    ctx.log("ObfuscationPass: начало обфускации маркированных регионов");

    std::vector<const MarkedRegion*> obfuscation_regions;
    for (const auto& marker : ctx.markers()) {
        if (marker.type == MarkerType::obfuscate_begin) {
            obfuscation_regions.push_back(&marker);
        }
    }

    if (obfuscation_regions.empty()) {
        ctx.log("ObfuscationPass: маркеров MX_OBFUSCATE не найдено, применение к кодовым секциям");

        bool has_code = false;
        for (const auto& sec : ctx.pe_image().sections()) {
            if (sec.is_code() && sec.virtual_size > 0) {
                has_code = true;
                break;
            }
        }

        if (!has_code) {
            ctx.log("ObfuscationPass: нет кодовых секций, пропуск");
            return {};
        }
    }

    Randomizer rng;
    ConstantUnfolder unfolder(ctx.pe_image().architecture());
    OpaquePredicateGenerator pred_gen(ctx.pe_image().architecture());

    uint32_t constants_unfolded = 0;
    uint32_t predicates_generated = 0;
    uint32_t regions_processed = 0;

    auto process_region = [&](uint8_t* code_data, size_t code_size, Va base_va) -> MxStatus {
        auto decode_result = ctx.disassembler()->decode_buffer(
            ByteView{code_data, code_size}, base_va);

        if (!decode_result) {
            ctx.log_fmt("  ObfuscationPass: ошибка декодирования по VA 0x{:016X}: {}",
                base_va, decode_result.error().message());
            return {};
        }

        const auto& instructions = *decode_result;

        for (size_t i = 0; i < instructions.size(); ++i) {
            const auto& insn = instructions[i];

            if (!unfolder.can_unfold(insn)) continue;

            size_t available_nop_after = 0;
            if (i + 1 < instructions.size()) {
                const Va gap_start = insn.next_address();
                const Va gap_end = instructions[i + 1].address();
                available_nop_after = static_cast<size_t>(gap_end - gap_start);
            }

            auto unfolded = unfolder.unfold(insn, rng);
            if (unfolded.code.empty()) continue;

            const size_t total_space = insn.length() + available_nop_after;
            if (unfolded.total_size > total_space) continue;

            const auto offset = static_cast<size_t>(insn.address() - base_va);
            if (offset + unfolded.total_size > code_size) continue;

            std::copy(unfolded.code.begin(), unfolded.code.end(),
                      code_data + offset);

            if (unfolded.total_size < insn.length()) {
                auto nop = x86::make_nop(
                    static_cast<uint8_t>(insn.length() - unfolded.total_size));
                std::copy(nop.begin(), nop.end(),
                          code_data + offset + unfolded.total_size);
            }

            ++constants_unfolded;
        }

        auto predicate = pred_gen.generate_always_true(rng, 0);
        if (!predicate.code.empty()) {
            ++predicates_generated;
        }

        return {};
    };

    if (!obfuscation_regions.empty()) {
        for (const auto* region : obfuscation_regions) {
            const Rva start_rva = region->start_rva;
            const Rva end_rva = region->end_rva;
            const uint32_t region_size = end_rva - start_rva;

            if (region_size == 0) continue;

            ctx.log_fmt("ObfuscationPass: обработка региона [0x{:08X}-0x{:08X}] ({} байт)",
                start_rva, end_rva, region_size);

            const auto* section = ctx.pe_image().section_by_rva(start_rva);
            if (!section) {
                ctx.log_fmt("ObfuscationPass: не найдена секция для RVA 0x{:08X}", start_rva);
                continue;
            }

            pe::SectionInfo* mutable_section = nullptr;
            for (auto& s : ctx.pe_image().sections()) {
                if (s.name == section->name && s.virtual_address == section->virtual_address) {
                    mutable_section = &s;
                    break;
                }
            }

            if (!mutable_section) continue;

            const uint32_t offset_in_section = start_rva - section->virtual_address;
            if (offset_in_section + region_size > mutable_section->data.size()) continue;

            const Va region_va = ctx.pe_image().image_base() + start_rva;

            auto status = process_region(
                mutable_section->data.data() + offset_in_section,
                region_size,
                region_va);

            if (status) {
                ++regions_processed;
            }
        }
    } else {
        for (auto& sec : ctx.pe_image().sections()) {
            if (!sec.is_code() || sec.data.empty()) continue;

            const Va section_va = ctx.pe_image().image_base() + sec.virtual_address;

            auto status = process_region(sec.data.data(), sec.data.size(), section_va);
            if (status) {
                ++regions_processed;
            }
        }
    }

    ctx.log_fmt("ObfuscationPass: завершено. Регионов: {}, констант развёрнуто: {}, "
                "предикатов подготовлено: {}",
        regions_processed, constants_unfolded, predicates_generated);

    return {};
}

} // namespace mx
