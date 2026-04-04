/**
 * @file cfg_flattening_pass.cpp
 * @brief [BUILDER] CfgFlattener + CfgFlatteningPass с трамплин-механизмом.
 *
 * @details Реализует два режима CFF:
 *          1. In-place: расплющенный код помещается на место оригинала (если помещается).
 *          2. Trampoline: оригинал заменяется JMP rel32, расплющенный код — в секции .mxprot1.
 *
 *          Trampoline-режим позволяет CFF работать с функциями любого размера:
 *          dispatcher + state transitions выносятся в новую секцию, а в оригинальной
 *          функции остаётся только JMP-перенаправление (5 байт).
 *
 *          При переносе кода блоков в новую секцию выполняется fixup CALL rel32
 *          инструкций (пересчёт смещений для нового адреса).
 */

#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/pe/section_manager.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <unordered_set>

namespace mx {

// ============================================================================
// CfgFlattener
// ============================================================================

CfgFlattener::CfgFlattener(Architecture arch, FlatteningConfig config)
    : arch_(arch)
    , config_(std::move(config))
{}

ByteBuffer CfgFlattener::extract_block_code(
    const analysis::BasicBlock& block,
    ByteView original_code,
    Va base_address) const
{
    const auto start_offset = static_cast<size_t>(block.start_address() - base_address);
    auto end_offset = static_cast<size_t>(block.end_address() - base_address);

    if (end_offset > original_code.size()) {
        end_offset = original_code.size();
    }

    if (start_offset >= end_offset) {
        return {};
    }

    ByteBuffer code(original_code.begin() + start_offset,
                     original_code.begin() + end_offset);

    const auto* terminator = block.terminator();
    if (terminator && (terminator->is_unconditional_jump() || terminator->is_conditional_branch())) {
        const auto term_len = terminator->length();
        if (code.size() >= term_len) {
            code.resize(code.size() - term_len);
        }
    }

    return code;
}

ByteBuffer CfgFlattener::build_state_transition(
    uint32_t next_state_id,
    x86::Reg state_reg,
    [[maybe_unused]] Randomizer& rng) const
{
    analysis::X86CodeEmitter em(is_64bit());

    if (config_.enable_mba_transitions) {
        const auto mask = rng.next_u32();
        const auto encoded_state = next_state_id ^ mask;

        em.mov(state_reg, static_cast<uint64_t>(encoded_state));
        em.xor_(state_reg, static_cast<int32_t>(mask));
    } else {
        em.mov(state_reg, static_cast<uint64_t>(next_state_id));
    }

    auto code = em.build();
    if (!code) return {};
    return std::move(*code);
}

MxResult<FlatteningResult> CfgFlattener::flatten(
    const analysis::ControlFlowGraph& cfg,
    ByteView original_code,
    Va base_address,
    Randomizer& rng)
{
    if (cfg.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::cfg_build_error,
            "CfgFlattener: empty CFG"));
    }

    std::vector<uint32_t> block_ids;
    block_ids.reserve(cfg.block_count());
    for (const auto& [id, block] : cfg.blocks()) {
        block_ids.push_back(id);
    }

    DispatcherGenerator disp_gen(arch_);
    auto state_map = disp_gen.assign_state_ids(block_ids, rng);

    std::vector<FlattenedBlock> flat_blocks;
    flat_blocks.reserve(cfg.block_count());

    for (const auto& [id, block] : cfg.blocks()) {
        FlattenedBlock fb;
        fb.original_block_id = id;
        fb.state_id = state_map[id];
        fb.original_va = block.start_address();

        fb.code = extract_block_code(block, original_code, base_address);

        for (const auto succ_id : block.successors()) {
            if (state_map.contains(succ_id)) {
                fb.successor_states.push_back(state_map[succ_id]);
            }
        }

        if (block.terminator() && block.terminator()->is_conditional_branch()) {
            const auto& raw = block.terminator()->raw_bytes();
            if (raw.size() >= 2 && raw[0] == 0x0F && (raw[1] & 0xF0) == 0x80) {
                fb.branch_cc = static_cast<analysis::ConditionCode>(raw[1] & 0x0F);
            } else if (raw.size() >= 1 && (raw[0] & 0xF0) == 0x70) {
                fb.branch_cc = static_cast<analysis::ConditionCode>(raw[0] & 0x0F);
            }
        }

        if (block.terminator() && block.terminator()->is_return()) {
            fb.successor_states.clear();
            const auto* term = block.terminator();
            fb.code.insert(fb.code.end(),
                term->raw_bytes().begin(), term->raw_bytes().end());
        }

        flat_blocks.push_back(std::move(fb));
    }

    uint32_t bogus_count = 0;
    if (config_.enable_bogus_flow) {
        BogusFlowGenerator bogus_gen(arch_);
        auto bogus_blocks = bogus_gen.generate_for_function(
            static_cast<uint32_t>(flat_blocks.size()),
            config_.bogus_probability,
            rng);

        for (size_t i = 0; i < flat_blocks.size() && i < bogus_blocks.size(); ++i) {
            if (bogus_blocks[i].total_size > 0) {
                ByteBuffer augmented;
                augmented.reserve(
                    bogus_blocks[i].predicate_code.size() +
                    bogus_blocks[i].junk_code.size() +
                    flat_blocks[i].code.size());

                augmented.insert(augmented.end(),
                    bogus_blocks[i].predicate_code.begin(),
                    bogus_blocks[i].predicate_code.end());
                augmented.insert(augmented.end(),
                    bogus_blocks[i].junk_code.begin(),
                    bogus_blocks[i].junk_code.end());
                augmented.insert(augmented.end(),
                    flat_blocks[i].code.begin(),
                    flat_blocks[i].code.end());

                flat_blocks[i].code = std::move(augmented);
                ++bogus_count;
            }
        }
    }

    const uint32_t entry_state = state_map[cfg.entry_block_id()];

    auto disp_result = disp_gen.generate(
        flat_blocks, entry_state, config_.state_var_reg, rng);

    if (!disp_result) {
        return std::unexpected(disp_result.error());
    }

    FlatteningResult result;
    result.flattened_code = std::move(disp_result->full_function);
    result.original_block_count = static_cast<uint32_t>(cfg.block_count());
    result.total_block_count = static_cast<uint32_t>(cfg.block_count() + bogus_count);
    result.bogus_blocks_added = bogus_count;
    result.total_size = static_cast<uint32_t>(result.flattened_code.size());
    result.block_placements = std::move(disp_result->block_placements);

    return result;
}

// ============================================================================
// Fixup: пересчёт всех относительных ссылок при переносе блоков
// ============================================================================

namespace {

void apply_relocation_fixups(
    ByteBuffer& section_data,
    const CffTrampolineEntry& trampoline,
    Rva section_rva,
    Va image_base)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    for (const auto& bp : trampoline.block_placements) {
        if (bp.code_size == 0 || bp.original_va == 0) continue;

        const uint32_t abs_offset = trampoline.section_offset + bp.output_offset;
        if (abs_offset + bp.code_size > section_data.size()) continue;

        const Rva original_block_rva = static_cast<Rva>(bp.original_va - image_base);
        const Rva new_block_rva = section_rva + abs_offset;
        const auto delta = static_cast<int64_t>(new_block_rva)
                         - static_cast<int64_t>(original_block_rva);

        size_t offset = 0;
        while (offset < bp.code_size) {
            ZydisDecodedInstruction insn{};
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

            const uint8_t* insn_ptr = section_data.data() + abs_offset + offset;
            const size_t remaining = bp.code_size - offset;

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    &decoder, insn_ptr, remaining, &insn, operands))) {
                ++offset;
                continue;
            }

            const uint32_t insn_file_base = abs_offset + static_cast<uint32_t>(offset);

            // RIP-relative memory operand ([rip+disp32]): LEA, MOV, CMP, CALL [rip+...], etc.
            if (insn.raw.disp.size == 32) {
                bool has_rip_mem = false;
                for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
                    if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                        has_rip_mem = true;
                        break;
                    }
                }

                if (has_rip_mem) {
                    const uint32_t disp_off = insn_file_base + insn.raw.disp.offset;
                    if (disp_off + 4 <= section_data.size()) {
                        int32_t old_disp = 0;
                        std::memcpy(&old_disp, section_data.data() + disp_off, 4);
                        const auto new_disp = static_cast<int32_t>(old_disp - delta);
                        std::memcpy(section_data.data() + disp_off, &new_disp, 4);
                    }
                }
            }

            // Immediate relative operand (CALL rel32, JMP rel32)
            for (ZyanU8 i = 0; i < insn.operand_count_visible; ++i) {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    operands[i].imm.is_relative &&
                    insn.raw.imm[0].size == 32) {

                    const uint32_t imm_off = insn_file_base + insn.raw.imm[0].offset;
                    if (imm_off + 4 <= section_data.size()) {
                        int32_t old_rel = 0;
                        std::memcpy(&old_rel, section_data.data() + imm_off, 4);
                        const auto new_rel = static_cast<int32_t>(old_rel - delta);
                        std::memcpy(section_data.data() + imm_off, &new_rel, 4);
                    }
                    break;
                }
            }

            offset += insn.length;
        }
    }
}

void write_jmp_trampoline(
    pe::SectionInfo& section,
    uint32_t offset_in_section,
    uint32_t original_size,
    Rva source_rva,
    Rva target_rva)
{
    if (offset_in_section + 5 > section.data.size()) return;

    const auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) - static_cast<int64_t>(source_rva) - 5);

    section.data[offset_in_section] = 0xE9;
    std::memcpy(section.data.data() + offset_in_section + 1, &rel32, 4);

    for (uint32_t i = 5; i < original_size; ++i) {
        if (offset_in_section + i < section.data.size()) {
            section.data[offset_in_section + i] = 0xCC;
        }
    }
}

} // anonymous namespace

// ============================================================================
// CfgFlatteningPass
// ============================================================================

bool CfgFlatteningPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    return ctx.config().enable_cfg_flattening;
}

MxStatus CfgFlatteningPass::execute(ProtectionContext& ctx) {
    ctx.log("CfgFlatteningPass: начало расплющивания потока управления");

    Randomizer rng;

    FlatteningConfig flat_config;
    flat_config.enable_bogus_flow = false;
    flat_config.bogus_probability = 0.0;
    flat_config.enable_mba_transitions = true;

    uint32_t functions_flattened_inplace = 0;
    uint32_t functions_trampolined = 0;
    uint32_t functions_skipped = 0;
    uint32_t total_original_blocks = 0;

    std::vector<CffTrampolineEntry> trampolines;

    // ====================================================================
    // Лямбда: пытаемся расплющить функцию, собираем трамплины
    // ====================================================================
    auto flatten_function = [&](pe::SectionInfo& sec, size_t offset,
                                size_t func_size, Va base_va,
                                Rva func_rva) -> MxStatus {
        if (func_size < 16) return {};

        ByteBuffer code_snapshot(sec.data.begin() + offset,
                                 sec.data.begin() + offset + func_size);

        analysis::CfgBuilder cfg_builder(ctx.disassembler());
        auto cfg_result = cfg_builder.build(
            ByteView{code_snapshot.data(), code_snapshot.size()}, base_va);

        if (!cfg_result) return {};

        const auto& cfg = *cfg_result;
        if (cfg.block_count() < 3) return {};

        // ==================================================================
        // Safety: skip functions with patterns incompatible with CFF
        // ==================================================================
        bool unsafe = false;
        for (const auto& [bid, block] : cfg.blocks()) {
            const auto* term = block.terminator();
            if (!term) continue;

            // Indirect jumps (jmp rax, jmp [mem]) → jump tables / switch
            if (term->is_unconditional_jump() && term->branch_targets().empty()) {
                unsafe = true;
                break;
            }

            // Indirect calls with no known target within function range
            // (call rax, call [mem]) are OK — they call external code and return.
            // But unconditional branches with out-of-range targets indicate
            // tail calls or thunks that break CFF's state machine.
            if (term->is_unconditional_jump() && !term->branch_targets().empty()) {
                bool all_external = true;
                for (const auto target : term->branch_targets()) {
                    if (target >= base_va && target < base_va + func_size) {
                        all_external = false;
                        break;
                    }
                }
                if (all_external) {
                    unsafe = true;
                    break;
                }
            }
        }

        // Verify blocks cover a reasonable portion of the function body
        uint64_t covered = 0;
        for (const auto& [bid, block] : cfg.blocks()) {
            covered += block.size();
        }
        if (covered < func_size / 2) {
            unsafe = true;
        }

        if (unsafe) {
            ++functions_skipped;
            return {};
        }

        CfgFlattener flattener(ctx.pe_image().architecture(), flat_config);
        auto flat_result = flattener.flatten(
            cfg, ByteView{code_snapshot.data(), code_snapshot.size()}, base_va, rng);

        if (!flat_result) return {};

        total_original_blocks += flat_result->original_block_count;

        if (flat_result->flattened_code.size() <= func_size) {
            std::copy(flat_result->flattened_code.begin(),
                      flat_result->flattened_code.end(),
                      sec.data.begin() + offset);

            if (flat_result->flattened_code.size() < func_size) {
                std::fill(sec.data.begin() + offset + flat_result->flattened_code.size(),
                          sec.data.begin() + offset + func_size,
                          static_cast<uint8_t>(0xCC));
            }

            ++functions_flattened_inplace;
        } else {
            CffTrampolineEntry entry;
            entry.original_func_rva = func_rva;
            entry.original_func_size = static_cast<uint32_t>(func_size);
            entry.flattened_code = std::move(flat_result->flattened_code);
            entry.block_placements = std::move(flat_result->block_placements);
            trampolines.push_back(std::move(entry));

            ++functions_trampolined;
        }

        return {};
    };

    // ====================================================================
    // Обработка маркированных регионов
    // ====================================================================
    std::vector<const MarkedRegion*> regions;
    for (const auto& marker : ctx.markers()) {
        if (marker.type == MarkerType::obfuscate_begin) {
            regions.push_back(&marker);
        }
    }

    if (!regions.empty()) {
        for (const auto* region : regions) {
            const Rva start_rva = region->start_rva;
            const Rva end_rva = region->end_rva;
            const uint32_t region_size = end_rva - start_rva;

            if (region_size < 16) continue;

            ctx.log_fmt("CfgFlatteningPass: регион [0x{:08X}-0x{:08X}] ({} байт)",
                start_rva, end_rva, region_size);

            pe::SectionInfo* section = nullptr;
            for (auto& s : ctx.pe_image().sections()) {
                if (s.contains_rva(start_rva)) {
                    section = &s;
                    break;
                }
            }

            if (!section) continue;

            const uint32_t offset_in_section = start_rva - section->virtual_address;
            if (offset_in_section + region_size > section->data.size()) continue;

            const Va region_va = ctx.pe_image().image_base() + start_rva;
            (void)flatten_function(*section, offset_in_section, region_size,
                                   region_va, start_rva);
        }
    } else {
        ctx.log("CfgFlatteningPass: маркеров не найдено, используем .pdata для границ функций");

        struct RuntimeFunction {
            uint32_t begin_addr;
            uint32_t end_addr;
            uint32_t unwind_info;
        };

        const pe::SectionInfo* pdata = ctx.pe_image().section_by_name(".pdata");
        if (!pdata || pdata->data.size() < sizeof(RuntimeFunction)) {
            ctx.log("CfgFlatteningPass: .pdata не найдена, пропуск CFF");
        } else {
            const size_t func_count = pdata->data.size() / sizeof(RuntimeFunction);
            const auto* funcs = reinterpret_cast<const RuntimeFunction*>(pdata->data.data());

            ctx.log_fmt("CfgFlatteningPass: найдено {} функций в .pdata", func_count);

            // Identify CRT boundary: user code is typically placed
            // BEFORE the CRT entry point in .text by MSVC linker.
            const Rva entry_rva = ctx.pe_image().entry_point_rva();
            size_t entry_idx = func_count;
            for (size_t j = 0; j < func_count; ++j) {
                if (funcs[j].begin_addr <= entry_rva &&
                    funcs[j].end_addr > entry_rva) {
                    entry_idx = j;
                    break;
                }
            }

            ctx.log_fmt("CfgFlatteningPass: entry point at .pdata[{}] "
                        "(RVA=0x{:08X}), CFF range: [0..{})",
                        entry_idx, entry_rva, entry_idx);

            for (size_t i = 0; i < entry_idx; ++i) {
                const Rva func_rva = funcs[i].begin_addr;
                const uint32_t func_size = funcs[i].end_addr - funcs[i].begin_addr;

                if (func_size < 32 || func_size > 8192) continue;

                pe::SectionInfo* section = nullptr;
                for (auto& s : ctx.pe_image().sections()) {
                    if (s.is_code() && s.contains_rva(func_rva)) {
                        section = &s;
                        break;
                    }
                }
                if (!section) continue;

                const uint32_t offset_in_section = func_rva - section->virtual_address;
                if (offset_in_section + func_size > section->data.size()) continue;

                const Va func_va = ctx.pe_image().image_base() + func_rva;
                (void)flatten_function(*section, offset_in_section, func_size,
                                       func_va, func_rva);
            }
        }
    }

    // ====================================================================
    // Создание секции .mxprot1 для трамплинов
    // ====================================================================
    if (!trampolines.empty()) {
        ctx.log_fmt("CfgFlatteningPass: {} функций требуют трамплин-секцию",
            trampolines.size());

        constexpr uint32_t func_alignment = 16;
        ByteBuffer section_data;

        for (auto& entry : trampolines) {
            while (section_data.size() % func_alignment != 0) {
                section_data.push_back(0xCC);
            }

            entry.section_offset = static_cast<uint32_t>(section_data.size());
            section_data.insert(section_data.end(),
                entry.flattened_code.begin(),
                entry.flattened_code.end());
        }

        while (section_data.size() % func_alignment != 0) {
            section_data.push_back(0xCC);
        }

        constexpr uint32_t cff_section_characteristics =
            pe::IMAGE_SCN_CNT_CODE |
            pe::IMAGE_SCN_MEM_EXECUTE |
            pe::IMAGE_SCN_MEM_READ;

        SectionManager sec_mgr(ctx.pe_image());
        auto add_result = sec_mgr.add_section(
            ".mxprot1",
            ByteView{section_data.data(), section_data.size()},
            cff_section_characteristics);

        if (!add_result) {
            ctx.log_fmt("CfgFlatteningPass: ошибка добавления секции: {}",
                add_result.error().message());
            return {};
        }

        const uint32_t section_index = *add_result;
        const auto& new_section = ctx.pe_image().sections()[section_index];
        const Rva section_rva = new_section.virtual_address;
        const Va image_base = ctx.pe_image().image_base();

        ctx.log_fmt("CfgFlatteningPass: секция .mxprot1 добавлена: RVA=0x{:08X}, "
                    "размер={} байт", section_rva, section_data.size());

        auto& mxprot_section = ctx.pe_image().sections()[section_index];

        for (const auto& entry : trampolines) {
            apply_relocation_fixups(
                mxprot_section.data, entry, section_rva, image_base);
        }

        for (const auto& entry : trampolines) {
            pe::SectionInfo* text_section = nullptr;
            for (auto& s : ctx.pe_image().sections()) {
                if (s.is_code() && s.contains_rva(entry.original_func_rva)) {
                    text_section = &s;
                    break;
                }
            }
            if (!text_section) continue;

            const uint32_t offset_in_text =
                entry.original_func_rva - text_section->virtual_address;
            const Rva target_rva = section_rva + entry.section_offset;

            write_jmp_trampoline(
                *text_section, offset_in_text, entry.original_func_size,
                entry.original_func_rva, target_rva);

            ctx.log_fmt("CfgFlatteningPass: трамплин 0x{:08X} -> 0x{:08X} "
                        "({} -> {} байт)",
                entry.original_func_rva, target_rva,
                entry.original_func_size,
                static_cast<uint32_t>(entry.flattened_code.size()));
        }

        // ==================================================================
        // Patch .pdata: zero out RUNTIME_FUNCTION entries for CFF'd functions
        // so the OS doesn't try to unwind through stale unwind info.
        // The trampoline (JMP) is a leaf instruction — no unwind needed.
        // ==================================================================
        struct RuntimeFunction {
            uint32_t begin_addr;
            uint32_t end_addr;
            uint32_t unwind_info;
        };

        pe::SectionInfo* pdata_sec = nullptr;
        for (auto& s : ctx.pe_image().sections()) {
            if (s.name == ".pdata") {
                pdata_sec = &s;
                break;
            }
        }

        if (pdata_sec && pdata_sec->data.size() >= sizeof(RuntimeFunction)) {
            const size_t entry_count = pdata_sec->data.size() / sizeof(RuntimeFunction);
            auto* rt_funcs = reinterpret_cast<RuntimeFunction*>(pdata_sec->data.data());

            std::unordered_set<Rva> trampolined_rvas;
            trampolined_rvas.reserve(trampolines.size());
            for (const auto& t : trampolines) {
                trampolined_rvas.insert(t.original_func_rva);
            }

            uint32_t patched = 0;
            for (size_t i = 0; i < entry_count; ++i) {
                if (trampolined_rvas.contains(rt_funcs[i].begin_addr)) {
                    rt_funcs[i].begin_addr = 0;
                    rt_funcs[i].end_addr = 0;
                    rt_funcs[i].unwind_info = 0;
                    ++patched;
                }
            }

            if (patched > 0) {
                ctx.log_fmt("CfgFlatteningPass: обнулено {} записей .pdata "
                            "для трамплинированных функций", patched);
            }
        }
    }

    ctx.log_fmt("CfgFlatteningPass: завершено. In-place: {}, трамплинов: {}, "
                "пропущено: {}, блоков: {}",
        functions_flattened_inplace, functions_trampolined,
        functions_skipped, total_original_blocks);

    return {};
}

} // namespace mx
