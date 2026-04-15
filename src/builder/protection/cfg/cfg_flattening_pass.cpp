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
#include "mxprotector/protection/cfg/map_parser.hpp"
#include "mxprotector/protection/cfg/mba_transition_gen.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/pe/section_manager.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <optional>
#include <queue>
#include <unordered_set>

namespace mx {

namespace {

bool code_uses_register(ByteView code, ZydisRegister reg) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    const auto matches = [reg](ZydisRegister r) {
        return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r) ==
               ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
    };

    size_t offset = 0;
    while (offset < code.size()) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code.data() + offset, code.size() - offset,
                &insn, operands))) {
            ++offset;
            continue;
        }

        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                matches(operands[i].reg.value)) {
                return true;
            }
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (matches(operands[i].mem.base) ||
                    matches(operands[i].mem.index)) {
                    return true;
                }
            }
        }

        offset += insn.length;
    }
    return false;
}

std::optional<x86::Reg> select_state_register(ByteView func_code) {
    struct Candidate {
        x86::Reg mx_reg;
        ZydisRegister zy_reg;
    };

    static constexpr Candidate candidates[] = {
        {x86::Reg::r10, ZYDIS_REGISTER_R10},
        {x86::Reg::r11, ZYDIS_REGISTER_R11},
    };

    for (const auto& [mx, zy] : candidates) {
        if (!code_uses_register(func_code, zy)) {
            return mx;
        }
    }
    return std::nullopt;
}

} // anonymous namespace

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
                const uint32_t prefix_size = static_cast<uint32_t>(
                    bogus_blocks[i].predicate_code.size() +
                    bogus_blocks[i].junk_code.size());

                ByteBuffer augmented;
                augmented.reserve(prefix_size + flat_blocks[i].code.size());

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
                flat_blocks[i].bogus_prefix_size = prefix_size;
                ++bogus_count;
            }
        }
    }

    const uint32_t entry_state = state_map[cfg.entry_block_id()];

    DispatcherConfig disp_config;
    disp_config.enable_mba_transitions = config_.enable_mba_transitions;
    disp_config.enable_junk_blocks     = config_.enable_junk_blocks;
    disp_config.junk_block_ratio       = config_.junk_block_ratio;

    auto disp_result = disp_gen.generate(
        flat_blocks, entry_state, config_.state_var_reg, rng, disp_config);

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

/// Check whether a function's prologue bytes indicate an MSVC
/// "register-save-via-rsp-copy" pattern that the current flattener
/// doesn't handle correctly:
///
///     mov rax, rsp              ; 48 8B C4 (load-form)
///     mov [rax+8], rbx          ; SAVE_NONVOL via the rax alias
///     mov [rax+0x10], rbp
///     ...
///     push r14                  ; THEN the "normal" push saves
///     sub rsp, N
///
/// The ORIGINAL pre-mutation bytes start with `48 8B C4` (opcode 8B
/// = MOV r64, r/m64). After `MutationPass` runs its instruction
/// substitution rules, the same sequence may be re-encoded to the
/// equivalent store-form `48 89 E0` (opcode 89 = MOV r/m64, r64);
/// both encodings produce `mov rax, rsp` with identical semantics.
/// The check below matches either form.
///
/// The failing pattern reproduces deterministically on
/// `test_exception.exe`'s RVA 0x184C CRT helper — a function that
/// saves rbx/rbp/rsi/rdi directly into the caller's shadow space
/// via `mov [rax+N], reg` rather than pushing them. The flattener
/// shuffles blocks and inserts its dispatcher jumps between the
/// `mov rax, rsp` and the subsequent mov-based saves in a way that
/// subtly breaks the function on some code paths. The root cause
/// wasn't isolated in a reasonable time budget, and a bisect via
/// `MX_CFF_SKIP_RVA=184C` confirmed this specific function is the
/// only crash source in the CRT helper window. Skipping it keeps
/// CFF coverage for every standard-prologue function while
/// avoiding the one pattern the flattener gets wrong.
[[nodiscard]] bool first_instruction_is_mov_rax_rsp(
    ByteView func_bytes) noexcept
{
    if (func_bytes.size() < 3) return false;
    // `48 8B C4` — MOV r64 rax, r/m64 rsp (load form)
    // `48 89 E0` — MOV r/m64 rax, r64 rsp (store form, post-mutation)
    if (func_bytes[0] == 0x48 && func_bytes[1] == 0x8B && func_bytes[2] == 0xC4) {
        return true;
    }
    if (func_bytes[0] == 0x48 && func_bytes[1] == 0x89 && func_bytes[2] == 0xE0) {
        return true;
    }
    return false;
}

/// Check whether a function's `.xdata` unwind record makes it unsafe
/// for CFG flattening. Three conditions, any of which is a stop-sign:
///
///   * `UNW_FLAG_EHANDLER (0x01)` — function has a `__try/__except`
///     or C++ catch scope directly attached. The SEH dispatcher
///     reads a language-specific scope table inline after the
///     unwind codes and matches current `Rip` against it to pick
///     the right filter. If CFF rewrites the function body, every
///     address in the scope table becomes stale and the match
///     picks the wrong filter — typical outcome is a silent
///     process abort during CRT startup.
///
///   * `UNW_FLAG_UHANDLER (0x02)` — termination handler
///     (`__try/__finally`). Same staleness risk. MSVC's
///     `__scrt_common_main_seh`, the CRT wrapper that runs
///     `main()` inside a `__try/__except(seh_filter_exe(...))`,
///     always has this flag set.
///
///   * `UNW_FLAG_CHAININFO (0x04)` — this record chains into
///     another record's unwind codes. Chained records are NOT
///     standalone functions: MSVC emits them when a single logical
///     function has multiple prologue phases (e.g., register saves
///     deferred past the main prologue because the saved register
///     is live-in), and each phase needs its own unwind codes.
///     The `begin/end` range of a chained entry covers a code
///     SLICE inside a larger function, and linear execution
///     typically falls out of the slice into the parent. CFF
///     processing this as a standalone function produces code that
///     emits `jmp exit` (= `int3` trap) where the original just
///     continued linearly into the rest of the parent function,
///     aborting the process the moment execution reaches that
///     slice. The test_exception.exe crash under `-l standard` was
///     this exact case at RVA 0x10C1, a chained entry whose parent
///     starts at RVA 0x1070.
///
/// The `.xdata` bytes may live in `.xdata`, `.rdata`, or any other
/// data section — MSVC typically emits unwind info into `.rdata`.
/// We resolve the containing section by RVA rather than by name.
[[nodiscard]] bool unwind_info_makes_function_unsafe_for_cff(
    const PeImage& image,
    uint32_t       unwind_info_rva) noexcept
{
    if (unwind_info_rva == 0) return false;

    const pe::SectionInfo* sec = image.section_by_rva(unwind_info_rva);
    if (sec == nullptr) return false;

    const uint32_t offset = unwind_info_rva - sec->virtual_address;
    if (offset >= sec->data.size()) return false;

    // UNWIND_INFO first byte: Version(3 bits) | Flags(5 bits).
    const uint8_t first_byte = sec->data[offset];
    const uint8_t flags = static_cast<uint8_t>((first_byte >> 3) & 0x1F);

    constexpr uint8_t kEhandler  = 0x01;
    constexpr uint8_t kUhandler  = 0x02;
    constexpr uint8_t kChainInfo = 0x04;

    return (flags & (kEhandler | kUhandler | kChainInfo)) != 0;
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
    flat_config.enable_bogus_flow      = true;
    flat_config.bogus_probability      = 0.5;
    flat_config.enable_mba_transitions = true;
    flat_config.enable_junk_blocks     = true;
    flat_config.junk_block_ratio       = 0.12;

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

        auto& cfg = *cfg_result;

        // Remove unreachable blocks (padding/INT3 after RET)
        {
            std::unordered_set<uint32_t> reachable;
            std::queue<uint32_t> bfs;
            bfs.push(cfg.entry_block_id());
            reachable.insert(cfg.entry_block_id());
            while (!bfs.empty()) {
                const auto cur = bfs.front();
                bfs.pop();
                const auto* blk = cfg.block_by_id(cur);
                if (!blk) continue;
                for (const auto succ : blk->successors()) {
                    if (reachable.insert(succ).second) {
                        bfs.push(succ);
                    }
                }
            }
            std::vector<uint32_t> to_remove;
            for (const auto& [id, _] : cfg.blocks()) {
                if (!reachable.contains(id)) {
                    to_remove.push_back(id);
                }
            }
            for (const auto id : to_remove) {
                cfg.blocks().erase(id);
            }
        }

        if (cfg.block_count() < 3) return {};

        // Skip the non-standard "mov rax, rsp; mov [rax+N], reg" prologue
        // pattern — see the comment on `first_instruction_is_mov_rax_rsp`
        // for the rationale.
        if (first_instruction_is_mov_rax_rsp(
                ByteView{code_snapshot.data(), code_snapshot.size()})) {
            ctx.log_fmt("  CFF: RVA=0x{:08X} size={} — skipped "
                        "(mov rax, rsp prologue pattern)",
                func_rva, func_size);
            ++functions_skipped;
            return {};
        }

        // ==================================================================
        // Safety: skip functions with patterns incompatible with CFF
        // ==================================================================
        bool unsafe = false;
        for (const auto& [bid, block] : cfg.blocks()) {
            const auto* term = block.terminator();
            if (!term) continue;

            if (term->is_unconditional_jump() && term->branch_targets().empty()) {
                unsafe = true;
                break;
            }

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

        const auto chosen_reg = select_state_register(
            ByteView{code_snapshot.data(), code_snapshot.size()});
        if (!chosen_reg) {
            ctx.log_fmt("  CFF: RVA=0x{:08X} size={} — skipped (no free state register)",
                func_rva, func_size);
            ++functions_skipped;
            return {};
        }
        auto func_config = flat_config;
        func_config.state_var_reg = *chosen_reg;

        const char* reg_name = (*chosen_reg == x86::Reg::r11) ? "R11" : "R10";
        ctx.log_fmt("  CFF: RVA=0x{:08X} size={} blocks={} state_reg={}",
            func_rva, func_size, cfg.block_count(), reg_name);

        CfgFlattener flattener(ctx.pe_image().architecture(), func_config);
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
        // Try .map file first, then fall back to .pdata
        bool used_map_file = false;

        if (!ctx.config().map_file_path.empty()) {
            ctx.log_fmt("CfgFlatteningPass: парсинг .map файла: {}",
                ctx.config().map_file_path.string());

            auto map_result = MapParser::parse(ctx.config().map_file_path);
            if (map_result) {
                const pe::SectionInfo* text_sec = nullptr;
                for (const auto& s : ctx.pe_image().sections()) {
                    if (s.is_code() && s.name == ".text") {
                        text_sec = &s;
                        break;
                    }
                }

                if (text_sec) {
                    ByteView text_code{text_sec->data.data(), text_sec->data.size()};
                    auto candidates = MapParser::filter_candidates(
                        map_result->all_functions, text_code,
                        text_sec->virtual_address, text_sec->virtual_size);

                    ctx.log_fmt("CfgFlatteningPass: .map: {} функций всего, "
                                "{} кандидатов для CFF",
                        map_result->all_functions.size(), candidates.size());

                    for (const auto& func : candidates) {
                        pe::SectionInfo* section = nullptr;
                        for (auto& s : ctx.pe_image().sections()) {
                            if (s.is_code() && s.contains_rva(func.rva)) {
                                section = &s;
                                break;
                            }
                        }
                        if (!section) continue;

                        const uint32_t offset_in_section =
                            func.rva - section->virtual_address;
                        if (offset_in_section + func.size > section->data.size()) continue;

                        const Va func_va = ctx.pe_image().image_base() + func.rva;
                        (void)flatten_function(*section, offset_in_section, func.size,
                                               func_va, func.rva);
                    }

                    used_map_file = true;
                }
            } else {
                ctx.log_fmt("CfgFlatteningPass: ошибка парсинга .map: {}",
                    map_result.error().message());
            }
        }

        if (!used_map_file) {
            // `.pdata` fallback: iterate every `RUNTIME_FUNCTION`
            // whose begin address is before the entry point and
            // try to flatten each one. This automatically covers
            // binaries that ship without a `.map` file or
            // `MX_OBFUSCATE_BEGIN/END` markers.
            //
            // ## The old bug
            //
            // An earlier version of this loop flattened every
            // entry in that window unconditionally, which broke
            // C++ binaries on `-l standard`+ because a subset of
            // `.pdata` entries describe CODE SLICES, not full
            // functions:
            //
            //   * **`UNW_FLAG_CHAININFO`**: MSVC emits chained
            //     unwind records whenever a function has multiple
            //     prologue phases (e.g., registers saved lazily
            //     after the main prologue). The chained entry's
            //     `BeginAddress`/`EndAddress` cover a slice in the
            //     middle of the parent function; linear execution
            //     falls out of the slice into the parent function's
            //     continuation, NOT to a `ret` inside the slice.
            //     CFG flattening on that slice emits a dispatcher
            //     with `jmp exit` for the last block (exit_label
            //     is a one-byte `int3` trap). Runtime execution
            //     hits the trap the moment it reaches the slice
            //     through the parent flow → exit 127 with no
            //     stdout during CRT startup.
            //
            //   * **`UNW_FLAG_EHANDLER`** / **`UNW_FLAG_UHANDLER`**:
            //     functions with attached SEH/C++ handlers carry
            //     a scope table after the unwind codes. Flattening
            //     their body invalidates the address references
            //     inside the scope table, so the runtime
            //     dispatcher picks the wrong handler (or an
            //     invalid one) and the process aborts.
            //
            // The `test_exception.exe` smoke test used to exit 127
            // under `-l standard` without `--no-cfg-flattening`
            // because `.pdata[2]` at RVA 0x10C1 was a chained
            // entry (parent at 0x1070) that this loop flattened.
            // `dumpbin /UNWINDINFO` confirmed the CHAININFO flag.
            //
            // ## The fix
            //
            // Skip any entry whose `UNWIND_INFO.Flags` contains
            // any of EHANDLER / UHANDLER / CHAININFO. This leaves
            // normal leaf functions and standard-prologue
            // functions eligible for CFF while excluding the
            // slice-style chained entries and the SEH-bearing
            // functions that carry language-specific scope
            // tables. The filter is cheap (one byte read per
            // candidate) and has no runtime cost in the protected
            // binary.
            ctx.log("CfgFlatteningPass: используем .pdata для границ функций");

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

                uint32_t unsafe_skipped = 0;
                for (size_t i = 0; i < entry_idx; ++i) {
                    const Rva func_rva = funcs[i].begin_addr;
                    const uint32_t func_size = funcs[i].end_addr - funcs[i].begin_addr;

                    if (func_size < MapParser::kMinFunctionSize ||
                        func_size > MapParser::kMaxFunctionSize) continue;

                    if (unwind_info_makes_function_unsafe_for_cff(
                            ctx.pe_image(), funcs[i].unwind_info)) {
                        ++unsafe_skipped;
                        continue;
                    }

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

                if (unsafe_skipped > 0) {
                    ctx.log_fmt("CfgFlatteningPass: пропущено {} функций с "
                                "UNW_FLAG_EHANDLER/UHANDLER/CHAININFO "
                                "(compat с C++ exception unwinder + "
                                "chained-unwind slices)",
                        unsafe_skipped);
                }
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
        const std::string& cff_section_name = ctx.section_names().cff;
        auto add_result = sec_mgr.add_section(
            cff_section_name,
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

        ctx.log_fmt("CfgFlatteningPass: секция '{}' добавлена: RVA=0x{:08X}, "
                    "размер={} байт", cff_section_name, section_rva, section_data.size());

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
        // .pdata handling for trampolined functions.
        //
        // Historical bug: this block used to zero out `begin_addr`,
        // `end_addr`, and `unwind_info` for every trampolined function,
        // reasoning that "the trampoline (JMP) is a leaf instruction —
        // no unwind needed." That reasoning is wrong for C++ exception
        // handling:
        //
        //   * The .pdata section is a sorted array of
        //     `RUNTIME_FUNCTION` entries. The SEH dispatcher
        //     binary-searches it by `Rip` to find unwind info for
        //     EVERY frame on the stack, not just the frame an
        //     exception is thrown from.
        //
        //   * When a protected C++ binary throws (even an internal
        //     CRT exception during startup), the unwinder walks UP
        //     the stack looking for a handler. If it ever hits a
        //     frame whose `Rip` resolves to a zeroed .pdata entry,
        //     `RtlLookupFunctionEntry` returns NULL, the walk fails,
        //     and the process terminates — usually with exit code
        //     127, no stdout, because the crash happens inside
        //     `RtlRaiseException` before user code has a chance to
        //     print anything.
        //
        //   * `test_exception.cpp` reproduces this: before the fix
        //     it exits 127 with empty output under `-l strong`;
        //     with `--no-cfg-flattening` it runs to completion.
        //
        // Fix: leave .pdata entries intact. The original entry still
        // points at the original `.xdata` blob, which describes the
        // function's prologue in RVA-independent terms. For in-place
        // flattening that's exactly what the runtime still has at
        // the original RVA (the flattener preserves prologue bytes).
        // For trampoline mode the original RVA is now a 5-byte
        // `jmp rel32` + `0xCC` pad, which is:
        //
        //   1. Almost never reached with Rip mid-jmp (a single
        //      instruction), and
        //   2. Describes a "leaf" function the unwinder can still
        //      trivially pass through: the original xdata codes
        //      tell it how to reverse the prologue, and since the
        //      actual stack state WAS correctly set up by the
        //      flattened trampoline target before `ret` fires, the
        //      unwind math agrees.
        //
        // This fix preserves CFF's original-RVA-range semantics for
        // the unwinder without introducing any new .pdata
        // resizing, reallocation, or header surgery.
        if (!trampolines.empty()) {
            ctx.log_fmt("CfgFlatteningPass: .pdata оставлен без изменений "
                        "({} трамплин. функций) для совместимости с "
                        "C++ exception unwinder",
                static_cast<uint32_t>(trampolines.size()));
        }
    }

    ctx.log_fmt("CfgFlatteningPass: завершено. In-place: {}, трамплинов: {}, "
                "пропущено: {}, блоков: {}",
        functions_flattened_inplace, functions_trampolined,
        functions_skipped, total_original_blocks);

    return {};
}

} // namespace mx
