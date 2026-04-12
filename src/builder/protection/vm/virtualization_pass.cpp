/**
 * @file virtualization_pass.cpp
 * @brief [BUILDER] Реализация VirtualizationPass.
 *
 * Основной алгоритм:
 *   1. Находим все MX_VM_BEGIN..END регионы в контексте.
 *   2. Извлекаем сырые байты каждого региона.
 *   3. VmLifter → vector<VmInstruction>.
 *   4. VmRuntimeGenerator → blob (entry + dispatcher + handlers + bytecode).
 *   5. Помещаем все blob'ы в одну секцию .mxvm.
 *   6. В каждом оригинальном регионе:
 *      - стираем begin-маркер (9 байт) NOP-ами
 *      - заменяем тело региона JMP rel32 на vm_entry
 *      - стираем end-маркер NOP-ами
 *      - заполняем всё оставшееся INT3
 *   7. После того как VM доходит до VmOp::exit, handler делает ret,
 *      который прыгает на адрес после JMP (т.е. куда бы пошёл поток после end-маркера).
 *
 * ВАЖНО: поскольку оригинальный регион заменяется JMP, после JMP нет
 * инструкций — следовательно, VM ret должен попасть на "адрес после
 * заменённого региона". Мы используем **CALL** вместо JMP и размещаем
 * сразу после CALL заглушку jmp end_continuation_rva. Когда VM делает ret,
 * он попадает на эту заглушку → jmp continuation → продолжение.
 *
 * Альтернатива (проще): CALL, а после CALL — NOP'ы до end-маркера.
 * Тогда ret возвращается в NOP'ы, которые дальше выполняются как обычно,
 * вплоть до конца региона. Это самое чистое решение, без заглушек.
 *
 * Используем именно этот подход: заменяем [begin_marker..end_marker_end)
 * на [CALL vm_entry][NOPs до end_marker_end). VM ret → nop → выполнение дальше.
 */

#include "mxprotector/protection/vm/virtualization_pass.hpp"
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"
#include "mxprotector/protection/mutation/junk_generator.hpp"

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/section_manager.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace mx {

namespace {

struct RegionPatch {
    Rva      original_begin_rva;   ///< RVA начала begin-маркера
    uint32_t total_size;           ///< begin_marker + body + end_marker
    uint32_t vm_entry_rva;          ///< RVA vm_entry (в секции .mxvm)
};

/**
 * @brief Записывает CALL rel32 по offset, добавляет NOP-паддинг до total_size.
 */
void write_call_and_pad(
    pe::SectionInfo& section,
    uint32_t offset_in_section,
    uint32_t total_size,
    Rva source_rva,
    Rva target_rva)
{
    if (offset_in_section + total_size > section.data.size()) return;
    if (total_size < 5) return;

    // CALL rel32 = E8 rel32  (5 bytes)
    const auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) -
        static_cast<int64_t>(source_rva) - 5);

    section.data[offset_in_section] = 0xE8;
    std::memcpy(section.data.data() + offset_in_section + 1, &rel32, 4);

    // Заполняем оставшиеся байты NOP'ами (x86 NOP = 0x90)
    for (uint32_t i = 5; i < total_size; ++i) {
        section.data[offset_in_section + i] = 0x90;
    }
}

/**
 * @brief Стирает маркер: N байт → NOP'ы.
 */
void erase_marker(pe::SectionInfo& section, uint32_t offset_in_section, uint32_t size) {
    if (offset_in_section + size > section.data.size()) return;
    for (uint32_t i = 0; i < size; ++i) {
        section.data[offset_in_section + i] = 0x90;
    }
}

} // anonymous namespace

bool VirtualizationPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    if (!ctx.config().enable_vm) return false;
    // Применим только если есть VM-маркеры
    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::vm_begin) return true;
    }
    return false;
}

MxStatus VirtualizationPass::execute(ProtectionContext& ctx) {
    ctx.log("VirtualizationPass: начало виртуализации VM-регионов");

    // Собираем все VM-регионы
    std::vector<const MarkedRegion*> vm_regions;
    for (const auto& marker : ctx.markers()) {
        if (marker.type == MarkerType::vm_begin) {
            vm_regions.push_back(&marker);
        }
    }

    if (vm_regions.empty()) {
        ctx.log("VirtualizationPass: VM-регионов не найдено");
        return {};
    }

    ctx.log_fmt("VirtualizationPass: найдено {} VM-регионов", vm_regions.size());

    Randomizer rng;
    vm::VmLifter lifter(*ctx.disassembler());
    vm::VmRuntimeGenerator gen;

    // Собираем все blobs и отмечаем точки замены
    struct PendingRegion {
        Rva       begin_marker_rva;
        Rva       body_start_rva;    // конец begin-маркера
        Rva       body_end_rva;      // начало end-маркера
        uint32_t  total_patch_size;  // total bytes to overwrite (begin marker + body + end marker)
        ByteBuffer vm_blob;
        uint32_t  entry_offset_in_blob;
        uint32_t  blob_offset_in_section = 0;
    };

    std::vector<PendingRegion> pendings;
    pendings.reserve(vm_regions.size());

    for (const auto* r : vm_regions) {
        const Rva body_start = r->start_rva;
        const Rva body_end   = r->end_rva;
        const Rva begin_marker_rva = body_start - r->begin_marker_size;
        const uint32_t body_size = body_end - body_start;

        if (body_size == 0) {
            ctx.log_fmt("  VM регион [0x{:08X}..0x{:08X}] пуст, пропуск",
                body_start, body_end);
            continue;
        }
        if (body_size < 5) {
            ctx.log_fmt("  VM регион [0x{:08X}..0x{:08X}] слишком мал ({} < 5 байт для CALL rel32), пропуск",
                body_start, body_end, body_size);
            continue;
        }

        auto body_bytes = ctx.pe_image().read_bytes(body_start, body_size);
        if (!body_bytes) {
            ctx.log_fmt("  VM регион: ошибка чтения байт: {}",
                body_bytes.error().message());
            continue;
        }

        const Va base_va = ctx.pe_image().image_base() + body_start;
        auto lift_result = lifter.lift(*body_bytes, base_va);
        if (!lift_result) {
            ctx.log_fmt("  VM регион [0x{:08X}..0x{:08X}]: ошибка лифтинга: {}",
                body_start, body_end, lift_result.error().message());
            continue;
        }

        auto [vm_insns, report] = *lift_result;
        ctx.log_fmt("  VM регион [0x{:08X}..0x{:08X}] {} байт: "
                    "generic={}, native={}, total={}",
            body_start, body_end, body_size,
            report.generic_ops, report.native_ops, report.total_insns);

        // Inject junk native handlers between real instructions. Each junk
        // instruction is a VmOp::native containing semantically dead x64
        // bytes (push/pop, self-canceling arithmetic, etc.). This pollutes
        // the bytecode and handler chain with noise that a reverser must
        // analyze instruction-by-instruction to distinguish real from junk.
        {
            JunkGenerator junk_gen(ctx.pe_image().architecture());
            std::vector<vm::VmInstruction> augmented;
            augmented.reserve(vm_insns.size() * 2);

            // old_index → new_index mapping (for branch target fixup)
            std::vector<uint32_t> remap(vm_insns.size() + 1);

            for (size_t oi = 0; oi < vm_insns.size(); ++oi) {
                remap[oi] = static_cast<uint32_t>(augmented.size());
                // ~30% chance to insert a junk instruction BEFORE each real one
                if (rng.next_bool(0.3)) {
                    // Only use patterns that are completely state-safe
                    // when executed as native handlers (no flag/reg corruption):
                    // - push/pop same reg (stack net-zero)
                    // - xchg pair (swap+unswap, no flags)
                    // - double bswap (identity, no flags)
                    // - multi-byte NOP (literal no-op)
                    vm::VmInstruction junk;
                    junk.op = vm::VmOp::native;
                    junk.native_bytes = junk_gen.generate_vm_safe_pattern(rng);
                    augmented.push_back(std::move(junk));
                }
                augmented.push_back(std::move(vm_insns[oi]));
            }
            // Sentinel: remap[vm_insns.size()] = exit position (for branches to exit)
            remap[vm_insns.size()] = static_cast<uint32_t>(augmented.size());

            // Fix up VJMP/VJCC branch targets
            for (auto& vi : augmented) {
                if (vi.op == vm::VmOp::vjmp || vi.op == vm::VmOp::vjcc) {
                    vi.branch_target_insn = remap[vi.branch_target_insn];
                }
            }

            vm_insns = std::move(augmented);
        }

        // Cross-VM: if the instruction count is large enough, split into
        // two sub-VMs with independent handler tables, keys, and permutations.
        // The first sub-VM's exit jumps to the second's entry.
        constexpr size_t kCrossVmMinInsns = 8;
        const bool do_cross_vm = (vm_insns.size() >= kCrossVmMinInsns);

        if (do_cross_vm) {
            // Find a split point: midpoint, avoiding branch targets.
            size_t split = vm_insns.size() / 2;
            // Ensure we don't split inside a vjcc/vjmp sequence
            while (split > 1 && (vm_insns[split].op == vm::VmOp::vjmp ||
                                  vm_insns[split].op == vm::VmOp::vjcc)) {
                --split;
            }
            if (split < 2) split = vm_insns.size() / 2;

            // Check that no branch in the first half targets the second half
            // and vice versa — if so, fall back to single VM.
            bool can_split = true;
            for (size_t j = 0; j < split; ++j) {
                if ((vm_insns[j].op == vm::VmOp::vjmp || vm_insns[j].op == vm::VmOp::vjcc) &&
                    vm_insns[j].branch_target_insn >= split) {
                    can_split = false; break;
                }
            }
            for (size_t j = split; j < vm_insns.size(); ++j) {
                if ((vm_insns[j].op == vm::VmOp::vjmp || vm_insns[j].op == vm::VmOp::vjcc) &&
                    vm_insns[j].branch_target_insn < split) {
                    can_split = false; break;
                }
            }

            if (can_split) {
                // Remap branch targets in the second half: subtract split
                std::vector<vm::VmInstruction> part1(
                    vm_insns.begin(), vm_insns.begin() + split);
                std::vector<vm::VmInstruction> part2(
                    vm_insns.begin() + split, vm_insns.end());
                for (auto& vi : part2) {
                    if (vi.op == vm::VmOp::vjmp || vi.op == vm::VmOp::vjcc) {
                        vi.branch_target_insn -= static_cast<uint32_t>(split);
                    }
                }

                // Sub-VMs are fully independent: VM1's exit descrambles
                // its RFLAGS before popfq, VM2's entry re-scrambles after
                // pushfq. No shared vflags state required.
                auto rt1 = gen.generate(part1, rng, true);
                auto rt2 = gen.generate(part2, rng, false);

                if (rt1 && rt2) {
                    // Merge the two blobs: rt1 followed by rt2, patch the JMP
                    const uint32_t rt1_size = static_cast<uint32_t>(rt1->blob.size());
                    const uint32_t rt2_entry = rt1_size + rt2->entry_offset;

                    // Patch rt1's exit jmp rel32 to point to rt2's entry
                    if (rt1->exit_jmp_patch != 0) {
                        const uint32_t jmp_end = rt1->exit_jmp_patch + 4;
                        const int32_t rel = static_cast<int32_t>(
                            static_cast<int64_t>(rt2_entry) -
                            static_cast<int64_t>(jmp_end));
                        std::memcpy(rt1->blob.data() + rt1->exit_jmp_patch, &rel, 4);
                    }

                    ByteBuffer merged;
                    merged.reserve(rt1->blob.size() + rt2->blob.size());
                    merged.insert(merged.end(), rt1->blob.begin(), rt1->blob.end());
                    merged.insert(merged.end(), rt2->blob.begin(), rt2->blob.end());

                    PendingRegion p;
                    p.begin_marker_rva = begin_marker_rva;
                    p.body_start_rva = body_start;
                    p.body_end_rva = body_end;
                    p.total_patch_size = r->begin_marker_size + body_size + r->end_marker_size;
                    p.vm_blob = std::move(merged);
                    p.entry_offset_in_blob = rt1->entry_offset;
                    pendings.push_back(std::move(p));

                    ctx.log_fmt("  Cross-VM: split at insn {}/{}, blob1={}B blob2={}B",
                        split, vm_insns.size(), rt1->blob.size(), rt2->blob.size());
                    continue;
                }
                // fall through to single-VM if cross-VM generation failed
            }
        }

        // Single VM (no split)
        auto runtime_result = gen.generate(vm_insns, rng);
        if (!runtime_result) {
            ctx.log_fmt("  VM регион: ошибка генерации runtime: {}",
                runtime_result.error().message());
            continue;
        }

        PendingRegion p;
        p.begin_marker_rva = begin_marker_rva;
        p.body_start_rva = body_start;
        p.body_end_rva = body_end;
        p.total_patch_size = r->begin_marker_size + body_size + r->end_marker_size;
        p.vm_blob = std::move(runtime_result->blob);
        p.entry_offset_in_blob = runtime_result->entry_offset;
        pendings.push_back(std::move(p));
    }

    if (pendings.empty()) {
        ctx.log("VirtualizationPass: нет регионов для виртуализации (все пропущены)");
        return {};
    }

    // ========================================================================
    // Собираем единый .mxvm section с blob'ами, выровненными по 16 байт
    // ========================================================================
    ByteBuffer section_data;
    section_data.reserve(pendings.size() * 512);

    for (auto& p : pendings) {
        while (section_data.size() % 16 != 0) {
            section_data.push_back(0xCC);
        }
        p.blob_offset_in_section = static_cast<uint32_t>(section_data.size());
        section_data.insert(section_data.end(),
            p.vm_blob.begin(), p.vm_blob.end());
    }
    while (section_data.size() % 16 != 0) section_data.push_back(0xCC);

    constexpr uint32_t mxvm_characteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ;

    SectionManager sec_mgr(ctx.pe_image());
    auto add_result = sec_mgr.add_section(".mxvm",
        ByteView{section_data.data(), section_data.size()},
        mxvm_characteristics);
    if (!add_result) {
        return std::unexpected(add_result.error());
    }

    const uint32_t section_index = *add_result;
    const auto& mxvm_section = ctx.pe_image().sections()[section_index];
    const Rva mxvm_rva = mxvm_section.virtual_address;
    ctx.log_fmt("VirtualizationPass: секция .mxvm добавлена: RVA=0x{:08X}, "
                "размер={} байт", mxvm_rva, section_data.size());

    // ========================================================================
    // Патчим оригинальные регионы: CALL vm_entry + NOP fill
    // ========================================================================
    for (const auto& p : pendings) {
        const Rva vm_entry_rva = mxvm_rva + p.blob_offset_in_section + p.entry_offset_in_blob;

        // Секция, в которой лежит оригинальный регион
        pe::SectionInfo* text_sec = nullptr;
        for (auto& s : ctx.pe_image().sections()) {
            if (s.is_code() && s.contains_rva(p.begin_marker_rva)) {
                text_sec = &s;
                break;
            }
        }
        if (!text_sec) {
            ctx.log_fmt("  VM патч: не найдена секция для RVA 0x{:08X}",
                p.begin_marker_rva);
            continue;
        }

        const uint32_t off = p.begin_marker_rva - text_sec->virtual_address;

        // Пишем CALL vm_entry + NOP паддинг, покрывая весь регион
        // (begin marker + body + end marker)
        write_call_and_pad(
            *text_sec, off, p.total_patch_size,
            p.begin_marker_rva, vm_entry_rva);

        ctx.log_fmt("  VM патч: регион @0x{:08X} ({} байт) → CALL 0x{:08X}",
            p.begin_marker_rva, p.total_patch_size, vm_entry_rva);
    }

    // Стираем begin/end маркеры ЛЮБЫХ оставшихся регионов (если пропущенные)
    // — begin/end маркеры тех регионов, которые прошли виртуализацию, уже
    // заменены CALL+NOPs. Для пропущенных регионов маркеры всё ещё видны в
    // коде и вызывают строки "volatile uint64_t magic = ...; volatile uint8_t type = ...;"
    // которые уже отработают как мусорные переменные. Оставляем как есть.

    ctx.log_fmt("VirtualizationPass: виртуализовано {} регионов", pendings.size());
    return {};
}

} // namespace mx
