/**
 * @file cff_trampoline_section.cpp
 * @brief Layout + inject + patch the CFF trampoline section.
 */

#include "mxprotector/protection/cfg/cff_trampoline_section.hpp"

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/cfg/cff_relocation_fixup.hpp"
#include "mxprotector/protection/cfg/cff_trampoline_writer.hpp"

namespace mx::cff {

namespace {

constexpr uint32_t kFunctionAlignment = 16;

/// Pad `buf` with `INT 3` until its size is a multiple of `kFunctionAlignment`.
void pad_to_alignment(ByteBuffer& buf) {
    while (buf.size() % kFunctionAlignment != 0) {
        buf.push_back(asm64::kInt3);
    }
}

/// Concatenate every entry's flattened code into a single buffer,
/// recording each entry's `section_offset`. The section starts and
/// ends at a 16-byte boundary.
[[nodiscard]] ByteBuffer lay_out_trampolines(std::vector<CffTrampolineEntry>& entries) {
    ByteBuffer section_data;
    for (auto& entry : entries) {
        pad_to_alignment(section_data);
        entry.section_offset = static_cast<uint32_t>(section_data.size());
        section_data.insert(section_data.end(),
                            entry.flattened_code.begin(),
                            entry.flattened_code.end());
    }
    pad_to_alignment(section_data);
    return section_data;
}

/// Point every trampolined function's original body at its new
/// location via a 5-byte `jmp rel32` + `0xCC` padding.
void emit_all_trampolines(ProtectionContext&                     ctx,
                          const std::vector<CffTrampolineEntry>& entries,
                          Rva                                    section_rva) {
    for (const auto& entry : entries) {
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

        write_jmp_trampoline(*text_section, offset_in_text,
                             entry.original_func_size,
                             entry.original_func_rva, target_rva);

        ctx.log_fmt("CfgFlatteningPass: трамплин 0x{:08X} -> 0x{:08X} "
                    "({} -> {} байт)",
            entry.original_func_rva, target_rva,
            entry.original_func_size,
            static_cast<uint32_t>(entry.flattened_code.size()));
    }
}

} // namespace

namespace {

/// Emit CFF state labels into `ctx.trace_hints()` for every block of
/// every trampolined entry. Runs only when `--trace-hints` is on;
/// cost is a few vector pushes per state, no runtime footprint in
/// the protected PE.
///
/// `dispatcher_entry_rva` = absolute RVA where this block's bytes
///     landed in the CFF section (section_rva + entry.section_offset
///     + placement.output_offset).
/// `source_bb_rva` = original-image RVA of the block this state
///     came from, or 0 for synthesised blocks (bogus).
/// `kind` = original if the placement has a real source VA, bogus
///     otherwise. Finer predicate/mba classification is handled by
///     `add_opaque_predicate` at upstream sites.
void emit_cff_state_labels(ProtectionContext&                     ctx,
                           const std::vector<CffTrampolineEntry>& entries,
                           Rva                                    section_rva,
                           Va                                     image_base)
{
    if (!ctx.config().emit_trace_hints) return;

    auto& hints = ctx.trace_hints();

    // Section start doubles as the first entry's dispatcher entry;
    // per-state dispatcher_entry_rva below gives the handler-level
    // resolution Phase 6 metrics need.
    hints.set_cff_dispatcher(
        /* dispatcher_rva = */ section_rva,
        /* state_var_rva  = */ 0 /* register-based by default */);

    std::uint32_t state_id = 0;
    for (const auto& entry : entries) {
        for (const auto& placement : entry.block_placements) {
            const std::uint32_t dispatcher_entry_rva =
                section_rva + entry.section_offset + placement.output_offset;
            const bool is_original = placement.original_va != 0;
            const std::uint32_t source_bb_rva =
                is_original
                    ? static_cast<std::uint32_t>(placement.original_va - image_base)
                    : 0u;
            const auto kind = is_original
                ? analysis::CffStateKind::original
                : analysis::CffStateKind::bogus;
            hints.add_cff_state(state_id++, dispatcher_entry_rva,
                                source_bb_rva, kind);
        }
    }
}

} // namespace

void commit_trampoline_section(ProtectionContext&               ctx,
                               std::vector<CffTrampolineEntry>& entries)
{
    if (entries.empty()) return;

    ctx.log_fmt("CfgFlatteningPass: {} функций требуют трамплин-секцию",
        entries.size());

    auto section_data = lay_out_trampolines(entries);

    SectionManager sec_mgr(ctx.pe_image());
    pe::SectionEmitter emit{sec_mgr, ctx.layout_policy()};
    const std::string& cff_section_name = ctx.section_names().cff;
    auto add_result = emit.append_section(
        cff_section_name,
        ByteView{section_data.data(), section_data.size()},
        pe::SectionIntent{pe::SectionContentType::code,
                          pe::SectionPermissions::rx});

    if (!add_result) {
        ctx.log_fmt("CfgFlatteningPass: ошибка добавления секции: {}",
            add_result.error().message());
        return;
    }

    const uint32_t section_index = *add_result;
    auto&          mxprot_section = ctx.pe_image().sections()[section_index];
    const Rva      section_rva    = mxprot_section.virtual_address;
    const Va       image_base     = ctx.pe_image().image_base();

    ctx.log_fmt("CfgFlatteningPass: секция '{}' добавлена: RVA=0x{:08X}, "
                "размер={} байт",
        cff_section_name, section_rva, section_data.size());

    for (const auto& entry : entries) {
        apply_relocation_fixups(mxprot_section.data, entry,
                                section_rva, image_base);
    }

    emit_all_trampolines(ctx, entries, section_rva);

    // Source-linked labels for the tracing MCP. Flag-gated internally.
    emit_cff_state_labels(ctx, entries, section_rva, image_base);

    // `.pdata` handling for trampolined functions.
    //
    // Historical bug: this block used to zero out `begin_addr`,
    // `end_addr`, and `unwind_info` for every trampolined function,
    // reasoning that "the trampoline (JMP) is a leaf instruction — no
    // unwind needed." That reasoning is wrong for C++ exception
    // handling:
    //
    //   * The .pdata section is a sorted array of `RUNTIME_FUNCTION`
    //     entries. The SEH dispatcher binary-searches it by `Rip` to
    //     find unwind info for EVERY frame on the stack, not just the
    //     frame an exception is thrown from.
    //
    //   * When a protected C++ binary throws (even an internal CRT
    //     exception during startup), the unwinder walks UP the stack
    //     looking for a handler. If it ever hits a frame whose `Rip`
    //     resolves to a zeroed .pdata entry, `RtlLookupFunctionEntry`
    //     returns NULL, the walk fails, and the process terminates —
    //     usually with exit code 127, no stdout, because the crash
    //     happens inside `RtlRaiseException` before user code has a
    //     chance to print anything.
    //
    //   * `test_exception.cpp` reproduces this: before the fix it
    //     exits 127 with empty output under `-l strong`; with
    //     `--no-cfg-flattening` it runs to completion.
    //
    // Fix: leave .pdata entries intact. The original entry still
    // points at the original `.xdata` blob, which describes the
    // function's prologue in RVA-independent terms. For in-place
    // flattening that's exactly what the runtime still has at the
    // original RVA (the flattener preserves prologue bytes). For
    // trampoline mode the original RVA is now a 5-byte `jmp rel32` +
    // `0xCC` pad, which is:
    //
    //   1. Almost never reached with Rip mid-jmp (a single
    //      instruction), and
    //   2. Describes a "leaf" function the unwinder can still
    //      trivially pass through: the original xdata codes tell it
    //      how to reverse the prologue, and since the actual stack
    //      state WAS correctly set up by the flattened trampoline
    //      target before `ret` fires, the unwind math agrees.
    //
    // This fix preserves CFF's original-RVA-range semantics for the
    // unwinder without introducing any new .pdata resizing,
    // reallocation, or header surgery.
    ctx.log_fmt("CfgFlatteningPass: .pdata оставлен без изменений "
                "({} трамплин. функций) для совместимости с "
                "C++ exception unwinder",
        static_cast<uint32_t>(entries.size()));
}

} // namespace mx::cff
