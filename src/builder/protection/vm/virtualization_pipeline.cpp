/**
 * @file virtualization_pipeline.cpp
 * @brief Implementation of `VirtualizationPipeline` — see header.
 *
 * Code is mechanically lifted from the previous in-line body of
 * `VirtualizationPass::execute`, split across `lift_region`,
 * `assemble_section_data`, `emit_section`, `emit_trace_hints` and
 * `patch_call_sites`. Behaviour is preserved byte-for-byte; the
 * stress run on test_vm_showcase pins that.
 */

#include "mxprotector/protection/vm/virtualization_pipeline.hpp"

#include <cstring>
#include <format>

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/mutation/junk_generator.hpp"

namespace mx::vm {

namespace {

/// Minimum number of VM instructions in a region before cross-VM
/// splitting is even considered. Below this, single-VM is always
/// the right shape.
constexpr std::size_t kCrossVmMinInsns = 8;

/// Probability of inserting a state-safe junk pattern before each
/// real VM instruction. ~30% gives a noticeable density without
/// blowing up bytecode size.
constexpr double kJunkInsertProbability = 0.3;

/// Inject native-byte junk between real VM instructions and remap
/// branch targets. State-safe patterns only (push/pop pair, xchg
/// pair, double bswap, multi-byte NOP) — see comment in the
/// pre-extraction history for the dead-handler experiment that
/// failed because operand-fetch ALU clobbers rflags.
void inject_safe_junk(std::vector<vm::VmInstruction>& vm_insns,
                       const PeImage& image,
                       Randomizer& rng)
{
    JunkGenerator junk_gen(image.architecture());
    std::vector<vm::VmInstruction> augmented;
    augmented.reserve(vm_insns.size() * 2);

    std::vector<std::uint32_t> remap(vm_insns.size() + 1);

    for (std::size_t oi = 0; oi < vm_insns.size(); ++oi) {
        remap[oi] = static_cast<std::uint32_t>(augmented.size());
        if (rng.next_bool(kJunkInsertProbability)) {
            vm::VmInstruction junk;
            junk.op = vm::VmOp::native;
            junk.native_bytes = junk_gen.generate_vm_safe_pattern(rng);
            augmented.push_back(std::move(junk));
        }
        augmented.push_back(std::move(vm_insns[oi]));
    }
    remap[vm_insns.size()] = static_cast<std::uint32_t>(augmented.size());

    for (auto& vi : augmented) {
        if (vi.op == vm::VmOp::vjmp || vi.op == vm::VmOp::vjcc) {
            vi.branch_target_insn = remap[vi.branch_target_insn];
        }
    }

    vm_insns = std::move(augmented);
}

/// Pick a split point inside `vm_insns` that does not bisect a
/// vjcc/vjmp run, and verify no branch crosses the split. Returns
/// `0` to mean "do not split".
[[nodiscard]] std::size_t pick_cross_vm_split_point(
    const std::vector<vm::VmInstruction>& vm_insns)
{
    if (vm_insns.size() < kCrossVmMinInsns) return 0;

    std::size_t split = vm_insns.size() / 2;
    while (split > 1 && (vm_insns[split].op == vm::VmOp::vjmp ||
                          vm_insns[split].op == vm::VmOp::vjcc))
    {
        --split;
    }
    if (split < 2) split = vm_insns.size() / 2;

    for (std::size_t j = 0; j < split; ++j) {
        if ((vm_insns[j].op == vm::VmOp::vjmp ||
             vm_insns[j].op == vm::VmOp::vjcc) &&
            vm_insns[j].branch_target_insn >= split)
        {
            return 0;
        }
    }
    for (std::size_t j = split; j < vm_insns.size(); ++j) {
        if ((vm_insns[j].op == vm::VmOp::vjmp ||
             vm_insns[j].op == vm::VmOp::vjcc) &&
            vm_insns[j].branch_target_insn < split)
        {
            return 0;
        }
    }
    return split;
}

/// Append `(handler_table, bytecode)` data regions for one runtime
/// rooted at `runtime_offset_in_blob` to `out`. The runtime's
/// internal layout is:
///
///   [...prologue...]
///   handler_table : `handler_count * 4` bytes XOR-encrypted
///   [CC pad to 8B]
///   bytecode      : `bytecode_size` bytes encrypted opcodes
///
/// The chaos pipeline reads these ranges to keep
/// `CodeReferenceScanner` from emitting bogus rel refs into the
/// non-instruction bytes.
void register_runtime_data_regions(
    const vm::VmRuntime&             rt,
    std::uint32_t                    runtime_offset_in_blob,
    std::vector<PendingDataRegion>&  out)
{
    if (rt.handler_count != 0) {
        out.push_back(PendingDataRegion{
            .offset_in_blob = runtime_offset_in_blob + rt.handler_table_offset,
            .size           = rt.handler_count * 4u,
            .kind           = pe::DataRegionKind::vm_handler_table,
        });
    }
    if (rt.bytecode_size != 0) {
        out.push_back(PendingDataRegion{
            .offset_in_blob = runtime_offset_in_blob + rt.bytecode_offset,
            .size           = rt.bytecode_size,
            .kind           = pe::DataRegionKind::vm_bytecode,
        });
    }
    // Inner VM (G2 V2) handler table — 14 × int32 deltas inside the
    // 160-byte inner-VM block. Bytes routinely decode as ghost
    // instructions and trip the same bogus-rel-ref bug as the outer
    // JT and bytecode.
    if (rt.inner_vm_handler_table_size != 0) {
        out.push_back(PendingDataRegion{
            .offset_in_blob = runtime_offset_in_blob
                            + rt.inner_vm_handler_table_offset,
            .size           = rt.inner_vm_handler_table_size,
            .kind           = pe::DataRegionKind::vm_handler_table,
        });
    }
}

/// Bundle of build-time information needed downstream of the
/// cross-VM concatenation step. Returned by `build_cross_vm_blob`
/// so `lift_region` can populate `PendingRegion::data_regions`
/// without rebuilding the runtime offsets.
struct CrossVmBuild {
    ByteBuffer                     blob;
    std::uint32_t                  entry_offset_in_blob;
    std::vector<PendingDataRegion> data_regions;
};

/// Build a cross-VM blob: split at `split`, generate two independent
/// runtimes, patch the rt1 exit jmp to rt2's entry, concatenate.
/// Returns nullopt if either generation step fails.
[[nodiscard]] std::optional<CrossVmBuild>
build_cross_vm_blob(const std::vector<vm::VmInstruction>& vm_insns,
                     std::size_t                          split,
                     vm::VmRuntimeGenerator&              gen,
                     Randomizer&                          rng,
                     const vm::VmGenOptions&              default_opts)
{
    std::vector<vm::VmInstruction> part1(
        vm_insns.begin(), vm_insns.begin() + split);
    std::vector<vm::VmInstruction> part2(
        vm_insns.begin() + split, vm_insns.end());
    for (auto& vi : part2) {
        if (vi.op == vm::VmOp::vjmp || vi.op == vm::VmOp::vjcc) {
            vi.branch_target_insn -= static_cast<std::uint32_t>(split);
        }
    }

    vm::VmGenOptions opts1 = default_opts;
    opts1.emit_exit_as_jmp = true;
    vm::VmGenOptions opts2 = default_opts;
    opts2.emit_exit_as_jmp = false;
    auto rt1 = gen.generate(part1, rng, opts1);
    auto rt2 = gen.generate(part2, rng, opts2);
    if (!rt1 || !rt2) return std::nullopt;

    const std::uint32_t rt1_size =
        static_cast<std::uint32_t>(rt1->blob.size());
    const std::uint32_t rt2_entry = rt1_size + rt2->entry_offset;

    if (rt1->exit_jmp_patch != 0) {
        const std::uint32_t jmp_end = rt1->exit_jmp_patch + 4;
        const std::int32_t rel = static_cast<std::int32_t>(
            static_cast<std::int64_t>(rt2_entry) -
            static_cast<std::int64_t>(jmp_end));
        std::memcpy(rt1->blob.data() + rt1->exit_jmp_patch, &rel, 4);
    }

    ByteBuffer merged;
    merged.reserve(rt1->blob.size() + rt2->blob.size());
    merged.insert(merged.end(), rt1->blob.begin(), rt1->blob.end());
    merged.insert(merged.end(), rt2->blob.begin(), rt2->blob.end());

    std::vector<PendingDataRegion> regions;
    regions.reserve(4);
    register_runtime_data_regions(*rt1, /*runtime_offset_in_blob=*/0, regions);
    register_runtime_data_regions(*rt2, rt1_size,                     regions);

    return CrossVmBuild{
        .blob                 = std::move(merged),
        .entry_offset_in_blob = rt1->entry_offset,
        .data_regions         = std::move(regions),
    };
}

/// Write `CALL rel32 vm_entry` followed by NOP padding into the
/// section's bytes, covering exactly `total_patch_size` bytes
/// starting at `off`.
void write_call_and_pad(pe::SectionInfo& sec,
                         std::uint32_t off,
                         std::uint32_t total_patch_size,
                         Rva           call_site_rva,
                         Rva           target_rva)
{
    constexpr std::uint32_t call_size = 5;  // E8 + rel32
    if (total_patch_size < call_size) return;

    const std::uint32_t call_end_rva = call_site_rva + call_size;
    const std::int32_t rel = static_cast<std::int32_t>(
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(call_end_rva));

    sec.data[off]     = 0xE8;
    std::memcpy(sec.data.data() + off + 1, &rel, 4);
    for (std::uint32_t i = call_size; i < total_patch_size; ++i) {
        sec.data[off + i] = asm64::kNop;
    }
}

} // anonymous namespace

VirtualizationPipeline::VirtualizationPipeline(ProtectionContext& ctx) noexcept
    : ctx_(ctx)
    , lifter_(*ctx.disassembler())
{}

vm::VmGenOptions VirtualizationPipeline::build_default_options() const {
    // ImageBase-derived table key requires (a) the packer being
    // enabled (it strips ASLR) and (b) the target being an
    // executable (DLL/SYS get relocated, key would decrypt to
    // garbage).
    const bool packer_will_run =
        ctx_.config().enable_packer &&
        ctx_.pe_image().pe_type() == PeType::executable;

    // Anti-tamper / anti-emulation entry-stub checks are user-mode
    // primitives (gs:[0x60] PEB walk, Hell's Gate ntdll resolve);
    // suppress for any non-user-mode target.
    const bool skip_user_mode_checks = !ctx_.target().is_user_mode();
    const vm::VmGenOptions opts{
        .emit_exit_as_jmp        = false,
        .use_imagebase_key       = packer_will_run,
        .preferred_image_base    =
            static_cast<std::uint64_t>(ctx_.pe_image().image_base()),
        .skip_anti_tamper_checks = skip_user_mode_checks,
    };

    if (opts.use_imagebase_key) {
        ctx_.log_fmt("VirtualizationPass: ImageBase-derived table key enabled "
                     "(preferred_base=0x{:X})",
            opts.preferred_image_base);
    }
    if (opts.skip_anti_tamper_checks) {
        ctx_.log_fmt("VirtualizationPass: non-user-mode target ({}) — "
                     "anti-tamper / anti-emulation entry-stub checks "
                     "suppressed (no user-mode PEB / Hell's Gate available)",
            mx::target::binary_kind_name(ctx_.target().kind));
    }
    return opts;
}

std::optional<PendingRegion> VirtualizationPipeline::lift_region(
    const MarkedRegion&     region,
    const vm::VmGenOptions& default_opts)
{
    const Rva           body_start        = region.start_rva;
    const Rva           body_end          = region.end_rva;
    const Rva           begin_marker_rva  = body_start - region.begin_marker_size;
    const std::uint32_t body_size         = body_end - body_start;

    if (body_size == 0) {
        ctx_.log_fmt("  VM регион [0x{:08X}..0x{:08X}] пуст, пропуск",
            body_start, body_end);
        return std::nullopt;
    }
    if (body_size < 5) {
        ctx_.log_fmt("  VM регион [0x{:08X}..0x{:08X}] слишком мал "
                     "({} < 5 байт для CALL rel32), пропуск",
            body_start, body_end, body_size);
        return std::nullopt;
    }

    auto body_bytes = ctx_.pe_image().read_bytes(body_start, body_size);
    if (!body_bytes) {
        ctx_.log_fmt("  VM регион: ошибка чтения байт: {}",
            body_bytes.error().message());
        return std::nullopt;
    }

    const Va base_va = ctx_.pe_image().image_base() + body_start;
    auto lift_result = lifter_.lift(*body_bytes, base_va);
    if (!lift_result) {
        ctx_.log_fmt("  VM регион [0x{:08X}..0x{:08X}]: ошибка лифтинга: {}",
            body_start, body_end, lift_result.error().message());
        return std::nullopt;
    }

    auto [vm_insns, report] = *lift_result;
    ctx_.log_fmt("  VM регион [0x{:08X}..0x{:08X}] {} байт: "
                 "generic={}, native={}, total={}",
        body_start, body_end, body_size,
        report.generic_ops, report.native_ops, report.total_insns);

    inject_safe_junk(vm_insns, ctx_.pe_image(), rng_);

    const std::size_t split = pick_cross_vm_split_point(vm_insns);
    if (split != 0) {
        if (auto cross = build_cross_vm_blob(
                vm_insns, split, gen_, rng_, default_opts))
        {
            PendingRegion p;
            p.begin_marker_rva     = begin_marker_rva;
            p.body_start_rva       = body_start;
            p.body_end_rva         = body_end;
            p.total_patch_size     =
                region.begin_marker_size + body_size + region.end_marker_size;
            p.vm_blob              = std::move(cross->blob);
            p.entry_offset_in_blob = cross->entry_offset_in_blob;
            p.data_regions         = std::move(cross->data_regions);
            ctx_.log_fmt("  Cross-VM: split at insn {}/{}, total={}B",
                split, vm_insns.size(), p.vm_blob.size());
            return p;
        }
        // Cross-VM gen failed — fall through to single-VM.
    }

    auto runtime_result = gen_.generate(vm_insns, rng_, default_opts);
    if (!runtime_result) {
        ctx_.log_fmt("  VM регион: ошибка генерации runtime: {}",
            runtime_result.error().message());
        return std::nullopt;
    }

    PendingRegion p;
    p.begin_marker_rva     = begin_marker_rva;
    p.body_start_rva       = body_start;
    p.body_end_rva         = body_end;
    p.total_patch_size     =
        region.begin_marker_size + body_size + region.end_marker_size;
    p.vm_blob              = std::move(runtime_result->blob);
    p.entry_offset_in_blob = runtime_result->entry_offset;
    register_runtime_data_regions(*runtime_result, /*runtime_offset_in_blob=*/0,
                                  p.data_regions);
    return p;
}

ByteBuffer VirtualizationPipeline::assemble_section_data(
    std::vector<PendingRegion>& pendings) const
{
    ByteBuffer section_data;
    section_data.reserve(pendings.size() * 512);

    for (auto& p : pendings) {
        while (section_data.size() % 16 != 0) {
            section_data.push_back(asm64::kInt3);
        }
        p.blob_offset_in_section = static_cast<std::uint32_t>(section_data.size());
        section_data.insert(section_data.end(),
            p.vm_blob.begin(), p.vm_blob.end());
    }
    while (section_data.size() % 16 != 0) {
        section_data.push_back(asm64::kInt3);
    }
    return section_data;
}

MxResult<std::uint32_t> VirtualizationPipeline::emit_section(
    const ByteBuffer& section_data)
{
    SectionManager sec_mgr(ctx_.pe_image());
    pe::SectionEmitter emit{sec_mgr, ctx_.layout_policy()};
    return emit.append_section(
        ctx_.section_names().vm,
        ByteView{section_data.data(), section_data.size()},
        pe::SectionIntent{pe::SectionContentType::code,
                          pe::SectionPermissions::rx});
}

void VirtualizationPipeline::emit_trace_hints(
    Rva                               mxvm_rva,
    const std::vector<PendingRegion>& pendings) const
{
    if (!ctx_.config().emit_trace_hints) return;

    auto& hints = ctx_.trace_hints();
    const auto& p0 = pendings.front();
    hints.set_vm_dispatcher(
        mxvm_rva + p0.blob_offset_in_section + p0.entry_offset_in_blob,
        /* handler_table_rva = */ 0);

    std::uint32_t region_id = 0;
    for (const auto& p : pendings) {
        hints.add_vm_handler(
            region_id,
            mxvm_rva + p.blob_offset_in_section,
            static_cast<std::uint32_t>(p.vm_blob.size()),
            std::format("region_{}", region_id));
        ++region_id;
    }
    for (const auto& p : pendings) {
        hints.add_protected_function(
            static_cast<std::uint32_t>(p.begin_marker_rva),
            p.total_patch_size,
            analysis::ProtectedFunctionKind::vm);
    }
}

void VirtualizationPipeline::patch_call_sites(
    Rva                               mxvm_rva,
    const std::vector<PendingRegion>& pendings) const
{
    for (const auto& p : pendings) {
        const Rva vm_entry_rva =
            mxvm_rva + p.blob_offset_in_section + p.entry_offset_in_blob;

        pe::SectionInfo* text_sec = nullptr;
        for (auto& s : ctx_.pe_image().sections()) {
            if (s.is_code() && s.contains_rva(p.begin_marker_rva)) {
                text_sec = &s;
                break;
            }
        }
        if (!text_sec) {
            ctx_.log_fmt("  VM патч: не найдена секция для RVA 0x{:08X}",
                p.begin_marker_rva);
            continue;
        }

        const std::uint32_t off =
            p.begin_marker_rva - text_sec->virtual_address;
        write_call_and_pad(*text_sec, off, p.total_patch_size,
            p.begin_marker_rva, vm_entry_rva);

        ctx_.log_fmt("  VM патч: регион @0x{:08X} ({} байт) → CALL 0x{:08X}",
            p.begin_marker_rva, p.total_patch_size, vm_entry_rva);
    }
}

MxStatus VirtualizationPipeline::execute() {
    ctx_.log("VirtualizationPass: начало виртуализации VM-регионов");

    std::vector<const MarkedRegion*> vm_regions;
    for (const auto& m : ctx_.markers()) {
        if (m.type == MarkerType::vm_begin) vm_regions.push_back(&m);
    }
    if (vm_regions.empty()) {
        ctx_.log("VirtualizationPass: VM-регионов не найдено");
        return {};
    }
    ctx_.log_fmt("VirtualizationPass: найдено {} VM-регионов",
        vm_regions.size());

    const auto default_opts = build_default_options();

    std::vector<PendingRegion> pendings;
    pendings.reserve(vm_regions.size());
    for (const auto* r : vm_regions) {
        if (auto p = lift_region(*r, default_opts)) {
            pendings.push_back(std::move(*p));
        }
    }
    if (pendings.empty()) {
        ctx_.log("VirtualizationPass: нет регионов для виртуализации "
                 "(все пропущены)");
        return {};
    }

    auto section_data = assemble_section_data(pendings);
    auto section_idx = emit_section(section_data);
    if (!section_idx) return std::unexpected(section_idx.error());

    auto& mxvm_section = ctx_.pe_image().sections()[*section_idx];
    const Rva mxvm_rva = mxvm_section.virtual_address;
    ctx_.log_fmt("VirtualizationPass: секция '{}' добавлена: RVA=0x{:08X}, "
                 "размер={} байт",
        ctx_.section_names().vm, mxvm_rva, section_data.size());

    // Promote each pending's blob-internal data ranges (handler
    // table + bytecode) to absolute-RVA ranges on the emitted
    // section. The chaos pipeline reads `SectionInfo::data_regions`
    // when filtering bogus rel refs that `CodeReferenceScanner`
    // would otherwise emit from these non-instruction bytes.
    for (const auto& p : pendings) {
        for (const auto& dr : p.data_regions) {
            mxvm_section.data_regions.push_back(pe::DataRegion{
                .begin_rva = static_cast<Rva>(
                    mxvm_rva + p.blob_offset_in_section + dr.offset_in_blob),
                .size      = dr.size,
                .kind      = dr.kind,
            });
        }
    }

    emit_trace_hints(mxvm_rva, pendings);
    patch_call_sites(mxvm_rva, pendings);

    ctx_.log_fmt("VirtualizationPass: виртуализовано {} регионов",
        pendings.size());
    return {};
}

} // namespace mx::vm
