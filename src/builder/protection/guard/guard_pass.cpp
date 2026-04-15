/**
 * @file guard_pass.cpp
 * @brief [BUILDER] Implementation of `GuardPass` — see guard_pass.hpp.
 */

#include "mxprotector/protection/guard/guard_pass.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"
#include "mxprotector/protection/guard/guard_page_layout.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <vector>

namespace mx {

namespace {

using guard::GuardDescriptor;
using guard::GuardPageLayout;
using guard::build_guard_page;
using guard::kGuardPageSize;

/// Raw opcode for `jmp rel32` — the 5-byte `E9 imm32` form.
constexpr uint8_t kJmpRel32Opcode = 0xE9;
constexpr uint32_t kJmpRel32Size  = 5;

/// Minimum patch size in the source section. Any guard region whose
/// `begin_marker + body + end_marker` is smaller than this cannot
/// hold the `jmp rel32` and is rejected.
constexpr uint32_t kMinPatchSize = kJmpRel32Size;

/// Intermediate per-guard record the pass carries between phases.
/// Holds the source-side info from the marker scan, the page bytes
/// built for it, and the `GuardDescriptor` that downstream commits
/// will consume via the context.
struct PendingGuard {
    uint32_t       source_section_index = 0;
    Rva            source_begin_marker_rva = 0;
    Rva            source_body_start_rva = 0;
    Rva            source_body_end_rva = 0;
    uint32_t       source_total_patch_size = 0;
    Rva            return_rva = 0;
    ByteBuffer     body_bytes;
    GuardPageLayout layout{};
    uint32_t       page_offset_in_section = 0;
};

/// Write a `jmp rel32 <target_rva>` at `offset` inside `section`,
/// then fill the rest of `[offset, offset + patch_size)` with single-
/// byte NOPs (`0x90`). `source_rva` is the RVA of the `jmp` itself.
///
/// Pre-conditions verified by the caller:
///   * `patch_size >= kJmpRel32Size`
///   * `offset + patch_size <= section.data.size()`
void write_jmp_rel32_and_pad(
    pe::SectionInfo& section,
    uint32_t         offset,
    uint32_t         patch_size,
    Rva              source_rva,
    Rva              target_rva) noexcept
{
    // jmp rel32 is computed against the end of the instruction, which
    // is `source_rva + kJmpRel32Size`.
    const auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) -
        static_cast<int64_t>(source_rva) -
        static_cast<int64_t>(kJmpRel32Size));

    section.data[offset] = kJmpRel32Opcode;
    std::memcpy(section.data.data() + offset + 1, &rel32, sizeof(rel32));
    for (uint32_t i = kJmpRel32Size; i < patch_size; ++i) {
        section.data[offset + i] = 0x90;  // NOP
    }
}

/// Patch the exit `jmp rel32` placeholder inside a guard page so it
/// points at `return_rva`. The placeholder was emitted by
/// `build_guard_page` as five zero bytes at
/// `page_offset_in_section + layout.exit_jmp_offset`.
///
/// Pre-condition: `section.data` already contains the page bytes
/// for this guard starting at `page_offset_in_section`.
void patch_exit_jump(
    pe::SectionInfo&     section,
    uint32_t             page_offset_in_section,
    const GuardPageLayout& layout,
    Rva                  page_rva,
    Rva                  return_rva) noexcept
{
    const uint32_t jmp_offset_in_section =
        page_offset_in_section + layout.exit_jmp_offset;
    const Rva jmp_rva        = page_rva + layout.exit_jmp_offset;
    const Rva jmp_end_rva    = jmp_rva + kJmpRel32Size;
    const auto rel32         = static_cast<int32_t>(
        static_cast<int64_t>(return_rva) -
        static_cast<int64_t>(jmp_end_rva));

    // Overwrite only the 4-byte rel32 slot; the `0xE9` opcode byte is
    // already in place from `build_guard_page`.
    std::memcpy(section.data.data() + jmp_offset_in_section + 1,
                &rel32, sizeof(rel32));
}

/// Read body bytes from the source section. Returns an owned
/// `ByteBuffer` so the caller does not hold a view into
/// `pe_image.sections()` across a later `add_section` call.
[[nodiscard]] MxResult<ByteBuffer> copy_body_bytes(
    const PeImage& image,
    Rva            body_start_rva,
    uint32_t       body_size)
{
    auto view = image.read_bytes(body_start_rva, body_size);
    if (!view) {
        return std::unexpected(view.error());
    }
    return ByteBuffer(view->begin(), view->end());
}

/// Walk `ctx.markers()` and collect every `guard_begin` region that
/// passes static validation. Rejected guards (empty body, too big,
/// unreadable source, patch region too small) are logged and skipped
/// rather than failing the whole pass.
[[nodiscard]] std::vector<PendingGuard> collect_pending_guards(
    ProtectionContext& ctx,
    Randomizer&        rng)
{
    std::vector<PendingGuard> result;

    for (const auto& region : ctx.markers()) {
        if (region.type != MarkerType::guard_begin) continue;

        const uint32_t body_size = region.end_rva - region.start_rva;
        const uint32_t total_patch_size =
            region.begin_marker_size + body_size + region.end_marker_size;

        if (body_size == 0) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} пустое тело, пропуск",
                region.start_rva);
            continue;
        }
        if (body_size + kJmpRel32Size > kGuardPageSize) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} тело {} байт не "
                        "помещается в одну страницу, пропуск",
                region.start_rva, body_size);
            continue;
        }
        if (total_patch_size < kMinPatchSize) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} patch-size {} < {}, "
                        "пропуск",
                region.start_rva, total_patch_size, kMinPatchSize);
            continue;
        }

        auto body_bytes = copy_body_bytes(
            ctx.pe_image(), region.start_rva, body_size);
        if (!body_bytes) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} ошибка чтения: {}",
                region.start_rva, body_bytes.error().message());
            continue;
        }

        auto layout = build_guard_page(
            ByteView{body_bytes->data(), body_bytes->size()}, rng);
        if (!layout) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} ошибка сборки "
                        "страницы: {}",
                region.start_rva, layout.error().message());
            continue;
        }

        PendingGuard pg;
        pg.source_section_index    = region.section_index;
        pg.source_begin_marker_rva = region.start_rva - region.begin_marker_size;
        pg.source_body_start_rva   = region.start_rva;
        pg.source_body_end_rva     = region.end_rva;
        pg.source_total_patch_size = total_patch_size;
        pg.return_rva              = region.end_rva + region.end_marker_size;
        pg.body_bytes              = std::move(*body_bytes);
        pg.layout                  = std::move(*layout);
        result.push_back(std::move(pg));
    }

    return result;
}

} // anonymous namespace

bool GuardPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    // Applicable only if at least one guard marker was found. The pass
    // runs silently for marker-free inputs — no empty `.mxguard`
    // section, no spurious log lines.
    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::guard_begin) return true;
    }
    return false;
}

MxStatus GuardPass::execute(ProtectionContext& ctx) {
    ctx.log("GuardPass: начало релокации MX_GUARD регионов");

    Randomizer rng;
    auto pendings = collect_pending_guards(ctx, rng);
    if (pendings.empty()) {
        ctx.log("GuardPass: нет подходящих MX_GUARD регионов, пропуск");
        return {};
    }

    ctx.log_fmt("GuardPass: собрано {} регионов к релокации", pendings.size());

    // ------------------------------------------------------------------
    // Phase 1 — concatenate every page into a single section buffer.
    // Each guard occupies exactly one `kGuardPageSize` page and the
    // pages pack back-to-back. Section alignment in PE is a multiple
    // of 4 KiB, so the first page at offset 0 IS 4 KiB-aligned and
    // subsequent pages remain aligned by construction.
    // ------------------------------------------------------------------
    ByteBuffer section_data;
    section_data.reserve(pendings.size() * kGuardPageSize);
    for (auto& pg : pendings) {
        pg.page_offset_in_section = static_cast<uint32_t>(section_data.size());
        section_data.insert(section_data.end(),
            pg.layout.bytes.begin(), pg.layout.bytes.end());
    }

    // ------------------------------------------------------------------
    // Phase 2 — inject the `.mxguard` section. Characteristics are
    // CODE + READ + EXECUTE. WRITE is deliberately NOT set: Commit 2
    // never modifies the guard pages at runtime. Commit 3 will flip
    // this to R+W+X (or toggle via NtProtect per-page) when the VEH
    // dispatcher starts encrypting and decrypting in place.
    // ------------------------------------------------------------------
    constexpr uint32_t kGuardCharacteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ;

    SectionManager sec_mgr(ctx.pe_image());
    const std::string& guard_section_name = ctx.section_names().guard;
    auto add_result = sec_mgr.add_section(
        guard_section_name,
        ByteView{section_data.data(), section_data.size()},
        kGuardCharacteristics);
    if (!add_result) {
        return std::unexpected(add_result.error());
    }

    const uint32_t guard_section_index = *add_result;
    // Re-fetch the section through the pe_image interface — the
    // section vector may have reallocated inside `add_section`, so
    // any earlier pointer into `pe_image.sections()` is stale.
    const Rva guard_section_rva =
        ctx.pe_image().sections()[guard_section_index].virtual_address;

    ctx.log_fmt("GuardPass: секция '{}' добавлена: RVA=0x{:08X}, {} байт "
                "(по странице 4KB на каждый guard)",
        guard_section_name, guard_section_rva, section_data.size());

    // ------------------------------------------------------------------
    // Phase 3 — patch every source section (`jmp rel32 <page_rva>` +
    // NOP padding) AND back-patch every page's exit jump rel32.
    //
    // Note on section lookup: `pendings[i].source_section_index` is
    // stable — `SectionManager::add_section` only appends to the
    // section vector, so pre-existing section indices do not shift.
    // ------------------------------------------------------------------
    auto& sections = ctx.pe_image().sections();
    std::vector<GuardDescriptor> descriptors;
    descriptors.reserve(pendings.size());

    uint32_t guard_id = 0;
    for (const auto& pg : pendings) {
        const Rva page_rva =
            guard_section_rva + pg.page_offset_in_section;

        // ---- Source-side: jmp into the page ----
        if (pg.source_section_index >= sections.size()) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} source_section_index "
                        "{} вне границ, пропуск",
                pg.source_body_start_rva, pg.source_section_index);
            continue;
        }
        auto& src_sec = sections[pg.source_section_index];
        if (pg.source_begin_marker_rva < src_sec.virtual_address) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} begin_rva вне секции, "
                        "пропуск",
                pg.source_body_start_rva);
            continue;
        }
        const uint32_t src_offset =
            pg.source_begin_marker_rva - src_sec.virtual_address;
        if (src_offset + pg.source_total_patch_size > src_sec.data.size()) {
            ctx.log_fmt("  GuardPass: регион @0x{:08X} patch-range вне "
                        "буфера секции, пропуск",
                pg.source_body_start_rva);
            continue;
        }
        write_jmp_rel32_and_pad(
            src_sec,
            src_offset,
            pg.source_total_patch_size,
            pg.source_begin_marker_rva,
            page_rva);

        // ---- Page-side: exit jmp rel32 → return_rva ----
        auto& guard_sec = sections[guard_section_index];
        patch_exit_jump(
            guard_sec,
            pg.page_offset_in_section,
            pg.layout,
            page_rva,
            pg.return_rva);

        GuardDescriptor d{};
        d.source_section_index    = pg.source_section_index;
        d.source_begin_marker_rva = pg.source_begin_marker_rva;
        d.source_body_start_rva   = pg.source_body_start_rva;
        d.source_body_end_rva     = pg.source_body_end_rva;
        d.source_total_patch_size = pg.source_total_patch_size;
        d.return_rva              = pg.return_rva;
        d.guard_id                = guard_id++;
        d.page_rva                = page_rva;
        d.body_offset             = pg.layout.body_offset;
        d.body_size               = pg.layout.body_size;
        descriptors.push_back(d);

        ctx.log_fmt("  GuardPass: guard #{} [RVA 0x{:08X}..0x{:08X}] "
                    "({} байт) → page 0x{:08X}, return 0x{:08X}",
            d.guard_id,
            d.source_begin_marker_rva,
            d.source_begin_marker_rva + d.source_total_patch_size,
            d.body_size,
            d.page_rva,
            d.return_rva);
    }

    ctx.log_fmt("GuardPass: релокация завершена, {} активных guard'ов",
        descriptors.size());
    // Descriptors are dropped on return for Commit 2 — later commits
    // will persist them through `ctx` so the VEH dispatcher and
    // encryption steps can consume them.
    (void)descriptors;
    return {};
}

} // namespace mx
