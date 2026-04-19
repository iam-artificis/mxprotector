/**
 * @file guard_collector.cpp
 * @brief Implementation of `collect_pending_guards` — see header.
 */

#include "mxprotector/protection/guard/guard_collector.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/guard/guard_page_layout.hpp"

namespace mx::guard {

namespace {

/// Size of the 5-byte `jmp rel32` that will replace each guarded
/// region — the minimum patch window a source-side `MX_GUARD_BEGIN`
/// span must provide.
constexpr uint32_t kMinPatchSize = 5;

/// Read body bytes from the source section into an owned buffer —
/// callers must NOT hold a view into `pe_image.sections()` across a
/// later `add_section` call because adding a section can relocate
/// the sections vector.
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

} // anonymous namespace

std::vector<PendingGuard> collect_pending_guards(
    ProtectionContext& ctx,
    Randomizer&        rng)
{
    std::vector<PendingGuard> result;
    uint32_t next_guard_id = 0;

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
        if (body_size + 2u * kGuardInt3TagSize > kGuardPageSize) {
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

        const uint32_t guard_id = next_guard_id;
        auto layout = build_guard_page(
            ByteView{body_bytes->data(), body_bytes->size()}, guard_id, rng);
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
        pg.guard_id                = guard_id;
        result.push_back(std::move(pg));
        ++next_guard_id;
    }

    return result;
}

} // namespace mx::guard
