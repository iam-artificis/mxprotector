/**
 * @file guard_pass.cpp
 * @brief [BUILDER] Implementation of `GuardPass` — see guard_pass.hpp.
 *
 * Commit 3a brings the full VEH infrastructure online. The section
 * layout produced by `GuardPass` is now:
 *
 * ```
 *     [guard_page_0]          kGuardPageSize bytes  ┐
 *     [guard_page_1]          kGuardPageSize bytes  │  N pages
 *     ...                                            │  (one per MX_GUARD pair)
 *     [guard_page_{N-1}]      kGuardPageSize bytes  ┘
 *     [descriptor_table]      N × 16 bytes           ← VEH input
 *     [veh_handler]           ~125 bytes             ← installed by TLS thunk
 *     [tls_installer]         ~180 bytes             ← registered via ctx
 * ```
 *
 * The descriptor table is the single source of truth for which
 * int3 addresses correspond to which guards. Entries contain:
 *
 * ```
 *     +0x00  uint32  entry_int3_rva
 *     +0x04  uint32  exit_int3_rva
 *     +0x08  uint32  body_start_rva
 *     +0x0C  uint32  return_rva
 * ```
 *
 * The `guard_tls_installer` gets its absolute VA (image_base +
 * installer_rva) stored into `ctx.extra_tls_callback_va`. When
 * `PackerPass::execute` later builds its own TLS callback array it
 * reads this field and appends the installer to the array, ensuring
 * the VEH gets registered at `DLL_PROCESS_ATTACH` before any guarded
 * code executes.
 *
 * Failure modes are identical to Commit 2 — each guard is processed
 * independently and a failure for any one guard results in a logged
 * warning and a skipped entry rather than a pipeline-wide error.
 */

#include "mxprotector/protection/guard/guard_pass.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"
#include "mxprotector/protection/guard/guard_page_layout.hpp"
#include "mxprotector/protection/guard/guard_tls_installer.hpp"
#include "mxprotector/protection/guard/guard_veh_emitter.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"  // fnv1a_32

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <vector>

namespace mx {

namespace {

using guard::GuardDescriptor;
using guard::GuardPageLayout;
using guard::GuardTlsInstallerEmit;
using guard::GuardVehEmit;
using guard::build_guard_page;
using guard::emit_guard_tls_installer;
using guard::emit_guard_veh_handler;
using guard::kGuardDescriptorStride;
using guard::kGuardInt3TagSize;
using guard::kGuardPageSize;

/// Opcode + size for the source-side `jmp rel32 <page>` patch that
/// replaces each guarded region in .text.
constexpr uint8_t  kJmpRel32Opcode = 0xE9;
constexpr uint32_t kJmpRel32Size   = 5;

/// Minimum source-side patch window — anything smaller cannot hold
/// the `jmp rel32` and is rejected.
constexpr uint32_t kMinPatchSize = kJmpRel32Size;

/// Intermediate per-guard record the pass carries between phases.
/// Populated during collection, consumed during section assembly
/// and patching.
struct PendingGuard {
    uint32_t       source_section_index = 0;
    Rva            source_begin_marker_rva = 0;
    Rva            source_body_start_rva = 0;
    Rva            source_body_end_rva = 0;
    uint32_t       source_total_patch_size = 0;
    Rva            return_rva = 0;
    ByteBuffer     body_bytes;
    GuardPageLayout layout{};
    uint32_t       guard_id = 0;
    uint32_t       page_offset_in_section = 0;
};

/// Little-endian helpers — the packer uses `byte_io.hpp` for these
/// but guard code lives in its own module, so we inline the two
/// one-liners rather than grow the include surface.
void write_u32_le(ByteBuffer& buf, uint32_t offset, uint32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

void write_i32_le(ByteBuffer& buf, uint32_t offset, int32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// Write `jmp rel32 <target>` at `offset`, pad the rest with NOPs.
///
/// Pre-conditions (caller-verified):
///   * `patch_size >= kMinPatchSize`
///   * `offset + patch_size <= section.data.size()`
void write_jmp_rel32_and_pad(
    pe::SectionInfo& section,
    uint32_t         offset,
    uint32_t         patch_size,
    Rva              source_rva,
    Rva              target_rva) noexcept
{
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

/// Read body bytes from the source section into an owned buffer —
/// the caller must NOT hold a view into pe_image.sections() across
/// a later `add_section` call because adding a section can relocate
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

/// Walk `ctx.markers()` and collect every `guard_begin` region that
/// passes static validation. Each accepted guard gets a dense,
/// 0-based `guard_id` in marker order.
[[nodiscard]] std::vector<PendingGuard> collect_pending_guards(
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

} // anonymous namespace

bool GuardPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::guard_begin) return true;
    }
    return false;
}

MxStatus GuardPass::execute(ProtectionContext& ctx) {
    ctx.log("GuardPass: начало релокации MX_GUARD регионов");

    // The runtime-guards subsystem depends on the packer stub's TLS
    // callback inheritance path to register the VEH install thunk.
    // Without a packer stub the callback is never wired up, the VEH
    // never runs, and the first guard int3 crashes the process.
    // Fail early with a clear message so the user can fix the
    // config rather than debug a mystery crash.
    if (!ctx.config().enable_packer) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::pass_failed),
            "GuardPass: MX_GUARD требует --packer (VEH инсталлируется "
            "через TLS callback в packer stub)"});
    }

    Randomizer rng;
    auto pendings = collect_pending_guards(ctx, rng);
    if (pendings.empty()) {
        ctx.log("GuardPass: нет подходящих MX_GUARD регионов, пропуск");
        return {};
    }
    ctx.log_fmt("GuardPass: собрано {} регионов к релокации", pendings.size());

    // ------------------------------------------------------------------
    // Phase 1 — concatenate every guard page into the section buffer.
    // Each page is kGuardPageSize bytes; since the PE section
    // alignment is a multiple of that, the first page at offset 0 is
    // naturally page-aligned and every subsequent page stays aligned.
    // ------------------------------------------------------------------
    ByteBuffer section_data;
    section_data.reserve(pendings.size() * kGuardPageSize + 512);
    for (auto& pg : pendings) {
        pg.page_offset_in_section = static_cast<uint32_t>(section_data.size());
        section_data.insert(section_data.end(),
            pg.layout.bytes.begin(), pg.layout.bytes.end());
    }

    // ------------------------------------------------------------------
    // Phase 2 — descriptor table.
    //
    // The VEH handler linearly scans this table on every int3 fault,
    // so its layout is a hard contract: 16 bytes per descriptor,
    // fields in the exact order the handler's `cmp [rsi + N]` /
    // `mov eax, [rsi + N]` bytes hard-code.
    // ------------------------------------------------------------------
    const uint32_t descriptor_table_offset =
        static_cast<uint32_t>(section_data.size());
    const uint32_t descriptor_count =
        static_cast<uint32_t>(pendings.size());
    section_data.resize(
        descriptor_table_offset + descriptor_count * kGuardDescriptorStride);

    // ------------------------------------------------------------------
    // Phase 3 — VEH handler body + TLS installer thunk. Both get
    // appended after the descriptor table so Phase 6 below can
    // back-patch all their rel32/imm32 slots with final RVAs.
    // ------------------------------------------------------------------
    const uint32_t veh_handler_offset =
        static_cast<uint32_t>(section_data.size());
    GuardVehEmit veh_patches{};
    {
        RawEmitter tmp{};
        veh_patches = emit_guard_veh_handler(tmp, rng);
        section_data.insert(section_data.end(),
            tmp.buf.begin(), tmp.buf.end());
    }

    const uint32_t tls_installer_offset =
        static_cast<uint32_t>(section_data.size());
    GuardTlsInstallerEmit tls_patches{};
    {
        RawEmitter tmp{};
        tls_patches = emit_guard_tls_installer(tmp, rng);
        section_data.insert(section_data.end(),
            tmp.buf.begin(), tmp.buf.end());
    }

    // ------------------------------------------------------------------
    // Phase 4 — inject the .mxguard section.
    //
    // R + W + X characteristics. The WRITE bit is required because
    // the VEH decrypts and re-encrypts guard bodies in place at
    // runtime (Commit 3b). Going through `NtProtectVirtualMemory`
    // to toggle W per-call was the cleaner alternative on paper but
    // would need a cached syscall pointer in a writable scratch
    // slot — which itself needs a writable section. Baking W into
    // .mxguard at build time is simpler, matches .mxpack's existing
    // R+W+X layout, and avoids a second "small writable tail
    // section" fingerprint.
    // ------------------------------------------------------------------
    constexpr uint32_t kGuardCharacteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ |
        pe::IMAGE_SCN_MEM_WRITE;

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
    const Rva guard_section_rva =
        ctx.pe_image().sections()[guard_section_index].virtual_address;

    ctx.log_fmt("GuardPass: секция '{}' добавлена: RVA=0x{:08X}, {} байт "
                "(pages={}, descriptor_count={}, veh@0x{:X}, tls_install@0x{:X})",
        guard_section_name,
        guard_section_rva,
        section_data.size(),
        pendings.size(),
        descriptor_count,
        guard_section_rva + veh_handler_offset,
        guard_section_rva + tls_installer_offset);

    // Compute absolute section RVAs for downstream patching.
    const Rva descriptor_table_rva = guard_section_rva + descriptor_table_offset;
    const Rva veh_handler_rva      = guard_section_rva + veh_handler_offset;
    const Rva tls_installer_rva    = guard_section_rva + tls_installer_offset;

    // ------------------------------------------------------------------
    // Phase 5 — per-guard: finalise descriptor, patch source section,
    // write descriptor table entry.
    // ------------------------------------------------------------------
    auto& sections = ctx.pe_image().sections();
    auto& guard_section = sections[guard_section_index];

    std::vector<GuardDescriptor> descriptors;
    descriptors.reserve(pendings.size());

    for (const auto& pg : pendings) {
        const Rva page_rva =
            guard_section_rva + pg.page_offset_in_section;
        const Rva entry_int3_rva = page_rva + pg.layout.entry_int3_offset;
        const Rva body_start_rva = page_rva + pg.layout.body_offset;
        const Rva exit_int3_rva  = page_rva + pg.layout.exit_int3_offset;

        // ---- Source-side jmp patching ----
        if (pg.source_section_index >= sections.size()) {
            ctx.log_fmt("  GuardPass: guard #{} source_section_index {} "
                        "вне границ, пропуск",
                pg.guard_id, pg.source_section_index);
            continue;
        }
        auto& src_sec = sections[pg.source_section_index];
        if (pg.source_begin_marker_rva < src_sec.virtual_address) {
            ctx.log_fmt("  GuardPass: guard #{} begin_rva вне секции, "
                        "пропуск",
                pg.guard_id);
            continue;
        }
        const uint32_t src_offset =
            pg.source_begin_marker_rva - src_sec.virtual_address;
        if (src_offset + pg.source_total_patch_size > src_sec.data.size()) {
            ctx.log_fmt("  GuardPass: guard #{} patch-range вне буфера, "
                        "пропуск",
                pg.guard_id);
            continue;
        }
        write_jmp_rel32_and_pad(
            src_sec,
            src_offset,
            pg.source_total_patch_size,
            pg.source_begin_marker_rva,
            entry_int3_rva);

        // ---- Descriptor table entry ----
        //
        // The 64-byte descriptor layout must match the offsets the
        // VEH handler's emitted byte stream bakes in:
        //
        //   +0x00  entry_int3_rva           (walked by cmp [rsi])
        //   +0x04  exit_int3_rva            (walked by cmp [rsi+4])
        //   +0x08  body_start_rva           (loaded by mov eax, [rsi+8])
        //   +0x0C  return_rva               (loaded by mov eax, [rsi+12])
        //   +0x10  body_size                (loaded by mov ecx, [rsi+0x10])
        //   +0x14  open_count = 0           (LOCK XADD target)
        //   +0x18..+0x38  per-guard XOR key (indexed by [rsi+r9+0x18])
        //   +0x38..+0x40  reserved (zero)
        //
        // The key is generated fresh per guard from the same
        // randomiser the page layout uses. Every guard gets its
        // own 32 random bytes — two guards never share a key, so
        // leaking one body's plaintext does not compromise any
        // other body.
        const uint32_t entry_offset_in_section =
            descriptor_table_offset + pg.guard_id * kGuardDescriptorStride;

        // --- RVAs + sizes ---
        write_u32_le(guard_section.data, entry_offset_in_section + 0x00,
                     entry_int3_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x04,
                     exit_int3_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x08,
                     body_start_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x0C,
                     pg.return_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x10,
                     pg.layout.body_size);
        // open_count is already zero from the initial resize of
        // section_data, but be explicit for auditability.
        write_u32_le(guard_section.data, entry_offset_in_section + 0x14, 0);

        // --- Per-guard key ---
        std::array<uint8_t, guard::kGuardDescriptorKeySize> key{};
        for (auto& b : key) b = rng.next_u8();
        std::memcpy(
            guard_section.data.data()
                + entry_offset_in_section + guard::kGuardDescriptorKeyOffset,
            key.data(),
            key.size());

        // --- XOR-encrypt body bytes in place ---
        //
        // The body currently sits at [page_offset + body_offset ..
        // page_offset + body_offset + body_size) as plaintext (it
        // was written verbatim by build_guard_page). Encrypt it in
        // place with the freshly-generated key so that the dump-on-
        // disk `.mxguard` section shows ciphertext for every guard
        // body; the VEH decrypts on entry and re-encrypts on exit
        // via the same XOR pass (XOR is self-inverse).
        //
        // The int3+tag windows at [page_offset + 0..5) and
        // [page_offset + body_offset + body_size..
        //    + body_offset + body_size + 5) are deliberately NOT
        // touched — they are the plaintext "skip windows" the CPU
        // needs to execute to raise STATUS_BREAKPOINT.
        {
            const uint32_t body_start_in_section =
                pg.page_offset_in_section + pg.layout.body_offset;
            for (uint32_t i = 0; i < pg.layout.body_size; ++i) {
                guard_section.data[body_start_in_section + i] ^=
                    key[i % guard::kGuardDescriptorKeySize];
            }
        }

        GuardDescriptor d{};
        d.source_section_index    = pg.source_section_index;
        d.source_begin_marker_rva = pg.source_begin_marker_rva;
        d.source_body_start_rva   = pg.source_body_start_rva;
        d.source_body_end_rva     = pg.source_body_end_rva;
        d.source_total_patch_size = pg.source_total_patch_size;
        d.return_rva              = pg.return_rva;
        d.guard_id                = pg.guard_id;
        d.page_rva                = page_rva;
        d.body_offset             = pg.layout.body_offset;
        d.body_size               = pg.layout.body_size;
        d.entry_int3_rva          = entry_int3_rva;
        d.exit_int3_rva           = exit_int3_rva;
        d.body_start_rva          = body_start_rva;
        descriptors.push_back(d);

        ctx.log_fmt("  GuardPass: guard #{} [RVA 0x{:08X}..0x{:08X}] "
                    "({} байт) → page 0x{:08X}, body 0x{:08X}, "
                    "exit 0x{:08X}, return 0x{:08X}",
            d.guard_id,
            d.source_begin_marker_rva,
            d.source_begin_marker_rva + d.source_total_patch_size,
            d.body_size,
            d.page_rva,
            d.body_start_rva,
            d.exit_int3_rva,
            d.return_rva);
    }

    // ------------------------------------------------------------------
    // Phase 6 — patch the VEH handler and TLS installer with final
    // RVAs.
    //
    // module_base sub imm32 = the RVA of the byte right after the
    //   handler's rip-relative `lea rbx, [rip + 0]`. Subtracting
    //   this value from that rip yields zero (= module_base delta
    //   for position-independent handler code).
    // descriptor table rel32 = offset from end-of-lea to table start.
    // descriptor count imm32 = total number of descriptors we wrote.
    // handler rel32 inside TLS installer = offset from end-of-lea to
    //   handler start, both inside the .mxguard section.
    // ------------------------------------------------------------------
    {
        // VEH: module_base sub imm32
        const uint32_t module_base_anchor_rva =
            veh_handler_rva + veh_patches.module_base_lea_anchor_offset;
        write_i32_le(
            guard_section.data,
            veh_handler_offset + veh_patches.module_base_sub_imm32_offset,
            static_cast<int32_t>(module_base_anchor_rva));

        // VEH: descriptor table rel32
        const Rva veh_rel32_end_rva =
            veh_handler_rva + veh_patches.descriptor_table_rel32_end_offset;
        const int32_t table_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(descriptor_table_rva) -
            static_cast<int64_t>(veh_rel32_end_rva));
        write_i32_le(
            guard_section.data,
            veh_handler_offset + veh_patches.descriptor_table_rel32_offset,
            table_rel32);

        // VEH: descriptor count imm32
        write_u32_le(
            guard_section.data,
            veh_handler_offset + veh_patches.descriptor_count_imm32_offset,
            static_cast<uint32_t>(descriptors.size()));

        // TLS installer: handler rel32 (offset within .mxguard)
        const uint32_t tls_rel32_end_in_section =
            tls_installer_offset + tls_patches.handler_rel32_end_offset;
        const int32_t handler_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(veh_handler_offset) -
            static_cast<int64_t>(tls_rel32_end_in_section));
        write_i32_le(
            guard_section.data,
            tls_installer_offset + tls_patches.handler_rel32_offset,
            handler_rel32);

        // --- Commit 6: self-CRC over the VEH handler bytes ---
        //
        // The TLS installer walks the handler byte-range at runtime
        // and computes fnv1a_32 over it, comparing against a
        // build-time-baked expected value. The expected value is
        // fnv1a_32(handler_bytes, handler_size) computed RIGHT HERE
        // (after all VEH patches have been applied: module_base
        // imm32, descriptor table rel32, descriptor count imm32).
        // Any runtime patch applied between PE mapping and TLS
        // callback execution shifts the hash and causes the
        // installer to silently skip AVEH, leaving the VEH
        // unregistered — the first guard int3 then terminates the
        // process.
        //
        // The handler size is fixed per build (emitter output
        // length), so we compute it from `veh_handler_offset` and
        // `tls_installer_offset`. Not perfectly tight if future
        // commits append bytes between handler and installer, but
        // good enough here because emission is dense.
        const uint32_t veh_handler_size =
            tls_installer_offset - veh_handler_offset;

        const uint32_t handler_crc = packer::fnv1a_32(
            ByteView{
                guard_section.data.data() + veh_handler_offset,
                veh_handler_size});

        // crc_walk_rel32: same target as handler_rel32 but from a
        // different lea, so the delta is different.
        const uint32_t crc_walk_rel32_end_in_section =
            tls_installer_offset + tls_patches.crc_walk_rel32_end_offset;
        const int32_t crc_walk_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(veh_handler_offset) -
            static_cast<int64_t>(crc_walk_rel32_end_in_section));
        write_i32_le(
            guard_section.data,
            tls_installer_offset + tls_patches.crc_walk_rel32_offset,
            crc_walk_rel32);

        // crc_size_imm32: total byte count to walk.
        write_u32_le(
            guard_section.data,
            tls_installer_offset + tls_patches.crc_size_imm32_offset,
            veh_handler_size);

        // crc_expected_imm32: fnv1a_32 of the handler bytes as they
        // exist RIGHT NOW. Any future write to the handler range
        // must happen BEFORE this point or the stored value will be
        // stale. Commits 4-5 and this one are the final writes;
        // commit 7's polymorphism adds a random tail AFTER this
        // point in the emission phase, which is why the tail lives
        // at a higher file offset than veh_handler_offset +
        // veh_handler_size and is excluded from the CRC walk.
        write_u32_le(
            guard_section.data,
            tls_installer_offset + tls_patches.crc_expected_imm32_offset,
            handler_crc);

        ctx.log_fmt("GuardPass: VEH handler CRC = 0x{:08X} "
                    "over {} bytes @ 0x{:X}",
            handler_crc, veh_handler_size, veh_handler_rva);
    }

    // ------------------------------------------------------------------
    // Phase 7 — hand the TLS installer VA to the packer.
    //
    // PackerPass reads `ctx.extra_tls_callback_va()` while building
    // its own TLS callback array and appends the installer right
    // after its anti-debug callback. The VA is absolute (image_base
    // + installer_rva) because the packer serializes TLS callback
    // pointers as absolute 64-bit addresses — same shape as every
    // other entry in the array.
    // ------------------------------------------------------------------
    {
        const uint64_t image_base =
            static_cast<uint64_t>(ctx.pe_image().image_base());
        const uint64_t installer_va = image_base + tls_installer_rva;
        ctx.set_extra_tls_callback_va(installer_va);
        ctx.log_fmt("GuardPass: TLS installer VA=0x{:016X} → "
                    "ctx.extra_tls_callback_va", installer_va);
    }

    ctx.log_fmt("GuardPass: релокация завершена, {} активных guard'ов",
        descriptors.size());
    return {};
}

} // namespace mx
