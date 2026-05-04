/**
 * @file chaos_layout.cpp
 * @brief Implementation of `ChaosLayout` — see header.
 */

#include "mxprotector/pe/layout/chaos_layout.hpp"

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/atomic_chunk_planner.hpp"
#include "mxprotector/pe/chaos/chaos_shuffler.hpp"
#include "mxprotector/pe/chaos/code_gap_pin_atom_source.hpp"
#include "mxprotector/pe/chaos/data_section_pin_atom_source.hpp"
#include "mxprotector/pe/chaos/delay_import_atom_source.hpp"
#include "mxprotector/pe/chaos/function_atom_source.hpp"
#include "mxprotector/pe/chaos/handler_table_integrity_refinalizer.hpp"
#include "mxprotector/pe/chaos/import_atom_source.hpp"
#include "mxprotector/pe/chaos/self_crc_refinalizer.hpp"
#include "mxprotector/pe/chaos/load_config_atom_source.hpp"
#include "mxprotector/pe/chaos/pdata_atom_source.hpp"
#include "mxprotector/pe/chaos/reloc_atom_source.hpp"
#include "mxprotector/pe/chaos/tls_atom_source.hpp"
#include "mxprotector/pe/chaos/volatile_metadata_atom_source.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/code_reference_scanner.hpp"
#include "mxprotector/pe/refmap/delay_import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/export_directory_scanner.hpp"
#include "mxprotector/pe/refmap/import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/load_config_directory_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/reference_overlap_filter.hpp"
#include "mxprotector/pe/refmap/reference_patcher.hpp"
#include "mxprotector/pe/refmap/reloc_absolute_va_scanner.hpp"
#include "mxprotector/pe/refmap/reloc_rebuilder.hpp"
#include "mxprotector/pe/refmap/resource_directory_scanner.hpp"
#include "mxprotector/pe/refmap/unwind_info_reference_scanner.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/refmap/obfuscated_jt_scanner.hpp"
#include "mxprotector/pe/refmap/structure_reference_scanner.hpp"
#include "mxprotector/pe/refmap/switch_jump_table_scanner.hpp"
#include "mxprotector/pe/refmap/tls_directory_scanner.hpp"
#include "mxprotector/pe/refmap/vm_call_pop_trampoline_scanner.hpp"
#include "mxprotector/pe/section_intent.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <span>
#include <utility>
#include <variant>

namespace mx::pe {

namespace {

/// Canonical chaos intent — every section claims to hold both code
/// and data and demands RWX runtime permissions.
constexpr SectionIntent kChaosIntent{
    SectionContentType::mixed_code_data,
    SectionPermissions::rwx,
};

/// The bit-mask that `make_section_characteristics` produces for
/// `kChaosIntent`. Computed as a `constexpr` constant so the
/// `finalize()` sweep does not redo the lookup per section.
constexpr std::uint32_t kChaosCharacteristics =
    make_section_characteristics(kChaosIntent);

/// Fill byte for the gaps that appear between the originals' bytes
/// inside the merged section. `0xCC` is `INT3` — looks like inline
/// debug-trap padding to a disassembler walking the unified region,
/// keeps the bytes recognisable in a hex dump, and guarantees a
/// hard fault if control flow ever reaches a gap (defence in depth).
constexpr std::uint8_t kGapFillByte = 0xCC;

/// Stamp the chaos bit-mask into every existing section's
/// characteristics. Discardable / shared / aligned bits the section
/// already had stay set — chaos has no opinion on them.
void stamp_chaos_characteristics(PeImage& image) noexcept {
    for (auto& sec : image.sections()) {
        sec.characteristics |= kChaosCharacteristics;
    }
}

/// Compute the merged-section extent — first byte's RVA and the
/// total span (`max(va + virtual_size) - min(va)`). Pre-condition:
/// at least one non-empty section exists.
struct MergedExtent {
    Rva           first_va;
    std::uint32_t total_vsize;
};

[[nodiscard]] MergedExtent compute_extent(const PeImage& image) noexcept {
    Rva           first_va = std::numeric_limits<Rva>::max();
    std::uint32_t last_end = 0;
    for (const auto& s : image.sections()) {
        first_va = std::min(first_va, s.virtual_address);
        last_end = std::max(last_end, s.virtual_address + s.virtual_size);
    }
    return MergedExtent{
        .first_va    = first_va,
        .total_vsize = static_cast<std::uint32_t>(last_end - first_va),
    };
}

/// Build the merged buffer.
///
/// Bytewise layout (RVA preserved exactly, so every internal RVA
/// reference still resolves to the same byte after the merge):
///
///   * Inter-section gaps — initial `kGapFillByte` (`0xCC`/INT3).
///   * Per-section body `[va, va + virtual_size)` — first
///     `min(data.size(), virtual_size)` bytes copied from `s.data`,
///     remaining bytes zero-filled to mirror the loader's
///     `virtual_size > raw_size` semantics. Any trailing bytes in
///     `s.data` past `virtual_size` (i.e. file-alignment padding
///     beyond the in-memory mapping) are dropped.
[[nodiscard]] ByteBuffer build_merged_buffer(
    const PeImage&     image,
    const MergedExtent extent)
{
    ByteBuffer buf(extent.total_vsize, kGapFillByte);
    for (const auto& s : image.sections()) {
        const auto off = static_cast<std::size_t>(
            s.virtual_address - extent.first_va);

        // Zero out the section's full virtual span first — within a
        // section, anything past the on-disk bytes is loader-visible
        // as zero, never as the chaos gap fill.
        std::memset(buf.data() + off, 0, s.virtual_size);

        if (!s.data.empty()) {
            const auto count = std::min(
                s.data.size(),
                static_cast<std::size_t>(s.virtual_size));
            std::memcpy(buf.data() + off, s.data.data(), count);
        }
    }
    return buf;
}

/// Pick a name for the merged unified section. `--debug-sections`
/// cannot reach here directly (the policy is selected before the
/// section-name pool runs), so we hand-pick a name that visibly
/// hints at the chaos transform: `.mxchaos` truncates to 8 bytes
/// to stay within `IMAGE_SIZEOF_SHORT_NAME`.
[[nodiscard]] std::string pick_merged_section_name() {
    return std::string{".mxchaos"};
}

/// Compute the file offset of the section table for a hypothetical
/// `section_count`-section image. Mirrors what `PeBuilder` will
/// compute at serialisation time, so the merged section's
/// `raw_offset` lines up with where the writer is about to put it.
[[nodiscard]] std::uint32_t compute_section_table_end_offset(
    const PeImage& image,
    std::size_t    section_count) noexcept
{
    std::uint32_t end = 0;
    std::visit([&](const auto& nt) {
        const auto lfanew = static_cast<std::uint32_t>(
            image.dos_header().e_lfanew);
        using NtType = std::decay_t<decltype(nt)>;
        end = lfanew
            + static_cast<std::uint32_t>(offsetof(NtType, OptionalHeader))
            + nt.FileHeader.SizeOfOptionalHeader
            + static_cast<std::uint32_t>(
                section_count * sizeof(pe::IMAGE_SECTION_HEADER));
    }, image.nt_headers());
    return end;
}

/// Replace the image's section table with a single unified section
/// covering `[first_va, first_va + total_vsize)`. `NumberOfSections`
/// in the FileHeader is rewritten to 1, and the new section's
/// `raw_offset` / `raw_size` are computed exactly so `PeBuilder` can
/// serialise the file without further recomputation.
void install_unified_section(
    PeImage&            image,
    const MergedExtent  extent,
    ByteBuffer&&        merged_data)
{
    const std::uint32_t fa = image.file_alignment();
    const std::uint32_t headers_end = compute_section_table_end_offset(
        image, /*section_count=*/1);
    const std::uint32_t raw_offset = static_cast<std::uint32_t>(
        align_up(headers_end, fa));
    const std::uint32_t raw_size = static_cast<std::uint32_t>(
        align_up(merged_data.size(), fa));

    SectionInfo unified;
    unified.name            = pick_merged_section_name();
    unified.virtual_address = extent.first_va;
    unified.virtual_size    = extent.total_vsize;
    unified.data            = std::move(merged_data);
    unified.characteristics = kChaosCharacteristics;
    unified.raw_offset      = raw_offset;
    unified.raw_size        = raw_size;

    auto& sections = image.sections();
    sections.clear();
    sections.push_back(std::move(unified));

    std::visit([](auto& nt) {
        nt.FileHeader.NumberOfSections = 1;
    }, image.nt_headers());
}

/// Collapse every section in the image into one unified RWX
/// section. RVAs of all original bytes are preserved exactly; only
/// the section *table* changes. Skipped (no-op) when the image has
/// fewer than two sections — a single section is already merged by
/// definition.
void merge_into_unified_section(PeImage& image) {
    if (image.sections().size() < 2) return;

    const auto extent = compute_extent(image);
    if (extent.total_vsize == 0) return;

    auto merged = build_merged_buffer(image, extent);
    install_unified_section(image, extent, std::move(merged));
}

/// Walk the image with every refmap scanner and accumulate every
/// emitted reference into one table.
///
/// The scanner ordering is irrelevant — each scanner only appends —
/// but we run code before structure before deep-directory before
/// reloc, so logs (when enabled) read in increasing-detail order.
[[nodiscard]] refmap::ReferenceTable scan_all_references(const PeImage& image) {
    refmap::ReferenceTable table;
    table.reserve(8192);

    // 1. Code-side references: rel32 / rel8 branches + RIP-relative
    //    operands. Emit per-section, ignoring per-section decode-error
    //    counts (chaos is best-effort, not a verifier). Each section
    //    forwards its registered `data_regions` so the scanner skips
    //    VM bytecode / handler-table bytes — bypassing both bogus-ref
    //    emissions and Zydis desync cascades that would otherwise leak
    //    misaligned references into adjacent real code.
    refmap::CodeReferenceScanner code;
    for (const auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        [[maybe_unused]] const auto errors = code.scan(
            ByteView{sec.data.data(),
                     std::min(sec.data.size(),
                              static_cast<std::size_t>(sec.virtual_size))},
            sec.virtual_address,
            std::span<const DataRegion>{
                sec.data_regions.data(), sec.data_regions.size()},
            table);
    }

    // 2. Top-level PE structure: entry point, DataDirectory pointers,
    //    .pdata RUNTIME_FUNCTION entries.
    refmap::StructureReferenceScanner{}.scan(image, table);

    // 3. Deep-directory scanners — IMPORT / EXPORT / DELAY_IMPORT /
    //    TLS / LOAD_CONFIG / RESOURCE. Each module pulls every
    //    RVA-bearing slot inside its directory into the table.
    refmap::ImportDescriptorScanner{}.scan(image, table);
    refmap::ExportDirectoryScanner{}.scan(image, table);
    refmap::DelayImportDescriptorScanner{}.scan(image, table);
    refmap::TlsDirectoryScanner{}.scan(image, table);
    refmap::LoadConfigDirectoryScanner{}.scan(image, table);
    refmap::ResourceDirectoryScanner{}.scan(image, table);

    // 4. UNWIND_INFO trailers — `ExceptionHandler` and `ChainInfo`
    //    are 4-byte RVAs into code that the loader reads but `.reloc`
    //    does not cover. Without this scanner, post-shuffle binaries
    //    keep stale handler RVAs and crash the moment SEH dispatches.
    refmap::UnwindInfoReferenceScanner{}.scan(image, table);

    // 5. MSVC x64 switch jump tables — the
    //    `mov r32, [imageBase + idx*4 + JT_RVA] / add / jmp r64`
    //    dispatcher reads 4-byte RVAs from `.rdata` that, like
    //    UNWIND_INFO trailers, are image-relative and hence not in
    //    `.reloc`. Found in every binary that uses the CRT
    //    `__memmove_avx2` / `__memset_avx2` family (i.e. essentially
    //    every C/C++ binary).
    refmap::SwitchJumpTableScanner{}.scan(image, table);

    // 5a. Obfuscated tail-dispatch jump tables — the VM tail
    //     dispatch (`x64_handlers.cpp::emit_tail_dispatch`) emits a
    //     7-instruction `lea + mov + xor + movsxd + add + jmp/push;ret`
    //     dispatcher whose JT entries are
    //     `(target_rva - jt_base_rva) XOR KEY`. The KEY rides along
    //     in the on-disk `xor eax, imm32` instruction; the scanner
    //     extracts it and emits one `xor_encoded_signed_delta_imm32`
    //     reference per entry so the patcher can re-encrypt the
    //     entry after chaos relocates the target.
    refmap::ObfuscatedJtScanner{}.scan(image, table);

    // 6. MxProtector VM `CallPop` trampolines —
    //    `call $+5; add qword [rsp], imm32; ret` whose imm32 is a
    //    rel32 anchored at `slot - 4` (call_after_rva). Zydis sees
    //    the imm32 as a non-relative immediate so
    //    `CodeReferenceScanner` does not produce a slot for it.
    refmap::VmCallPopTrampolineScanner{}.scan(image, table);

    // 7. Final pass — every IMAGE_REL_BASED_DIR64 entry the linker
    //    emitted. Catches any absolute-VA slot the targeted scanners
    //    missed (defence in depth).
    refmap::RelocAbsoluteVaScanner{}.scan(image, table);

    return table;
}

/// Per-build random seed for the atomic planner. Drawing it from a
/// fresh `Randomizer` (auto-seeded from `std::random_device`) gives
/// each build a non-reproducible permutation. The 64-bit value is
/// then handed to a deterministic `Randomizer{seed}` so the same
/// seed produces the same plan for the rest of the run.
[[nodiscard]] std::uint64_t fresh_seed() {
    Randomizer rng;
    return rng.next_u64();
}

/// Build the atom-source list registered with the atomic planner.
///
/// Order matters only for diagnostics — every source emits into the
/// same table and `AtomTable::normalize()` sorts and merges before
/// the planner consumes the list. The order below groups by
/// abstraction depth: code (function atoms) first, then PE-format
/// directory structures, then the data-section blanket pin.
///
/// `InstructionAtomSource` / `InstructionClusterAtomSource` are
/// intentionally NOT registered: per-instruction or per-cluster
/// shuffle without rewriting control flow corrupts fall-through
/// transitions. Function atoms — bracketed by RET / unconditional
/// JMP — are the smallest unit at which re-ordering is provably
/// safe. String atoms are also omitted: their natural alignment is
/// arbitrary, so the planner would skip them; the data-section pin
/// covers their bytes either way.
void register_atom_sources(chaos::AtomicChunkPlanner& planner) {
    using std::make_unique;

    // 1. Movable: per-function atoms covering the exact `.pdata`
    //    `[BeginAddress, EndAddress)` range of each function.
    planner.add_source(make_unique<chaos::FunctionAtomSource>());

    // 2. Pinned: every byte in `.text` outside any `.pdata`-listed
    //    function. These are inter-function thunks and CFG stubs
    //    the loader and runtime can still call into; pinning them
    //    keeps their bytes verbatim at the original RVA.
    planner.add_source(make_unique<chaos::CodeGapPinAtomSource>());

    // 2. Pinned: every PE directory the loader walks linearly.
    planner.add_source(make_unique<chaos::ImportAtomSource>());
    planner.add_source(make_unique<chaos::DelayImportAtomSource>());
    planner.add_source(make_unique<chaos::TlsAtomSource>());
    planner.add_source(make_unique<chaos::PdataAtomSource>());
    planner.add_source(make_unique<chaos::LoadConfigAtomSource>());
    planner.add_source(make_unique<chaos::VolatileMetadataAtomSource>());
    planner.add_source(make_unique<chaos::RelocBlockAtomSource>());
    planner.add_source(make_unique<chaos::RelocPointerAtomSource>());

    // 3. Pinned: every byte in every non-code section. Prevents the
    //    loose-chunk carving from splitting natural-aligned values
    //    (`__security_cookie`, vtable slots, …) across chunks.
    planner.add_source(make_unique<chaos::DataSectionPinAtomSource>());
}

/// Loose-chunk size range. Values are rounded DOWN to a multiple
/// of 8 inside the planner, so the practical range is 64 / 96 in
/// 8-byte increments. The padding bytes between functions
/// (typically `INT3` filler) are what end up in these chunks; their
/// order is irrelevant for correctness.
constexpr std::uint32_t kMinLooseChunkSize = 64;
constexpr std::uint32_t kMaxLooseChunkSize = 96;

/// Run the post-merge fragment shuffle (B.4.12 atomic-mode wire).
///
/// Pipeline:
///   1. Scan references (consumes the pre-merge per-section layout).
///   2. Plan with `AtomicChunkPlanner` — function atoms shuffle
///      inside `.text`; data sections stay pinned; every chunk
///      boundary lands on an 8-aligned RVA so no naturally-aligned
///      64-bit value is split across chunks.
///   3. Merge sections into the unified `.mxchaos` section.
///   4. Apply the byte shuffle in the unified section.
///   5. Patch every reference slot at its new RVA to point at its
///      new target RVA.
///   6. Rebuild `.reloc` so the loader's ASLR delta lands on the
///      new slot positions.
void apply_fragment_shuffle(PeImage& image) {
    if (image.sections().size() < 2) return;

    auto refs = scan_all_references(image);

    // Drop bogus `rel`/`rip-rel` references whose byte range overlaps
    // a structurally-encoded slot OR a section-registered data region
    // (VM bytecode, handler tables, immediate pools). These are
    // emitted by `CodeReferenceScanner` whenever Zydis opportunistically
    // decodes structured bytes as ghost instructions; surviving them
    // into the patcher silently corrupts the structured byte run and
    // crashes the protected binary at runtime. See
    // `reference_overlap_filter.hpp` for the full rationale.
    {
        std::vector<DataRegion> data_regions;
        for (const auto& sec : image.sections()) {
            data_regions.insert(
                data_regions.end(),
                sec.data_regions.begin(), sec.data_regions.end());
        }
        refs = refmap::ReferenceOverlapFilter{}.filter(
            refs,
            std::span<const DataRegion>{
                data_regions.data(), data_regions.size()});
    }

    Randomizer rng{fresh_seed()};
    chaos::AtomicChunkPlanner planner{
        kMinLooseChunkSize, kMaxLooseChunkSize};
    register_atom_sources(planner);
    auto remapper = planner.plan(image, rng);

    merge_into_unified_section(image);

    if (!image.sections().empty()) {
        auto& unified = image.sections()[0];
        chaos::apply_chunk_shuffle(
            unified.data, unified.virtual_address, remapper);
    }

    refmap::ReferencePatcher patcher;
    [[maybe_unused]] const auto patch_stats =
        patcher.apply(image, refs, remapper);

    refmap::RelocRebuilder reloc_rebuilder;
    [[maybe_unused]] const auto reloc_stats =
        reloc_rebuilder.rebuild(image, remapper);

    // Step 7 — re-finalise the handler-table XOR-sum integrity
    // check. `ObfuscatedJtScanner`'s patches just re-encrypted
    // every JT entry whose target moved, so the stored
    // `xor edx, expected` immediate is stale. The refinaliser walks
    // the image once, recomputes `XOR(entry_0 .. entry_N-1)` over
    // the post-shuffle table bytes, and writes the result to the
    // placeholder. This MUST run before the self-CRC refinaliser:
    // the integrity check sits inside the self-CRC byte range, so
    // updating the integrity-expected slot first lets the self-CRC
    // hash stabilise on the final byte content.
    chaos::HandlerTableIntegrityRefinalizer{}.refinalize(image);

    // Step 8 — re-finalise every self-CRC anti-tamper check whose
    // covered byte range overlapped a chunk that the patcher just
    // rewrote. The expected-CRC placeholder was last computed BEFORE
    // chaos shuffle, so any rel32 the patcher updated inside that
    // range invalidates the stored CRC. The refinaliser walks the
    // image once more, recomputes the CRC over the post-shuffle
    // bytes, and patches the `cmp eax, imm32` slot in place.
    chaos::SelfCrcRefinalizer{}.refinalize(image);
}

} // anonymous namespace

SectionIntent ChaosLayout::resolve(
    std::string_view /*section_name*/,
    SectionIntent    /*requested*/) const noexcept
{
    return kChaosIntent;
}

MxStatus ChaosLayout::finalize(PeImage& image) const {
    // Step 1 — collapse + (optionally) shuffle FIRST. Both paths end
    // up overwriting the section table with a single unified section
    // whose `characteristics` are already chaos-stamped (see
    // `install_unified_section`). The `apply_fragment_shuffle` path
    // additionally scans references, plans chunks, shuffles bytes,
    // and patches references — all of which read the *original*
    // per-section characteristics (e.g. `is_code()` on .text vs
    // .rdata).
    //
    // The fragment shuffle is opt-in because deep internal-directory
    // references that B.4.8 added (IMPORT descriptor pointers, EXPORT
    // name table, LOAD_CONFIG CFG tables, TLS callback array, etc.)
    // are now scanned, but the policy is conservative — flip on via
    // `--chaos-shuffle` and stress-test before defaulting on.
    if (enable_fragment_shuffle_) {
        apply_fragment_shuffle(image);
    } else {
        merge_into_unified_section(image);
    }

    // Step 2 — stamp the chaos bit-mask onto the now-unified section.
    // The merge already sets `unified.characteristics =
    // kChaosCharacteristics`, so this is normally a no-op; the loop
    // exists as defence in depth for any external code that bypasses
    // the merge path.
    stamp_chaos_characteristics(image);

    return {};
}

std::string_view ChaosLayout::name() const noexcept {
    return "chaos";
}

} // namespace mx::pe
