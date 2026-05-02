/**
 * @file packer_pass.cpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector orchestrator.
 *
 * `PackerPass` is a thin facade over a seven-step pipeline. Every
 * sub-step lives in its own translation unit; this file is the
 * orchestrator that threads them together and owns the
 * EXE/DLL-specific stub-shape choice.
 *
 * Pipeline (decrypt order at runtime is the reverse):
 *
 *   step1 — strip base relocations, collect target sections, steal a
 *           safe OEP prologue, make `.rdata` writable for the IAT
 *           wipe. Free-function helpers `disable_relocations`,
 *           `collect_target_sections`, `prepare_oep_steal`.
 *
 *   step2 — clamp `packer_cipher_layers`, draw per-layer 32-byte RC4
 *           base keys, mark target sections writable, decide the G3
 *           VEH trap gate.
 *
 *   step3 — the policy Emitter (`ExeStubEmitter` /
 *           `DllFullStubEmitter` from `stub_emitter.hpp`) produces
 *           the stub code bytes + `CipherBodyPatches`.
 *
 *   step4 — `packer::append_stub_artifacts` walks the fixed
 *           stub-tail layout: per-layer keys, sbox scratch, P3
 *           VM blob (`packer_ksa_vm_lifter`), reprotect table, P4
 *           TLS callback body + directory + callback array + optional
 *           index slot.
 *
 *   step5 — inject the .mxpack section via `finalize_packer_stub`,
 *           then delegate every rel32 / imm32 / anchor patch to
 *           `packer::apply_post_inject_patches` (analogue of
 *           `x64_blob_patcher`).
 *
 *   step6 — `packer::finalize_tls_metadata` fills the TLS directory
 *           and callback array, points `DataDirectory[TLS]` at the
 *           new directory.
 *
 *   step7 — `packer::hash_derive_and_encrypt` stamps the self-hash
 *           count imm32, computes FNV-1a over the stub, derives
 *           effective per-layer keys, and RC4-encrypts every target
 *           section in build order.
 *
 * Shared pre/post helpers: `disable_relocations`,
 * `collect_target_sections`, `prepare_oep_steal`, and
 * `finalize_packer_stub` stay in this TU because they own
 * cross-cutting PE mutations (relocation-dir stamping, entry
 * redirection, section injection with rel32 fixups) that no
 * downstream extractor needs to see in isolation.
 */

#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"
#include "mxprotector/protection/packer/dll_characteristics_audit.hpp"
#include "mxprotector/protection/packer/packer_section_encryptor.hpp"
#include "mxprotector/protection/packer/packer_stub_artifacts.hpp"
#include "mxprotector/protection/packer/packer_stub_patcher.hpp"
#include "mxprotector/protection/packer/packer_tls_finalizer.hpp"
#include "mxprotector/protection/packer/rc4.hpp"
#include "mxprotector/protection/packer/reloc_partition.hpp"
#include "mxprotector/protection/packer/stolen_bytes.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"

#include <algorithm>
#include <concepts>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace mx {

namespace {

using mx::packer::kKeySize;
using mx::packer::plan_stolen_bytes;
using mx::packer::StolenPlan;
using mx::packer::write_i32;
using mx::packer::CommonStubPatches;
using mx::packer::StubArtifactsInfo;
using mx::packer::StubEmitter;
using mx::packer::StubEmissionParams;
using mx::packer::ExeStubEmitter;
using mx::packer::DllFullStubEmitter;
using mx::packer::DriverStubEmitter;


/// Adjust `OptionalHeader.DllCharacteristics` so the protected output
/// loads cleanly across the target shapes the packer supports.
///
///   * `GUARD_CF` is cleared unconditionally. The packer itself adds
///     `.mxpack`; earlier passes may have added `.mxvm`, the CFF
///     trampoline section, and `.mxstr`. None of those carry entries
///     in the original Control Flow Guard bitmap, so a CFG-aware
///     indirect call landing in any of them would be flagged as an
///     invalid target and trip the loader's CFG dispatch into a
///     fail-fast path. The protected binary as a whole can no
///     longer claim CFG compliance — drop the bit so the loader
///     does not enforce a guarantee we cannot keep.
///
///   * `FORCE_INTEGRITY` is cleared for kernel drivers. The kernel
///     loader (and its bootmgr-level integrity check) refuses to
///     load a `FORCE_INTEGRITY` image that is not embedded-signed
///     by Microsoft. Our packer rewrites `.text` bytes which
///     invalidates any pre-existing signature, so the bit must
///     come off — otherwise the driver will not load even with
///     test-signing or HVCI relaxations active.
///
/// User-mode targets keep `FORCE_INTEGRITY` untouched: it is rare
/// enough on EXEs / DLLs that we are not currently concerned with
/// it, and the packed binary is signed by whatever post-build step
/// the user runs (or unsigned, in which case the loader does not
/// enforce the bit).
///
/// The bit-level policy lives in `dll_characteristics_audit.hpp` as
/// a pure `constexpr` function so every target-shape × bit-combo
/// can be unit-tested in isolation. This orchestrator only wires
/// the pure result into the PE header and emits log lines for the
/// cleared bits.
void apply_dll_characteristics_audit(ProtectionContext& ctx) {
    uint16_t cleared = 0;
    const bool is_driver = ctx.target().is_kernel_driver();
    std::visit([&](auto& nt) {
        const auto r = packer::audit_dll_characteristics(
            nt.OptionalHeader.DllCharacteristics, is_driver);
        nt.OptionalHeader.DllCharacteristics = r.output;
        cleared = r.cleared;
    }, ctx.pe_image().nt_headers());

    if (cleared == 0) return;  // No-op path: input had none of the
                                // relevant bits set. Stay silent.

    if (cleared & pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        ctx.log("PackerPass: DllCharacteristics: GUARD_CF cleared "
                "(injected sections lack CFG bitmap entries)");
    }
    if (cleared & pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
        ctx.log("PackerPass: DllCharacteristics: FORCE_INTEGRITY cleared "
                "(driver target — packed bytes invalidate any "
                "Microsoft signature)");
    }
}

/// Strip base relocations: clear the directory entry, set the file header's
/// IMAGE_FILE_RELOCS_STRIPPED bit, clear DYNAMIC_BASE in DllCharacteristics,
/// and blank out in-memory .reloc contents so PeBuilder doesn't re-emit them.
void disable_relocations(PeImage& image) {
    std::visit([&](auto& nt) {
        using NT = std::decay_t<decltype(nt)>;

        nt.FileHeader.Characteristics |= pe::IMAGE_FILE_RELOCS_STRIPPED;
        nt.OptionalHeader.DllCharacteristics &=
            static_cast<uint16_t>(~pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS32> ||
                      std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC < nt.OptionalHeader.NumberOfRvaAndSizes) {
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            }
        }
    }, image.nt_headers());

    image.set_relocations({});

    for (auto& sec : image.sections()) {
        if (sec.name == ".reloc") {
            std::fill(sec.data.begin(), sec.data.end(), static_cast<uint8_t>(0));
        }
    }
}

/// Find the primary code section to encrypt. For MSVC-built PEs this is
/// ".text". If a CFF trampoline section (`ctx.section_names().cff`) or a VM
/// blob (`ctx.section_names().vm`) was added earlier, they are also encrypted
/// so neither is left in the clear.
///
/// The S2 string-protection section (`ctx.section_names().str`) is NOT
/// included: the packer's post-decrypt `NtProtectVirtualMemory` loop
/// revokes the write bit on every encrypted section, but `mx_str_get`
/// does an in-place XOR over the `.mxstr` data pool on the first call
/// to each string and flips a sticky flag inside the descriptor. Both
/// operations require the section to stay writable, so `.mxstr` is left
/// out of the packer target list. Its data pool is still ciphertext at
/// rest thanks to the per-string XOR encryption built into the pass,
/// and strong packer protection for the decryptor itself is a job for
/// S2c (`--strings=vm`) which lifts `mx_str_get` into a VM region.
std::vector<size_t> collect_target_sections(const PeImage& image,
                                             const SectionNameMap& names) {
    std::vector<size_t> indices;
    for (size_t i = 0; i < image.sections().size(); ++i) {
        const auto& sec = image.sections()[i];
        if (sec.data.empty()) continue;
        if (sec.name == ".text" || sec.name == names.cff || sec.name == names.vm) {
            indices.push_back(i);
        }
    }
    return indices;
}

/// Result of `prepare_oep_steal`: the section the real entry point lives
/// in, the entry RVA, the safe stolen-byte plan, and the bytes themselves
/// (empty if no safe prologue could be stolen, in which case the stub is
/// entered, runs its payload, and jumps straight back to the unchanged
/// entry RVA).
struct OepStealResult {
    size_t     section_index;
    Rva        oep_rva;
    StolenPlan plan;
    ByteBuffer stolen_bytes;
};

/// Shared packer pre-stub preparation.
///
/// Strips base relocations, locates the section that holds the real
/// entry point, tries to steal a safe prologue range, and overwrites
/// the stolen range in the source section with 0xCC so memory dumps
/// are missing the real prologue.
///
/// Returns std::nullopt if the entry RVA is zero (no entry at all —
/// nothing to protect) or falls outside every section; callers
/// treat that as "skip the packer for this image".
[[nodiscard]] std::optional<OepStealResult>
prepare_oep_steal(ProtectionContext& ctx, std::string_view steal_label) {
    // Adjust `OptionalHeader.DllCharacteristics` so the loader does
    // not enforce guarantees the packed binary cannot keep (CFG over
    // injected sections, embedded-signature integrity for drivers).
    // No-op when the input had none of the relevant bits set.
    apply_dll_characteristics_audit(ctx);

    // Decide how to handle `.reloc` based on target shape.
    //
    // 1. OS-loaded EXE / DLL (neither kernel driver nor manual-map):
    //    the OS loader does all relocations; our stub never touches
    //    `.reloc`. We strip the directory, set `RELOCS_STRIPPED`, and
    //    clear `DYNAMIC_BASE` so the OS loader is forced to the
    //    preferred base (required by the `use_imagebase_key` VM
    //    handler-table derivation and by the TLS directory's
    //    absolute-VA `AddressOfCallBacks` field).
    //
    // 2. User-mode manual-map (EXE / DLL + `--load-mode=manual`):
    //    we still need the OS loader to land the binary at the
    //    preferred base, because the TLS plumbing we emit (callback
    //    body + directory + array) uses absolute VAs baked at build
    //    time. So `RELOCS_STRIPPED` stays ON. Mappers that IGNORE
    //    the flag and walk `.reloc` anyway get a safe directory:
    //    `partition_encrypted_relocs` has already neutralised every
    //    entry that targeted an encrypted section to
    //    `IMAGE_REL_BASED_ABSOLUTE` (treated as padding). Mappers
    //    that HONOUR the flag skip everything, which is also fine
    //    because the stub handles its own entries from the private
    //    blob.
    //
    // 3. Kernel driver (any load mode): no TLS directory is
    //    finalised (kernel images do not run TLS callbacks) and the
    //    driver cipher body contains no absolute VAs. There is
    //    therefore nothing tying us to the preferred base, so we
    //    leave `RELOCS_STRIPPED` at its input value and let any
    //    mapper relocate freely — the partitioned `.reloc` +
    //    stub-private blob cover every code scenario.
    const bool is_driver       = ctx.target().is_kernel_driver();
    const bool keep_relocs     = is_driver || ctx.target().is_manually_mapped();
    if (!keep_relocs) {
        disable_relocations(ctx.pe_image());
        ctx.log("PackerPass: релокации отключены (IMAGE_FILE_RELOCS_STRIPPED)");
    } else if (is_driver) {
        ctx.log("PackerPass: .reloc preserved, RELOCS_STRIPPED not forced "
                "(driver stub emits no absolute VAs; mapper may load at "
                "any base)");
    } else {
        // User-mode manual-map. Force RELOCS_STRIPPED so a relocation-
        // respecting loader lands the image at the preferred base —
        // the stub's TLS callback array holds absolute VAs that
        // require it. Leave the `.reloc` directory bytes intact for
        // mappers that ignore the flag; partitioning guarantees they
        // do not corrupt ciphertext.
        std::visit([&](auto& nt) {
            nt.FileHeader.Characteristics |= pe::IMAGE_FILE_RELOCS_STRIPPED;
        }, ctx.pe_image().nt_headers());
        ctx.log("PackerPass: manual-map — RELOCS_STRIPPED set "
                "(TLS absolute VAs require preferred base); "
                ".reloc preserved for mappers that ignore the flag");
    }

    const Rva oep_rva = ctx.pe_image().entry_point_rva();
    if (oep_rva == 0) {
        ctx.log("PackerPass: entry point == 0, пропуск");
        return std::nullopt;
    }

    auto& sections = ctx.pe_image().sections();
    size_t section_index = sections.size();
    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i];
        if (oep_rva >= s.virtual_address &&
            oep_rva < s.virtual_address + s.virtual_size) {
            section_index = i;
            break;
        }
    }
    if (section_index == sections.size()) {
        ctx.log("PackerPass: entry RVA вне секций, пропуск");
        return std::nullopt;
    }

    OepStealResult result{};
    result.section_index = section_index;
    result.oep_rva       = oep_rva;

    auto& oep_target = sections[section_index];
    const uint32_t oep_off = oep_rva - oep_target.virtual_address;
    result.plan = plan_stolen_bytes(
        ByteView{oep_target.data.data(), oep_target.data.size()},
        oep_off, oep_rva);

    if (result.plan.size > 0) {
        result.stolen_bytes.assign(
            oep_target.data.begin() + oep_off,
            oep_target.data.begin() + oep_off + result.plan.size);
        std::fill(oep_target.data.begin() + oep_off,
                  oep_target.data.begin() + oep_off + result.plan.size,
                  static_cast<uint8_t>(0xCC));
        ctx.log_fmt("PackerPass: украдено {} байт {} (0x{:08X}), {} CALL-fixup",
            result.plan.size, steal_label, oep_rva,
            static_cast<uint32_t>(result.plan.relocs.size()));
    } else {
        ctx.log_fmt("PackerPass: {} небезопасен для stolen bytes — пропуск",
            steal_label);
    }
    return result;
}

/// Result of `finalize_packer_stub`.
struct PackerStubInjection {
    size_t  pack_section_index;  ///< index into ctx.pe_image().sections()
    Rva     stub_rva;            ///< RVA where the injected stub was placed
};

/// Shared packer post-stub finalisation.
///
/// Injects a `.mxpack` (or equivalently-named) section carrying the
/// assembled stub buffer, patches the two rel32 slots every stub
/// emitter must produce (`rel_to_oep_at` → real entry + stolen_size,
/// and any CALL rel32 fix-ups inside the embedded stolen payload),
/// and retargets `AddressOfEntryPoint` at the stub.
///
/// Returns {section_index, stub_rva} so the caller can apply any
/// emitter-specific patches (per-section LEA/ECX slots, key/sbox
/// rel32, reprotect table, IAT wipe — all EXE-only for now).
[[nodiscard]] MxResult<PackerStubInjection> finalize_packer_stub(
    ProtectionContext& ctx,
    ByteBuffer&&       stub_buf,
    pe::SectionIntent  intent,
    const OepStealResult& steal,
    const CommonStubPatches& common)
{
    SectionManager sec_mgr(ctx.pe_image());
    pe::SectionEmitter emit{sec_mgr, ctx.layout_policy()};
    const std::string& packer_section_name = ctx.section_names().packer;
    auto add_res = emit.append_section(
        packer_section_name,
        ByteView{stub_buf.data(), stub_buf.size()},
        intent);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const uint32_t pack_idx = *add_res;
    auto& pack_sec = ctx.pe_image().sections()[pack_idx];
    const Rva stub_rva = pack_sec.virtual_address;

    ctx.log_fmt("PackerPass: секция '{}' добавлена: RVA=0x{:08X}, размер={} байт",
        packer_section_name, stub_rva,
        static_cast<uint32_t>(pack_sec.data.size()));

    // jmp rel32 → real entry + stolen_size
    {
        const Rva resume_rva  = steal.oep_rva + steal.plan.size;
        const Rva jmp_end_rva = stub_rva + common.rel_to_oep_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(resume_rva) -
            static_cast<int64_t>(jmp_end_rva));
        write_i32(pack_sec.data, common.rel_to_oep_at, rel);
    }

    // Fix up CALL rel32 inside the stolen payload so each target RVA
    // stays identical after the move into the stub section.
    for (const auto& r : steal.plan.relocs) {
        const uint32_t rel_abs_offset = common.stolen_bytes_offset + r.offset_in_stolen;
        const uint32_t instr_end_abs  = common.stolen_bytes_offset + r.instr_end_in_stolen;
        const Rva new_instr_end_rva   = stub_rva + instr_end_abs;
        const int32_t new_rel = static_cast<int32_t>(
            static_cast<int64_t>(r.original_target_rva) -
            static_cast<int64_t>(new_instr_end_rva));
        write_i32(pack_sec.data, rel_abs_offset, new_rel);
    }

    ctx.pe_image().set_entry_point_rva(stub_rva);
    std::visit([&](auto& nt) {
        nt.OptionalHeader.AddressOfEntryPoint = stub_rva;
    }, ctx.pe_image().nt_headers());

    ctx.log_fmt("PackerPass: entry перенаправлен 0x{:08X} -> 0x{:08X}",
        steal.oep_rva, stub_rva);

    return PackerStubInjection{pack_idx, stub_rva};
}

/// Orchestration state for one `execute_encrypted_stub<Emitter>` call.
///
/// Holds all cross-step state (`steal_`, `layer_keys_`, `encrypted_`,
/// `stub_buf_`, `patches_`, `artifacts_`, `stub_rva_`) as private
/// members. `execute()` walks the seven steps in order; steps 1 and
/// 2 can short-circuit via `skip_` when the image has no encryptable
/// target, and steps 5 and 7 can propagate `MxStatus` errors
/// (section-injection failure, bad hash range).
///
/// See the file-level docstring for the pipeline itself — the step
/// methods below are thin wrappers around the extracted components.
template <StubEmitter Emitter>
    requires std::constructible_from<Emitter, StubEmissionParams>
class PackerPipeline {
public:
    PackerPipeline(ProtectionContext& ctx, std::string_view steal_label) noexcept
        : ctx_(ctx), steal_label_(steal_label) {}

    [[nodiscard]] MxStatus execute() {
        step1_prepare();
        if (skip_) return {};
        step2_generate_keys_and_targets();
        if (skip_) return {};
        step2b_partition_relocs();
        step3_emit_stub_body();
        step4_append_artifacts();
        if (auto r = step5_inject_and_patch(); !r) return r;
        step6_finalize_tls();
        if (auto r = step7_hash_and_encrypt(); !r) return r;
        ctx_.log("PackerPass: упаковка завершена");
        return {};
    }

private:
    struct EncryptedTarget {
        size_t   image_index;
        Rva      rva;
        uint32_t size;
    };

    // --- step methods -------------------------------------------------

    void step1_prepare() {
        target_indices_ = collect_target_sections(ctx_.pe_image(),
                                                   ctx_.section_names());
        if (target_indices_.empty()) {
            ctx_.log("PackerPass: нет подходящих секций, пропуск");
            skip_ = true;
            return;
        }

        auto steal_opt = prepare_oep_steal(ctx_, steal_label_);
        if (!steal_opt) {
            skip_ = true;
            return;
        }
        steal_ = std::move(*steal_opt);

        // Make .rdata writable so the stub can zero the Import
        // Directory at runtime.
        for (auto& sec : ctx_.pe_image().sections()) {
            if (sec.name == ".rdata") {
                sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;
            }
        }
    }

    void step2_generate_keys_and_targets() {
        // P2 — Multi-layer cipher rounds. Each round has its own RC4
        // key and its own PRGA decrypt loop. Layer 0 is the innermost
        // (runtime decrypted LAST, anti-debug bias woven into its KSA);
        // build-time encryption applies layers in the reverse of
        // runtime order, i.e. `layer 0 first, then 1, ..., then N-1`.
        // `layer_count` is clamped to at least 1 — a config value of 0
        // is promoted to 1 so the decrypt body still emits one cipher
        // round.
        layer_count_ =
            std::max<uint32_t>(1, ctx_.config().packer_cipher_layers);

        layer_keys_.assign(layer_count_, ByteBuffer{});
        for (auto& k : layer_keys_) {
            k.resize(kKeySize);
            for (auto& b : k) b = rng_.next_u8();
        }

        encrypted_.reserve(target_indices_.size());

        // Walk the target sections once to skip empty ones and mark
        // them writable. The layer-encryption loop later re-walks the
        // resulting `encrypted_` vector so every layer sees the same
        // section order that the runtime stub's PRGA loops will walk.
        for (const size_t idx : target_indices_) {
            auto& sec = ctx_.pe_image().sections()[idx];
            const uint32_t sec_size = static_cast<uint32_t>(sec.data.size());
            if (sec_size == 0) continue;

            // Allow the stub to decrypt in place.
            sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

            encrypted_.push_back({idx, sec.virtual_address, sec_size});
        }

        if (encrypted_.empty()) {
            ctx_.log("PackerPass: все кандидаты пусты, пропуск");
            skip_ = true;
            return;
        }

        // P6 — section encryption is DEFERRED until after the stub is
        // fully assembled and patched. The effective cipher keys that
        // encrypt each section are a function of the stub's FNV-1a
        // self-integrity hash, which can only be computed once every
        // rel32 inside the stub and the hash count imm32 have been
        // finalised. The sections stay plaintext in `pe_image` until
        // step7 (`P6 hash + derive + encrypt`) which runs after TLS
        // callback finalisation. Nothing between here and that step
        // reads section contents — every downstream step only needs
        // section RVAs and sizes, which are already captured in
        // `encrypted_`.

        // G3 Phase 2 VEH INT3 trap gate: opt-in AND EXE-only. DLL
        // stubs cannot safely install a VEH — it would outlive the
        // DLL's unload and leave a dangling handler in the host
        // process. The DllFullStubEmitter forces
        // `enable_veh_trap=false` inside its emit() regardless of what
        // we pass here, but we still clear the flag at this level so
        // the log / params reflect reality.
        const bool pe_is_exe =
            ctx_.pe_image().pe_type() == PeType::executable;
        enable_veh_trap_ =
            ctx_.config().enable_veh_anti_tamper && pe_is_exe;

        if (ctx_.config().enable_veh_anti_tamper && !pe_is_exe) {
            ctx_.log("PackerPass: --anti-tamper-veh проигнорирован для DLL "
                     "(VEH переживёт unload — unsafe)");
        } else if (enable_veh_trap_) {
            ctx_.log("PackerPass: G3 Phase 2 VEH INT3 trap включён");
        }

        // Stage 3 — post-decrypt base-relocation applier.
        //
        // Enabled when EITHER the user opted into manual-mapped output
        // (mapper may relocate before the stub runs) OR the target is
        // a kernel driver (the kernel loader / `MmLoadSystemImage`
        // freely relocates drivers when the preferred base is taken,
        // and manual driver mappers like kdmapper always relocate).
        // For OS-loaded user-mode targets the OS loader already
        // applied relocations, so emitting the applier would
        // double-apply the delta — keep it off in that case.
        apply_relocs_inline_ =
            ctx_.target().is_manually_mapped() ||
            ctx_.target().is_kernel_driver();
        if (apply_relocs_inline_) {
            ctx_.log_fmt(
                "PackerPass: post-decrypt reloc applier enabled "
                "(reason: {})",
                ctx_.target().is_kernel_driver()
                    ? "kernel-driver target"
                    : "manual-map mode");
        }
    }

    /**
     * @brief Partition the visible `.reloc` directory between
     *        mapper-applicable entries (kept in `.reloc` as-is) and
     *        stub-private entries (extracted into `stub_private_relocs_`
     *        for embedding in `.mxpack`).
     *
     * No-op when `apply_relocs_inline_` is false — the OS-loaded
     * EXE / DLL paths still leave the original `.reloc` for the
     * Windows loader to apply. With `apply_relocs_inline_ == true`
     * (manual-map or kernel driver) we pre-process `.reloc` so the
     * entries that target encrypted sections become `ABSOLUTE`
     * padding for the mapper, and a private copy of those entries
     * is embedded for the stub's `emit_reloc_applier` to walk.
     */
    void step2b_partition_relocs() {
        if (!apply_relocs_inline_) return;

        std::vector<packer::TargetSection> tgt_sections(encrypted_.size());
        for (size_t i = 0; i < encrypted_.size(); ++i) {
            tgt_sections[i] =
                {encrypted_[i].rva, encrypted_[i].size};
        }

        auto result = packer::partition_encrypted_relocs(
            ctx_.pe_image(),
            std::span<const packer::TargetSection>{tgt_sections});

        stub_private_relocs_ = std::move(result.stub_private_blob);

        if (stub_private_relocs_.empty()) {
            ctx_.log_fmt(
                "PackerPass: .reloc partition: 0 encrypted-section "
                "entries (visible: {}, blob: empty)",
                result.visible_entry_count);
        } else {
            ctx_.log_fmt(
                "PackerPass: .reloc partitioned — {} encrypted-section "
                "entries from {} block(s) moved to stub-private blob "
                "({} bytes); {} entries remain visible to mapper",
                result.stub_private_entry_count,
                result.neutralised_block_count,
                static_cast<uint32_t>(stub_private_relocs_.size()),
                result.visible_entry_count);
        }
    }

    void step3_emit_stub_body() {
        Emitter emitter{StubEmissionParams{
            .section_count        = static_cast<uint32_t>(encrypted_.size()),
            .layer_count          = layer_count_,
            .enable_veh_trap      = enable_veh_trap_,
            .apply_relocs_inline  = apply_relocs_inline_,
        }};
        auto [stub_buf, patches] = emitter.emit(
            rng_,
            ByteView{steal_.stolen_bytes.data(), steal_.stolen_bytes.size()});
        stub_buf_ = std::move(stub_buf);
        patches_  = std::move(patches);
    }

    void step4_append_artifacts() {
        // Delegates to packer_stub_artifacts, which walks the fixed
        // post-emit layout (keys, sbox, P3 VM blob, reprotect table,
        // optional stub-private reloc blob, P4 TLS callback body +
        // directory + callback array + optional index slot) and
        // returns every recorded offset.
        //
        // `emit_tls` is forced off for kernel drivers — the kernel
        // image loader ignores `DataDirectory[TLS]` entirely, and
        // `step6_finalize_tls` is already a compile-time no-op for
        // the driver shape. Skipping the emission avoids ~120 bytes
        // of dead payload inside `.mxpack` and removes a misleading
        // TLS artefact a future reverse engineer would otherwise
        // trip over.
        constexpr bool emit_tls =
            !std::is_same_v<Emitter, DriverStubEmitter>;
        artifacts_ = packer::append_stub_artifacts(
            ctx_, stub_buf_, rng_,
            layer_keys_,
            layer_count_,
            encrypted_.size(),
            patches_.ksa_block_start_offset,
            patches_.ksa_block_end_offset,
            ByteView{stub_private_relocs_.data(),
                     stub_private_relocs_.size()},
            emit_tls);
    }

    [[nodiscard]] MxStatus step5_inject_and_patch() {
        // Inject the .mxpack section + apply the common rel32
        // patches. Section is RWX because the RC4 KSA rebuilds the
        // S-box scratch area at runtime and the scratch lives inside
        // the stub section itself.
        constexpr pe::SectionIntent pack_intent{
            pe::SectionContentType::code,
            pe::SectionPermissions::rwx};

        auto inject = finalize_packer_stub(
            ctx_, std::move(stub_buf_),
            pack_intent, steal_, patches_);
        if (!inject) return std::unexpected(inject.error());

        pack_section_index_ = inject->pack_section_index;
        stub_rva_           = inject->stub_rva;
        auto& pack_sec      = ctx_.pe_image().sections()[pack_section_index_];

        // Thin the EncryptedTarget vector down to just {rva, size}
        // for the patcher — it doesn't need `image_index` (that's
        // step7's concern).
        std::vector<packer::TargetSection> tgt_sections(encrypted_.size());
        for (size_t i = 0; i < encrypted_.size(); ++i) {
            tgt_sections[i] = {encrypted_[i].rva, encrypted_[i].size};
        }

        // Delegate every rel32 / imm32 / anchor patch to the right
        // patcher: the user-mode (EXE / DLL) version touches every
        // user-mode-only slot (reprotect table, IAT wipe, imagebase
        // anchor); the driver version skips them because the driver
        // cipher body never emits the corresponding code (their
        // offsets stay at zero, and writing into offset 0 would
        // corrupt the stub prologue).
        if constexpr (std::is_same_v<Emitter, DriverStubEmitter>) {
            packer::apply_driver_post_inject_patches(
                ctx_, pack_sec.data, stub_rva_,
                layer_count_, patches_, artifacts_,
                std::span<const packer::TargetSection>{tgt_sections});
        } else {
            packer::apply_post_inject_patches(
                ctx_, pack_sec.data, stub_rva_,
                layer_count_, patches_, artifacts_,
                std::span<const packer::TargetSection>{tgt_sections});
        }

        return {};
    }

    void step6_finalize_tls() {
        // Drivers do not have TLS — kernel images do not run TLS
        // callbacks and we never set DataDirectory[TLS] for them, so
        // the entire finaliser is a no-op for the driver path. The
        // TLS scratch artefacts that `step4_append_artifacts` emits
        // remain inside `.mxpack` as dead bytes (worth ~120 bytes —
        // a future tightening pass can drop them when the emitter is
        // refactored to skip emission).
        if constexpr (std::is_same_v<Emitter, DriverStubEmitter>) {
            return;
        }

        // Delegates to packer_tls_finalizer — fills the callback
        // array, IMAGE_TLS_DIRECTORY64 fields, and updates the PE
        // header's DataDirectory[TLS] entry to point at the new
        // directory inside .mxpack.
        auto& pack_sec = ctx_.pe_image().sections()[pack_section_index_];
        packer::finalize_tls_metadata(ctx_, pack_sec.data, stub_rva_, artifacts_);
    }

    [[nodiscard]] MxStatus step7_hash_and_encrypt() {
        // Delegates the P6 "stamp count imm32 → hash stub → derive
        // effective keys → RC4-encrypt every target section" cascade
        // to packer_section_encryptor. Base keys in `layer_keys_`
        // stay untouched — the encryptor derives on a local copy so
        // the stub's in-section bytes remain the base keys, which is
        // what the runtime derivation loop reads.
        auto& pack_sec = ctx_.pe_image().sections()[pack_section_index_];

        std::vector<packer::EncryptionTarget> targets(encrypted_.size());
        for (size_t i = 0; i < encrypted_.size(); ++i) {
            targets[i] = {encrypted_[i].image_index,
                          encrypted_[i].rva,
                          encrypted_[i].size};
        }

        return packer::hash_derive_and_encrypt(
            ctx_, pack_sec.data,
            patches_.hash_range_end_offset,
            patches_.self_hash.count_imm32_offset,
            layer_count_, layer_keys_,
            std::span<const packer::EncryptionTarget>{targets});
    }

    // --- inputs ------------------------------------------------------
    ProtectionContext& ctx_;
    std::string_view   steal_label_;

    // --- shared rng used across steps 2/3/4 --------------------------
    Randomizer rng_{};

    // --- step1 outputs -----------------------------------------------
    bool skip_ = false;
    std::vector<size_t> target_indices_;
    OepStealResult      steal_{};

    // --- step2 outputs -----------------------------------------------
    uint32_t                layer_count_     = 1;
    std::vector<ByteBuffer> layer_keys_;
    std::vector<EncryptedTarget> encrypted_;
    bool                    enable_veh_trap_ = false;
    bool                    apply_relocs_inline_ = false;

    /// Stub-private reloc blob produced by `step2b_partition_relocs`.
    /// Empty when partitioning was skipped (`apply_relocs_inline_` is
    /// false) or when no encrypted-section relocations were found.
    ByteBuffer              stub_private_relocs_;

    // --- step3 outputs (emitter) -------------------------------------
    ByteBuffer                     stub_buf_;
    typename Emitter::patches_type patches_{};

    // --- step4 outputs -----------------------------------------------
    StubArtifactsInfo artifacts_{};

    // --- step5 outputs -----------------------------------------------
    size_t pack_section_index_ = 0;
    Rva    stub_rva_           = 0;
};

/// Thin wrapper retained so the facade below keeps its familiar
/// call-site shape. Behaviour is entirely in `PackerPipeline`.
template <StubEmitter Emitter>
    requires std::constructible_from<Emitter, StubEmissionParams>
[[nodiscard]] MxStatus execute_encrypted_stub(ProtectionContext& ctx,
                                              std::string_view   steal_label)
{
    return PackerPipeline<Emitter>(ctx, steal_label).execute();
}

} // anonymous namespace

bool PackerPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    // The self-unpacking stub is assembled in x64 PE form; other targets
    // need their own packer implementations.
    if (!ctx.config().enable_packer)        return false;
    if (!ctx.target().is_windows_pe_x64())  return false;
    // EXE / DLL / SYS are dispatched in `execute()` to dedicated stub
    // emitters. UEFI has no equivalent emitter today (no PE loader,
    // no IAT, no TLS callbacks, no Win32 syscalls — every assumption
    // baked into the existing stubs is wrong for it). Reject EFI here
    // so the dispatch never reaches the silent fallthrough below; an
    // `EfiStubEmitter` can be slotted in later without touching this
    // gate beyond removing the EFI rejection.
    if (ctx.target().is_efi_application()) return false;
    return true;
}

MxStatus PackerPass::execute(ProtectionContext& ctx) {
    ctx.log("PackerPass: начало самораспаковывающейся защиты");

    const auto pe_type = ctx.pe_image().pe_type();
    if (pe_type == PeType::executable) {
        return execute_encrypted_stub<ExeStubEmitter>(ctx, "OEP");
    }
    if (pe_type == PeType::dynamic_library) {
        return execute_encrypted_stub<DllFullStubEmitter>(ctx, "DllMain");
    }
    if (pe_type == PeType::kernel_driver) {
        return execute_encrypted_stub<DriverStubEmitter>(ctx, "DriverEntry");
    }
    return {};
}


} // namespace mx
