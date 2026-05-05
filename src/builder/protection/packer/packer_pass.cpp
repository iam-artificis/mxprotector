/**
 * @file packer_pass.cpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector orchestrator.
 *
 * `PackerPass` is a thin facade over a seven-step pipeline. Every
 * sub-step lives in its own translation unit; this file is the
 * orchestrator that threads them together and resolves the stub
 * shape (EXE / DLL / SYS / EFI) at runtime through
 * `IPackerStubBackend`.
 *
 * Pipeline (decrypt order at runtime is the reverse):
 *
 *   step1 — strip base relocations, collect target sections, steal a
 *           safe OEP prologue, make `.rdata` writable for the IAT
 *           wipe. Free-function helpers `disable_relocations`,
 *           `collect_target_sections`, `prepare_oep_steal` (R3.1
 *           moved them to `packer_setup.{hpp,cpp}`).
 *
 *   step2 — clamp `packer_cipher_layers`, draw per-layer 32-byte RC4
 *           base keys, mark target sections writable, decide the G3
 *           VEH trap gate.
 *
 *   step3 — `IPackerStubBackend::produce(kind, ...)` produces the
 *           stub bytes + a per-shape `PackerStubPatches` variant
 *           (R11). The variant index matches `kind`; downstream
 *           steps read `CipherBodyPatches` / `CommonStubPatches` via
 *           the `cipher_patches()` / `common_patches()` `std::visit`
 *           helpers.
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
 *           `x64_blob_patcher`). The driver / EFI shapes use the
 *           subset patcher `packer::apply_driver_post_inject_patches`.
 *
 *   step6 — `packer::finalize_tls_metadata` fills the TLS directory
 *           and callback array, points `DataDirectory[TLS]` at the
 *           new directory. No-op for driver / EFI shapes.
 *
 *   step7 — `packer::hash_derive_and_encrypt` stamps the self-hash
 *           count imm32, computes FNV-1a over the stub, derives
 *           effective per-layer keys, and RC4-encrypts every target
 *           section in build order.
 */

#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"
#include "mxprotector/protection/packer/packer_section_encryptor.hpp"
#include "mxprotector/protection/packer/packer_setup.hpp"
#include "mxprotector/protection/packer/packer_stub_artifacts.hpp"
#include "mxprotector/protection/packer/packer_stub_backend.hpp"
#include "mxprotector/protection/packer/packer_stub_patcher.hpp"
#include "mxprotector/protection/packer/packer_tls_finalizer.hpp"
#include "mxprotector/protection/packer/rc4_stream_cipher.hpp"
#include "mxprotector/protection/packer/reloc_partition.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"
#include "mxprotector/protection/packer/x64_pe_stub_backend.hpp"

#include <memory>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace mx {

namespace {

using mx::packer::CommonStubPatches;
using mx::packer::IPackerStubBackend;
using mx::packer::IPackerStubBackendFactory;
using mx::packer::OepStealResult;
using mx::packer::PackerStubKind;
using mx::packer::PackerStubPatches;
using mx::packer::PackerStubResult;
using mx::packer::StubArtifactsInfo;
using mx::packer::StubEmissionParams;
using mx::packer::X64PeStubBackendFactory;
using mx::packer::collect_target_sections;
using mx::packer::finalize_packer_stub;
using mx::packer::kKeySize;
using mx::packer::prepare_oep_steal;

/// Map from `PeType` to the matching `PackerStubKind` so step3 can
/// drive the runtime backend.
[[nodiscard]] PackerStubKind kind_for_pe_type(PeType pe_type) noexcept {
    switch (pe_type) {
        case PeType::executable:      return PackerStubKind::exe_executable;
        case PeType::dynamic_library: return PackerStubKind::dll_full;
        case PeType::kernel_driver:   return PackerStubKind::driver;
        case PeType::efi_application: return PackerStubKind::efi;
    }
    // Caller (`PackerPass::execute`) gates on `is_applicable`, which
    // requires `is_windows_pe_x64`; a value outside the known set
    // reaches here only on a future PE-type extension that forgot to
    // update this switch. Default to EXE — safest fallback because
    // every `is_applicable` PE has at least the EXE shape.
    return PackerStubKind::exe_executable;
}

/// Steal label that pairs with each stub kind. Drives
/// `prepare_oep_steal`'s log line; the label has no impact on byte
/// emission.
[[nodiscard]] std::string_view steal_label_for_kind(PackerStubKind kind) noexcept {
    switch (kind) {
        case PackerStubKind::exe_executable: return "OEP";
        case PackerStubKind::dll_full:       return "DllMain";
        case PackerStubKind::driver:         return "DriverEntry";
        case PackerStubKind::efi:            return "_ModuleEntryPoint";
    }
    return "OEP";
}

/// Orchestration state for one `execute_encrypted_stub` call.
///
/// Holds all cross-step state (`steal_`, `layer_keys_`, `encrypted_`,
/// `stub_buf_`, `patches_`, `artifacts_`, `stub_rva_`) as private
/// members. `execute()` walks the seven steps in order; steps 1 and
/// 2 can short-circuit via `skip_` when the image has no encryptable
/// target, and steps 5 and 7 can propagate `MxStatus` errors
/// (section-injection failure, bad hash range).
///
/// The pipeline is shape-agnostic: it owns one `IPackerStubBackend`
/// (resolved by the caller via `IPackerStubBackendFactory`) and a
/// `PackerStubKind` enum, and dispatches between user-mode and
/// driver / EFI specifics on the kind value at runtime.
class PackerPipeline {
public:
    PackerPipeline(ProtectionContext&                  ctx,
                   PackerStubKind                      kind,
                   std::unique_ptr<IPackerStubBackend> backend) noexcept
        : ctx_(ctx)
        , kind_(kind)
        , backend_(std::move(backend))
        , steal_label_(steal_label_for_kind(kind))
    {}

    [[nodiscard]] MxStatus execute() {
        step1_prepare();
        if (skip_) return {};
        step2_generate_keys_and_targets();
        if (skip_) return {};
        step2b_partition_relocs();
        if (auto r = step3_emit_stub_body(); !r) return r;
        step4_append_artifacts();
        if (auto r = step5_inject_and_patch(); !r) return r;
        step6_finalize_tls();
        if (auto r = step7_hash_and_encrypt(); !r) return r;
        ctx_.log("PackerPass: упаковка завершена");
        return {};
    }

private:
    struct EncryptedTarget {
        std::size_t image_index;
        Rva         rva;
        std::uint32_t size;
    };

    /// `true` for kernel-driver and UEFI shapes, where the stub
    /// uses the subset cipher body without the user-mode reprotect
    /// loop / IAT wipe / TLS plumbing.
    [[nodiscard]] bool is_driver_or_efi() const noexcept {
        return kind_ == PackerStubKind::driver ||
               kind_ == PackerStubKind::efi;
    }

    /// Read access to the `CipherBodyPatches` slice of the active
    /// variant alternative — the downstream patchers and step7
    /// only need this base.
    [[nodiscard]] const packer::CipherBodyPatches& cipher_patches() const {
        return std::visit(
            [](const auto& p) -> const packer::CipherBodyPatches& {
                return p;
            }, patches_);
    }

    /// Read access to the `CommonStubPatches` slice — `step5`'s
    /// `finalize_packer_stub` uses this.
    [[nodiscard]] const CommonStubPatches& common_patches() const {
        return std::visit(
            [](const auto& p) -> const CommonStubPatches& {
                return p;
            }, patches_);
    }

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
        // Multi-layer cipher rounds. Each round has its own RC4 key
        // and its own PRGA decrypt loop. Layer 0 is the innermost
        // (runtime decrypted LAST, anti-debug bias woven into its
        // KSA); build-time encryption applies layers in the reverse
        // of runtime order. `layer_count` is clamped to at least 1.
        layer_count_ =
            std::max<std::uint32_t>(1, ctx_.config().packer_cipher_layers);

        layer_keys_.assign(layer_count_, ByteBuffer{});
        for (auto& k : layer_keys_) {
            k.resize(kKeySize);
            for (auto& b : k) b = rng_.next_u8();
        }

        encrypted_.reserve(target_indices_.size());

        for (const std::size_t idx : target_indices_) {
            auto& sec = ctx_.pe_image().sections()[idx];
            const std::uint32_t sec_size =
                static_cast<std::uint32_t>(sec.data.size());
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

        // P6 — section encryption is DEFERRED until step 7. The
        // effective cipher keys depend on the stub's FNV-1a self-
        // integrity hash, which can only be computed once every
        // rel32 inside the stub is finalised.

        // G3 Phase 2 VEH INT3 trap gate: opt-in AND EXE-only. DLL
        // stubs cannot safely install a VEH — it would outlive the
        // DLL's unload and leave a dangling handler in the host
        // process.
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

        // Stage 3 — post-decrypt base-relocation applier. Enabled
        // for manual-mapped output, kernel drivers, and UEFI
        // applications. Drivers / mappers / firmware all relocate
        // freely; for OS-loaded user-mode EXEs/DLLs the OS loader
        // already applied relocations before the stub runs.
        apply_relocs_inline_ =
            ctx_.target().is_manually_mapped() ||
            ctx_.target().is_kernel_driver()   ||
            ctx_.target().is_efi_application();
        if (apply_relocs_inline_) {
            const char* reason =
                ctx_.target().is_kernel_driver()    ? "kernel-driver target" :
                ctx_.target().is_efi_application()  ? "UEFI application target" :
                                                       "manual-map mode";
            ctx_.log_fmt(
                "PackerPass: post-decrypt reloc applier enabled "
                "(reason: {})", reason);
        }
    }

    /// Partition `.reloc` between mapper-applicable entries (left in
    /// `.reloc`) and stub-private entries (extracted into
    /// `stub_private_relocs_` for embedding in `.mxpack`). No-op when
    /// `apply_relocs_inline_` is false.
    void step2b_partition_relocs() {
        if (!apply_relocs_inline_) return;

        std::vector<packer::TargetSection> tgt_sections(encrypted_.size());
        for (std::size_t i = 0; i < encrypted_.size(); ++i) {
            tgt_sections[i] = {encrypted_[i].rva, encrypted_[i].size};
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
                static_cast<std::uint32_t>(stub_private_relocs_.size()),
                result.visible_entry_count);
        }
    }

    [[nodiscard]] MxStatus step3_emit_stub_body() {
        const StubEmissionParams params{
            .section_count        =
                static_cast<std::uint32_t>(encrypted_.size()),
            .layer_count          = layer_count_,
            .enable_veh_trap      = enable_veh_trap_,
            .apply_relocs_inline  = apply_relocs_inline_,
        };
        auto produced = backend_->produce(
            kind_, rng_,
            ByteView{steal_.stolen_bytes.data(), steal_.stolen_bytes.size()},
            params);
        if (!produced) {
            return std::unexpected(produced.error());
        }
        stub_buf_ = std::move(produced->bytes);
        patches_  = std::move(produced->patches);
        return {};
    }

    void step4_append_artifacts() {
        // `emit_tls` is forced off for kernel drivers and UEFI
        // applications — neither image loader honours
        // `DataDirectory[TLS]` (UEFI has no TLS facility at all),
        // and `step6_finalize_tls` is already a no-op for both
        // shapes.
        const bool emit_tls = !is_driver_or_efi();
        const auto& cb = cipher_patches();
        artifacts_ = packer::append_stub_artifacts(
            ctx_, stub_buf_, rng_,
            layer_keys_,
            layer_count_,
            encrypted_.size(),
            cb.ksa_block_start_offset,
            cb.ksa_block_end_offset,
            ByteView{stub_private_relocs_.data(),
                     stub_private_relocs_.size()},
            emit_tls);
    }

    [[nodiscard]] MxStatus step5_inject_and_patch() {
        // `.mxpack` is RWX because the RC4 KSA rebuilds the S-box
        // scratch area inside the section itself at runtime.
        constexpr pe::SectionIntent pack_intent{
            pe::SectionContentType::code,
            pe::SectionPermissions::rwx};

        auto inject = finalize_packer_stub(
            ctx_, std::move(stub_buf_),
            pack_intent, steal_, common_patches());
        if (!inject) return std::unexpected(inject.error());

        pack_section_index_ = inject->pack_section_index;
        stub_rva_           = inject->stub_rva;
        auto& pack_sec      = ctx_.pe_image().sections()[pack_section_index_];

        std::vector<packer::TargetSection> tgt_sections(encrypted_.size());
        for (std::size_t i = 0; i < encrypted_.size(); ++i) {
            tgt_sections[i] = {encrypted_[i].rva, encrypted_[i].size};
        }

        // User-mode (EXE / DLL) version touches every user-mode-only
        // slot (reprotect table, IAT wipe, imagebase anchor); the
        // driver and UEFI versions skip them because the driver
        // cipher body (shared with the EFI stub) never emits the
        // corresponding code.
        if (is_driver_or_efi()) {
            packer::apply_driver_post_inject_patches(
                ctx_, pack_sec.data, stub_rva_,
                layer_count_, cipher_patches(), artifacts_,
                std::span<const packer::TargetSection>{tgt_sections});
        } else {
            packer::apply_post_inject_patches(
                ctx_, pack_sec.data, stub_rva_,
                layer_count_, cipher_patches(), artifacts_,
                std::span<const packer::TargetSection>{tgt_sections});
        }

        return {};
    }

    void step6_finalize_tls() {
        if (is_driver_or_efi()) return;
        auto& pack_sec = ctx_.pe_image().sections()[pack_section_index_];
        packer::finalize_tls_metadata(
            ctx_, pack_sec.data, stub_rva_, artifacts_);
    }

    [[nodiscard]] MxStatus step7_hash_and_encrypt() {
        auto& pack_sec = ctx_.pe_image().sections()[pack_section_index_];

        std::vector<packer::EncryptionTarget> targets(encrypted_.size());
        for (std::size_t i = 0; i < encrypted_.size(); ++i) {
            targets[i] = {encrypted_[i].image_index,
                          encrypted_[i].rva,
                          encrypted_[i].size};
        }

        const auto& cb = cipher_patches();
        packer::Rc4StreamCipher cipher;
        return packer::hash_derive_and_encrypt(
            ctx_, pack_sec.data,
            cb.hash_range_end_offset,
            cb.self_hash.count_imm32_offset,
            layer_count_, layer_keys_,
            std::span<const packer::EncryptionTarget>{targets},
            cipher);
    }

    // --- inputs ------------------------------------------------------
    ProtectionContext&                  ctx_;
    PackerStubKind                      kind_;
    std::unique_ptr<IPackerStubBackend> backend_;
    std::string_view                    steal_label_;

    // --- shared rng used across steps 2/3/4 --------------------------
    Randomizer rng_{};

    // --- step1 outputs -----------------------------------------------
    bool skip_ = false;
    std::vector<std::size_t> target_indices_;
    OepStealResult           steal_{};

    // --- step2 outputs -----------------------------------------------
    std::uint32_t                layer_count_         = 1;
    std::vector<ByteBuffer>      layer_keys_;
    std::vector<EncryptedTarget> encrypted_;
    bool                         enable_veh_trap_     = false;
    bool                         apply_relocs_inline_ = false;

    /// Stub-private reloc blob produced by `step2b_partition_relocs`.
    /// Empty when partitioning was skipped or no encrypted-section
    /// relocations were found.
    ByteBuffer                   stub_private_relocs_;

    // --- step3 outputs (backend) -------------------------------------
    ByteBuffer        stub_buf_;
    PackerStubPatches patches_{};

    // --- step4 outputs -----------------------------------------------
    StubArtifactsInfo artifacts_{};

    // --- step5 outputs -----------------------------------------------
    std::size_t pack_section_index_ = 0;
    Rva         stub_rva_           = 0;
};

} // anonymous namespace

bool PackerPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    if (!ctx.config().enable_packer)        return false;
    if (!ctx.target().is_windows_pe_x64())  return false;
    // EXE / DLL / SYS / EFI are all dispatched below — every kind
    // has its own dedicated stub kind on the backend.
    return true;
}

MxStatus PackerPass::execute(ProtectionContext& ctx) {
    ctx.log("PackerPass: начало самораспаковывающейся защиты");

    // Resolve the stub backend through the factory. R8.4 wired
    // `IPackerStubBackend` + `X64PeStubBackendFactory`; this is the
    // first consumer-side migration off the per-shape Emitter
    // template (R11). A future arm64 PE backend or ELF backend
    // becomes one new factory + one factory selection here.
    X64PeStubBackendFactory factory;
    auto backend = factory.create(arch::ArchInfo::x64_baseline(),
                                  ctx.target().container);
    if (!backend) {
        return std::unexpected(backend.error());
    }

    const auto kind = kind_for_pe_type(ctx.pe_image().pe_type());
    return PackerPipeline(ctx, kind, std::move(*backend)).execute();
}

} // namespace mx
