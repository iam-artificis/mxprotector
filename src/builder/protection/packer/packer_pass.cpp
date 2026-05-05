/**
 * @file packer_pass.cpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector orchestrator.
 *
 * `PackerPass` is a thin facade over a seven-step pipeline. Every
 * sub-step lives in its own translation unit; this file is the
 * orchestrator that threads them together and owns the
 * EXE/DLL/SYS-specific stub-shape choice.
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
 *   step3 — the policy Emitter (`ExeStubEmitter` /
 *           `DllFullStubEmitter` / `DriverStubEmitter` from
 *           `stub_emitter.hpp`) produces the stub code bytes +
 *           `CipherBodyPatches`.
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
 */

#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"
#include "mxprotector/protection/packer/packer_section_encryptor.hpp"
#include "mxprotector/protection/packer/packer_setup.hpp"
#include "mxprotector/protection/packer/packer_stub_artifacts.hpp"
#include "mxprotector/protection/packer/packer_stub_patcher.hpp"
#include "mxprotector/protection/packer/packer_tls_finalizer.hpp"
#include "mxprotector/protection/packer/rc4_stream_cipher.hpp"
#include "mxprotector/protection/packer/reloc_partition.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"

#include <concepts>
#include <span>
#include <utility>
#include <vector>

namespace mx {

namespace {

using mx::packer::CommonStubPatches;
using mx::packer::DllFullStubEmitter;
using mx::packer::DriverStubEmitter;
using mx::packer::EfiStubEmitter;
using mx::packer::ExeStubEmitter;
using mx::packer::OepStealResult;
using mx::packer::StubArtifactsInfo;
using mx::packer::StubEmissionParams;
using mx::packer::StubEmitter;
using mx::packer::collect_target_sections;
using mx::packer::finalize_packer_stub;
using mx::packer::kKeySize;
using mx::packer::prepare_oep_steal;

/// Orchestration state for one `execute_encrypted_stub<Emitter>` call.
///
/// Holds all cross-step state (`steal_`, `layer_keys_`, `encrypted_`,
/// `stub_buf_`, `patches_`, `artifacts_`, `stub_rva_`) as private
/// members. `execute()` walks the seven steps in order; steps 1 and
/// 2 can short-circuit via `skip_` when the image has no encryptable
/// target, and steps 5 and 7 can propagate `MxStatus` errors
/// (section-injection failure, bad hash range).
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
        std::size_t image_index;
        Rva         rva;
        std::uint32_t size;
    };

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

    void step3_emit_stub_body() {
        Emitter emitter{StubEmissionParams{
            .section_count        =
                static_cast<std::uint32_t>(encrypted_.size()),
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
        // `emit_tls` is forced off for kernel drivers and UEFI
        // applications — neither image loader honours
        // `DataDirectory[TLS]` (UEFI has no TLS facility at all),
        // and `step6_finalize_tls` is already a compile-time no-op
        // for both shapes.
        constexpr bool emit_tls =
            !std::is_same_v<Emitter, DriverStubEmitter> &&
            !std::is_same_v<Emitter, EfiStubEmitter>;
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
        // `.mxpack` is RWX because the RC4 KSA rebuilds the S-box
        // scratch area inside the section itself at runtime.
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

        std::vector<packer::TargetSection> tgt_sections(encrypted_.size());
        for (std::size_t i = 0; i < encrypted_.size(); ++i) {
            tgt_sections[i] = {encrypted_[i].rva, encrypted_[i].size};
        }

        // User-mode (EXE / DLL) version touches every user-mode-only
        // slot (reprotect table, IAT wipe, imagebase anchor); the
        // driver and UEFI versions skip them because the driver
        // cipher body (shared with the EFI stub) never emits the
        // corresponding code.
        if constexpr (std::is_same_v<Emitter, DriverStubEmitter> ||
                      std::is_same_v<Emitter, EfiStubEmitter>)
        {
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
        if constexpr (std::is_same_v<Emitter, DriverStubEmitter> ||
                      std::is_same_v<Emitter, EfiStubEmitter>)
        {
            return;
        }
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

        packer::Rc4StreamCipher cipher;
        return packer::hash_derive_and_encrypt(
            ctx_, pack_sec.data,
            patches_.hash_range_end_offset,
            patches_.self_hash.count_imm32_offset,
            layer_count_, layer_keys_,
            std::span<const packer::EncryptionTarget>{targets},
            cipher);
    }

    // --- inputs ------------------------------------------------------
    ProtectionContext& ctx_;
    std::string_view   steal_label_;

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

    // --- step3 outputs (emitter) -------------------------------------
    ByteBuffer                     stub_buf_;
    typename Emitter::patches_type patches_{};

    // --- step4 outputs -----------------------------------------------
    StubArtifactsInfo artifacts_{};

    // --- step5 outputs -----------------------------------------------
    std::size_t pack_section_index_ = 0;
    Rva         stub_rva_           = 0;
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
    if (!ctx.config().enable_packer)        return false;
    if (!ctx.target().is_windows_pe_x64())  return false;
    // EXE / DLL / SYS / EFI are all dispatched below — every kind
    // has its own dedicated stub emitter. The Feature C EFI path
    // shares the driver cipher body and post-inject patcher.
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
    if (pe_type == PeType::efi_application) {
        return execute_encrypted_stub<EfiStubEmitter>(ctx, "_ModuleEntryPoint");
    }
    return {};
}

} // namespace mx
