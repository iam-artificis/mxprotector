/**
 * @file packer_pass.cpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector implementation.
 *
 * Strategy:
 *   1. Strip base relocations (set IMAGE_FILE_RELOCS_STRIPPED, clear DYNAMIC_BASE,
 *      clear the IMAGE_DIRECTORY_ENTRY_BASERELOC directory). The loader will
 *      load at the preferred ImageBase without applying any fixups, so the
 *      encrypted bytes survive loader → stub unchanged.
 *   2. Generate a per-build random 256-byte XOR key.
 *   3. Encrypt .text in place: enc[i] = plain[i] ^ key[i % 256]. Mark .text
 *      writable so the stub can decrypt in place.
 *   4. Emit an x64 decryption stub into a new .mxpack section. The stub:
 *        - uses RIP-relative LEAs to locate .text and the embedded key,
 *        - masks the byte index against 0xFF so a single-byte counter drives
 *          the key stream,
 *        - jmps to the original entry point via rel32.
 *   5. Retarget the PE entry point to the stub.
 *
 * Limitations (MVP):
 *   - Only .text is encrypted.
 *   - .reloc is stripped — binaries must be loadable at ImageBase.
 *   - Stub does not restore the .text page protection after decrypting.
 */

#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"
#include "mxprotector/protection/packer/rc4.hpp"
#include "mxprotector/protection/packer/stolen_bytes.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"
#include "mxprotector/protection/packer/tls_callback.hpp"
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <concepts>
#include <cstring>
#include <format>
#include <optional>
#include <utility>
#include <variant>

namespace mx {

namespace {

// Pull the packer helpers into this TU's anonymous namespace so the
// existing unqualified references to `kKeySize`, `kSboxSize`,
// `Rc4State`, `rc4_init`, `rc4_process`, `kMinStolenBytes`,
// `kMaxStolenBytes`, `StolenReloc`, `StolenPlan`, and
// `plan_stolen_bytes` keep compiling after the extraction. Future
// commits that split the stub emitter / cipher body / TLS callback
// out of this file will move their call sites to the fully-qualified
// `packer::` form.
using mx::packer::kKeySize;
using mx::packer::kSboxSize;
using mx::packer::Rc4State;
using mx::packer::rc4_init;
using mx::packer::rc4_process;

using mx::packer::kMinStolenBytes;
using mx::packer::kMaxStolenBytes;
using mx::packer::StolenReloc;
using mx::packer::StolenPlan;
using mx::packer::plan_stolen_bytes;

using mx::packer::write_i32;
using mx::packer::write_u32_le;
using mx::packer::write_u64_le;
using mx::packer::read_u32_le;
using mx::packer::read_u64_le;

using mx::packer::TlsCallbackEmit;
using mx::packer::ExistingTlsDirectory;
using mx::packer::read_existing_tls_directory;
using mx::packer::emit_tls_callback_body;

using mx::packer::DecryptSection;
using mx::packer::LayerPatches;
using mx::packer::CipherBodyPatches;
using mx::packer::emit_decrypt_body;

using mx::packer::CommonStubPatches;
using mx::packer::ExeStubPatches;
using mx::packer::DllFullStubPatches;
using mx::packer::StubEmitter;
using mx::packer::StubEmissionParams;
using mx::packer::ExeStubEmitter;
using mx::packer::DllFullStubEmitter;

using mx::packer::fnv1a_32;
using mx::packer::derive_effective_key_in_place;


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
    disable_relocations(ctx.pe_image());
    ctx.log("PackerPass: релокации отключены (IMAGE_FILE_RELOCS_STRIPPED)");

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
    uint32_t           section_characteristics,
    const OepStealResult& steal,
    const CommonStubPatches& common)
{
    SectionManager sec_mgr(ctx.pe_image());
    const std::string& packer_section_name = ctx.section_names().packer;
    auto add_res = sec_mgr.add_section(
        packer_section_name,
        ByteView{stub_buf.data(), stub_buf.size()},
        section_characteristics);
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

/// Shared encrypted-packer pipeline. Parameterised on `Emitter` so EXE
/// and DLL both flow through the same steps, differing only in the
/// policy type's save/restore shell (and, for DLL, its PROCESS_ATTACH
/// gate). The emitter's `patches_type` must inherit from both
/// `CommonStubPatches` and `CipherBodyPatches`, which the concept +
/// multi-inheritance of the concrete patch types statically guarantee.
///
/// Pipeline:
///   1. Collect target sections (`.text`, vm blob, cff blob).
///   2. `prepare_oep_steal` — strip relocations, locate entry, steal
///      safe prologue bytes, 0xCC the stolen range in place.
///   3. Make `.rdata` writable so the stub can wipe the Import
///      Directory at runtime.
///   4. Generate the per-build random 32-byte RC4 key and encrypt
///      every target section in place (KSA seeded with j = 0 at
///      build time — see the anti-debug bias comment in Rc4State).
///   5. Ask the emitter for the stub bytes.
///   6. Append key, S-box scratch, optional P3 VM KSA blob, reprotect
///      section table, all into the same stub buffer so everything
///      lives inside one `.mxpack` section.
///   7. `finalize_packer_stub` — inject section, patch common rel32
///      slots (jmp → real entry, stolen CALL fix-ups), retarget
///      AddressOfEntryPoint.
///   8. Patch cipher-body rel32s (per-section LEA/ECX, key, S-box,
///      reprotect table, IAT wipe). Optionally overwrite the KSA
///      range with a `call rel32 <vm_entry>` if the VM lift
///      succeeded in step 6.
template <StubEmitter Emitter>
    requires std::constructible_from<Emitter, StubEmissionParams>
[[nodiscard]] MxStatus execute_encrypted_stub(ProtectionContext& ctx,
                                              std::string_view   steal_label)
{
    auto target_indices = collect_target_sections(ctx.pe_image(),
                                                   ctx.section_names());
    if (target_indices.empty()) {
        ctx.log("PackerPass: нет подходящих секций, пропуск");
        return {};
    }

    auto steal_opt = prepare_oep_steal(ctx, steal_label);
    if (!steal_opt) return {};
    auto& steal = *steal_opt;

    // Make .rdata writable so the stub can zero the Import Directory at runtime.
    for (auto& sec : ctx.pe_image().sections()) {
        if (sec.name == ".rdata") {
            sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;
        }
    }

    // P2 — Multi-layer cipher rounds. Each round has its own RC4 key
    // and its own PRGA decrypt loop. Layer 0 is the innermost (runtime
    // decrypted LAST, anti-debug bias woven into its KSA); build-time
    // encryption applies layers in the reverse of runtime order, i.e.
    // `layer 0 first, then 1, ..., then N-1`. `layer_count` is clamped
    // to at least 1 — a config value of 0 is promoted to 1 so the
    // decrypt body still emits one cipher round.
    const uint32_t layer_count =
        std::max<uint32_t>(1, ctx.config().packer_cipher_layers);

    Randomizer rng;
    std::vector<ByteBuffer> layer_keys(layer_count);
    for (auto& k : layer_keys) {
        k.resize(kKeySize);
        for (auto& b : k) b = rng.next_u8();
    }

    struct EncryptedTarget {
        size_t   image_index;
        Rva      rva;
        uint32_t size;
    };
    std::vector<EncryptedTarget> encrypted;
    encrypted.reserve(target_indices.size());

    // Walk the target sections once to skip empty ones and mark them
    // writable. The layer-encryption loop below re-walks the resulting
    // `encrypted` vector so every layer sees the same section order
    // that the runtime stub's PRGA loops will walk.
    for (const size_t idx : target_indices) {
        auto& sec = ctx.pe_image().sections()[idx];
        const uint32_t sec_size = static_cast<uint32_t>(sec.data.size());
        if (sec_size == 0) continue;

        // Allow the stub to decrypt in place.
        sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

        encrypted.push_back({idx, sec.virtual_address, sec_size});
    }

    if (encrypted.empty()) {
        ctx.log("PackerPass: все кандидаты пусты, пропуск");
        return {};
    }

    // P6 — section encryption is DEFERRED until after the stub is
    // fully assembled and patched. The effective cipher keys that
    // encrypt each section are a function of the stub's FNV-1a self
    // integrity hash, which can only be computed once every rel32
    // inside the stub and the hash count imm32 have been finalised.
    // The sections stay plaintext in `pe_image` until the final
    // "hash + derive + encrypt" block at the end of this function,
    // which runs after TLS callback finalisation. Nothing between
    // here and that block reads section contents — every downstream
    // step only needs section RVAs and sizes, which are already
    // captured in `encrypted`.

    // G3 Phase 2 VEH INT3 trap gate: opt-in AND EXE-only. DLL stubs
    // cannot safely install a VEH — it would outlive the DLL's
    // unload and leave a dangling handler in the host process. The
    // DllFullStubEmitter forces `enable_veh_trap=false` inside its
    // emit() regardless of what we pass here, but we still clear
    // the flag at this level so the log / params reflect reality.
    const bool pe_is_exe =
        ctx.pe_image().pe_type() == PeType::executable;
    const bool enable_veh_trap =
        ctx.config().enable_veh_anti_tamper && pe_is_exe;

    if (ctx.config().enable_veh_anti_tamper && !pe_is_exe) {
        ctx.log("PackerPass: --anti-tamper-veh проигнорирован для DLL "
                "(VEH переживёт unload — unsafe)");
    } else if (enable_veh_trap) {
        ctx.log("PackerPass: G3 Phase 2 VEH INT3 trap включён");
    }

    // Emit the stub via the policy-specified emitter.
    Emitter emitter{StubEmissionParams{
        .section_count   = static_cast<uint32_t>(encrypted.size()),
        .layer_count     = layer_count,
        .enable_veh_trap = enable_veh_trap,
    }};
    auto [stub_buf, patches] = emitter.emit(
        rng, ByteView{steal.stolen_bytes.data(), steal.stolen_bytes.size()});

    // Append each layer's 32-byte RC4 key to the stub buffer and
    // record the stub-relative offsets so each layer's `lea rsi, key_K`
    // rel32 can be patched after the stub section is injected.
    std::vector<uint32_t> key_offsets_in_stub(layer_count);
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        key_offsets_in_stub[layer] = static_cast<uint32_t>(stub_buf.size());
        stub_buf.insert(stub_buf.end(),
                        layer_keys[layer].begin(),
                        layer_keys[layer].end());
    }

    // S-box scratch: 256 bytes. At runtime the KSA overwrites the
    // whole region — the build-time content doesn't matter, we just
    // need the space inside the section so `lea r8, sbox` points at
    // valid memory.
    const uint32_t sbox_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), kSboxSize, uint8_t{0});

    // P3 — VM-protected KSA. If a disassembler is available, lift
    // the RC4 KSA range through the existing VM engine and append
    // the runtime blob to the stub buffer; the original plaintext
    // KSA bytes are later overwritten with `call rel32 <vm_entry>`.
    size_t   packer_vm_blob_offset    = 0;
    uint32_t packer_vm_entry_offset   = 0;
    bool     packer_vm_lift_succeeded = false;
    if (ctx.disassembler() != nullptr &&
        patches.ksa_block_end_offset > patches.ksa_block_start_offset)
    {
        const size_t ksa_size =
            patches.ksa_block_end_offset - patches.ksa_block_start_offset;
        ByteView ksa_view{
            stub_buf.data() + patches.ksa_block_start_offset,
            ksa_size};

        vm::VmLifter lifter(*ctx.disassembler());
        constexpr Va kFakeKsaBase = 0x0000000140000000ULL;
        auto lift_result = lifter.lift(ksa_view, kFakeKsaBase);
        if (!lift_result) {
            ctx.log_fmt("PackerPass: P3 VM-lift KSA failed ({}), keeping plaintext",
                lift_result.error().message());
        } else {
            auto [vm_insns, report] = *lift_result;
            ctx.log_fmt("PackerPass: P3 VM-lift OK — total={}, generic={}, native={}",
                report.total_insns, report.generic_ops, report.native_ops);

            vm::VmRuntimeGenerator gen;
            // `use_imagebase_key` reads `PEB.ImageBaseAddress` at VM
            // runtime and folds it into the handler-table key via a
            // build-time MBA chain anchored on `preferred_image_base`.
            // For an EXE, PEB.ImageBase == the exe's own preferred
            // base (we strip relocations), so the chain agrees. For
            // a DLL, PEB.ImageBase is the HOST exe's base regardless
            // of which module is running — a DLL VM using this key
            // would compute the wrong table_xor_key and dispatch
            // every handler into garbage. `VirtualizationPass` has
            // the same gate for the same reason.
            const bool is_exe =
                ctx.pe_image().pe_type() == PeType::executable;
            const vm::VmGenOptions opts{
                .emit_exit_as_jmp        = false,
                .use_imagebase_key       = is_exe,
                .preferred_image_base    =
                    static_cast<uint64_t>(ctx.pe_image().image_base()),
                .skip_anti_tamper_checks = true,
            };
            auto runtime = gen.generate(vm_insns, rng, opts);
            if (!runtime) {
                ctx.log_fmt("PackerPass: P3 VM-lift generate failed ({}), keeping plaintext",
                    runtime.error().message());
            } else {
                while (stub_buf.size() % 16 != 0) {
                    stub_buf.push_back(0xCC);
                }
                packer_vm_blob_offset   = stub_buf.size();
                packer_vm_entry_offset  = runtime->entry_offset;
                stub_buf.insert(stub_buf.end(),
                                runtime->blob.begin(),
                                runtime->blob.end());
                packer_vm_lift_succeeded = true;
                ctx.log_fmt("PackerPass: P3 VM blob {} байт, entry @ stub+0x{:X}",
                    runtime->blob.size(),
                    packer_vm_blob_offset + packer_vm_entry_offset);
            }
        }
    }

    // Embed the reprotect section table right after the VM blob.
    const uint32_t reprotect_table_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), encrypted.size() * 8, uint8_t{0});

    // ----------------------------------------------------------
    // P4 — TLS callback artefacts.
    //
    // Layout appended to the end of stub_buf (all inside the same
    // .mxpack section, so everything lives in one R+W+X page the
    // loader maps as one unit):
    //
    //     [callback body]           ~32 bytes
    //     [8-byte alignment pad]
    //     [IMAGE_TLS_DIRECTORY64]   40 bytes
    //     [8-byte alignment pad]
    //     [callback array]          (N+2) × 8 bytes, NULL terminated
    //     [optional index slot]     4 bytes, only if no existing TLS
    //
    // For inputs that already ship with a TLS directory (C++
    // programs with `__declspec(thread)` statics, for instance) we
    // parse the existing one first and preserve its fields —
    // StartAddressOfRawData / EndAddressOfRawData / AddressOfIndex /
    // SizeOfZeroFill / Characteristics — verbatim. Our new callback
    // prepends itself to the front of the existing callback array
    // so the anti-debug probe fires before any CRT-registered TLS
    // initialiser, and every original callback still runs in its
    // original order afterward.
    //
    // Everything past this point lives at a fixed offset inside
    // `stub_buf`; the runtime RVA of each slot is
    // `stub_rva + offset_in_stub_buf`. We record the offsets now
    // and back-patch them (along with the RC4-key rel32 inside the
    // callback body) after `finalize_packer_stub` has placed the
    // .mxpack section and we know `stub_rva`.
    const auto existing_tls_opt = read_existing_tls_directory(ctx.pe_image());

    // Align to 8 bytes before the callback body so every downstream
    // 8-byte field lands at a naturally-aligned offset.
    while (stub_buf.size() % 8 != 0) stub_buf.push_back(0xCC);

    const TlsCallbackEmit tls_cb = emit_tls_callback_body(stub_buf, rng, layer_count);

    while (stub_buf.size() % 8 != 0) stub_buf.push_back(0xCC);
    const uint32_t tls_dir_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), 40, uint8_t{0});  // IMAGE_TLS_DIRECTORY64

    while (stub_buf.size() % 8 != 0) stub_buf.push_back(0xCC);
    const uint32_t tls_cb_array_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    // Callback array sizing: packer_cb + (optional guard installer) +
    // existing user callbacks + NULL terminator. The guard installer
    // slot is only reserved when an earlier pass (GuardPass) set
    // `ctx.extra_tls_callback_va`; otherwise we keep the old layout.
    const bool has_extra_tls_cb = ctx.extra_tls_callback_va() != 0;
    const size_t tls_cb_array_entries =
        (existing_tls_opt.has_value()
            ? existing_tls_opt->callbacks.size()
            : 0)
        + (has_extra_tls_cb ? 1u : 0u)
        + 2u;  // +1 for our packer cb, +1 for the NULL terminator
    stub_buf.insert(stub_buf.end(), tls_cb_array_entries * 8, uint8_t{0});

    // Index slot — only needed when the input had no TLS directory
    // of its own. If an existing directory was found its
    // AddressOfIndex already points at a valid 4-byte slot in one
    // of the preserved input sections, so we reuse that.
    uint32_t tls_index_slot_offset_in_stub = 0;
    if (!existing_tls_opt.has_value()) {
        while (stub_buf.size() % 4 != 0) stub_buf.push_back(0xCC);
        tls_index_slot_offset_in_stub =
            static_cast<uint32_t>(stub_buf.size());
        stub_buf.insert(stub_buf.end(), 4, uint8_t{0});
    }

    // Inject the .mxpack section + apply the common rel32 patches.
    // Characteristics include MEM_WRITE because the RC4 KSA rebuilds
    // the S-box scratch area at runtime and the scratch lives inside
    // the stub section itself.
    constexpr uint32_t pack_characteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ |
        pe::IMAGE_SCN_MEM_WRITE;

    auto inject = finalize_packer_stub(
        ctx, std::move(stub_buf), pack_characteristics, steal, patches);
    if (!inject) return std::unexpected(inject.error());

    auto& pack_sec = ctx.pe_image().sections()[inject->pack_section_index];
    const Rva stub_rva = inject->stub_rva;

    // Per-layer patching: every layer has its own `lea rsi, key_K`
    // and its own per-section `lea rdi / mov ecx` pair.
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        const auto& lp = patches.layers[layer];

        // lea rsi, [rip + rel] → this layer's 32-byte RC4 key.
        {
            const Rva lea_end_rva = stub_rva + lp.rel_to_key_at + 4;
            const Rva key_rva     = stub_rva + key_offsets_in_stub[layer];
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, lp.rel_to_key_at, rel);
        }

        // Per-section: lea rdi → section base, mov ecx → section size.
        for (size_t i = 0; i < encrypted.size(); ++i) {
            const auto& ds  = lp.sections[i];
            const auto& tgt = encrypted[i];

            const Rva lea_end_rva = stub_rva + ds.patch_lea_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(tgt.rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, ds.patch_lea_at, rel);
            write_i32(pack_sec.data, ds.patch_size_at,
                      static_cast<int32_t>(tgt.size));
        }
    }

    // lea r8, [rip + rel] → 256-byte S-box scratch area.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_sbox_at + 4;
        const Rva sbox_rva    = stub_rva + sbox_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(sbox_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_sbox_at, rel);
    }

    // P3 — if the KSA block was successfully lifted, overwrite the
    // plaintext KSA bytes with `call rel32 <vm_entry>` + NOP pad.
    if (packer_vm_lift_succeeded) {
        const Rva vm_entry_rva =
            stub_rva +
            static_cast<Rva>(packer_vm_blob_offset) +
            static_cast<Rva>(packer_vm_entry_offset);
        const uint32_t ksa_off = patches.ksa_block_start_offset;
        const Rva    call_rva   = stub_rva + ksa_off;
        const Rva    call_end_rva = call_rva + 5;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(vm_entry_rva) -
            static_cast<int64_t>(call_end_rva));

        pack_sec.data[ksa_off + 0] = 0xE8;  // call rel32
        pack_sec.data[ksa_off + 1] = static_cast<uint8_t>(rel        & 0xFF);
        pack_sec.data[ksa_off + 2] = static_cast<uint8_t>((rel >> 8)  & 0xFF);
        pack_sec.data[ksa_off + 3] = static_cast<uint8_t>((rel >> 16) & 0xFF);
        pack_sec.data[ksa_off + 4] = static_cast<uint8_t>((rel >> 24) & 0xFF);
        for (uint32_t i = ksa_off + 5; i < patches.ksa_block_end_offset; ++i) {
            pack_sec.data[i] = 0x90;
        }
        ctx.log_fmt("PackerPass: P3 KSA replaced with call vm_entry @ RVA=0x{:08X}",
            vm_entry_rva);
    }

    // ImageBase rip-relative computation. The `lea rbx, [rip + 0];
    // sub rbx, imm32` pair in the reprotect block needs `imm32 =
    // stub_section_rva + imagebase_lea_anchor_offset` so that at
    // runtime `rbx = current_rip - imm32 = module_base`. This works
    // for both EXE (host == packed module) and DLL (host != packed
    // module) — we never read PEB.ImageBaseAddress.
    {
        const uint32_t imm32 =
            stub_rva + patches.imagebase_lea_anchor_offset;
        write_i32(pack_sec.data, patches.imagebase_sub_imm32_at,
                  static_cast<int32_t>(imm32));
    }

    // lea r14, [rip + rel] → reprotect section table + fill data.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_reprotect_table_at + 4;
        const Rva table_rva   = stub_rva + reprotect_table_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(table_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_reprotect_table_at, rel);

        for (size_t i = 0; i < encrypted.size(); ++i) {
            const uint32_t entry_off =
                reprotect_table_offset_in_stub + static_cast<uint32_t>(i * 8);
            write_i32(pack_sec.data, entry_off + 0,
                      static_cast<int32_t>(encrypted[i].rva));
            write_i32(pack_sec.data, entry_off + 4,
                      static_cast<int32_t>(encrypted[i].size));
        }
    }

    // IAT destruction: patch lea rdi → Import Directory + the size.
    {
        Rva impdir_rva = 0;
        uint32_t impdir_size = 0;
        std::visit([&](const auto& nt) {
            if (pe::IMAGE_DIRECTORY_ENTRY_IMPORT < nt.OptionalHeader.NumberOfRvaAndSizes) {
                impdir_rva  = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                impdir_size = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
        }, ctx.pe_image().nt_headers());

        if (impdir_rva != 0 && impdir_size >= 4) {
            const Rva lea_end_rva = stub_rva + patches.rel_to_impdir_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(impdir_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, patches.rel_to_impdir_at, rel);
            write_i32(pack_sec.data, patches.impdir_size_at,
                      static_cast<int32_t>(impdir_size / 4));
            ctx.log_fmt("PackerPass: IAT destruction — Import Directory 0x{:08X} ({} байт) "
                        "будет обнулён при запуске",
                impdir_rva, impdir_size);
        } else {
            write_i32(pack_sec.data, patches.impdir_size_at, 0);
        }
    }

    // ----------------------------------------------------------
    // P4 — TLS callback finalisation.
    //
    // At this point the .mxpack section has been placed at
    // `stub_rva` and every byte of stub_buf has been copied into
    // `pack_sec.data`. We can now compute the absolute VAs for our
    // TLS callback, the callback array, the TLS directory fields,
    // and the (optional) index slot, and patch them into the
    // section bytes. Finally we update `DataDirectory[TLS]` in the
    // PE header to point at the new directory.
    //
    // Absolute VAs are safe because the packer strips base
    // relocations at the very top of `execute_encrypted_stub`
    // (via `prepare_oep_steal` → `disable_relocations`), so the
    // runtime image base equals the build-time preferred base.
    {
        const auto image_base =
            static_cast<uint64_t>(ctx.pe_image().image_base());
        const uint64_t cb_body_va =
            image_base + stub_rva + tls_cb.body_offset;
        const uint64_t tls_dir_va =
            image_base + stub_rva + tls_dir_offset_in_stub;
        const uint64_t cb_array_va =
            image_base + stub_rva + tls_cb_array_offset_in_stub;

        // 1. Patch the `xor byte [rip + rel32], imm8` inside the
        //    callback body to point at one byte of a per-build
        //    random cipher layer's RC4 key. Corrupting ANY layer's
        //    key is sufficient to cascade: a wrong S-box for one
        //    layer produces a wrong PRGA output which means the
        //    other layers decrypt the intermediate bytes into
        //    garbage. Randomising the target layer per build
        //    denies reversers a stable pivot — extracting the
        //    corruption site from one binary tells them nothing
        //    about the next. The rel32 is computed from the end
        //    of the xor instruction (`xor_instruction_end`) to
        //    the target byte.
        const uint32_t key_target_offset_in_stub =
            key_offsets_in_stub[tls_cb.key_layer_index] +
            tls_cb.key_byte_offset_in_key;
        const int32_t xor_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(key_target_offset_in_stub) -
            static_cast<int64_t>(tls_cb.xor_instruction_end));
        write_i32(pack_sec.data, tls_cb.xor_key_rel32_offset, xor_rel32);

        // 2. Fill the callback array: our packer callback first,
        //    then (optional) the runtime-guards VEH installer from
        //    `ctx.extra_tls_callback_va`, then every existing
        //    callback from the input TLS directory in its original
        //    order, then a NULL terminator.
        //
        // Ordering rationale: packer_cb MUST run first so the
        // anti-debug key-corruption gag fires before any other
        // callback has a chance to inspect the stub. The guard
        // installer MUST run before any existing user callback
        // because user callbacks may execute code that later
        // triggers guarded paths — if the VEH isn't installed yet,
        // those int3s crash the process. So:
        //     [packer_cb][guard_install_cb?][user_cb_0][user_cb_1]...[NULL]
        uint32_t write_off = tls_cb_array_offset_in_stub;
        write_u64_le(pack_sec.data, write_off, cb_body_va);
        write_off += 8;
        if (has_extra_tls_cb) {
            write_u64_le(pack_sec.data, write_off,
                         ctx.extra_tls_callback_va());
            write_off += 8;
        }
        if (existing_tls_opt.has_value()) {
            for (const uint64_t old_cb : existing_tls_opt->callbacks) {
                write_u64_le(pack_sec.data, write_off, old_cb);
                write_off += 8;
            }
        }
        write_u64_le(pack_sec.data, write_off, 0);  // terminator

        // 3. Fill the TLS directory. Non-callback fields come from
        //    the existing directory when present, so C++
        //    `__declspec(thread)` data still works.
        uint64_t index_va = 0;
        uint64_t start_va = 0;
        uint64_t end_va   = 0;
        uint32_t zero_fill = 0;
        uint32_t characteristics = 0;
        if (existing_tls_opt.has_value()) {
            start_va        = existing_tls_opt->start_va;
            end_va          = existing_tls_opt->end_va;
            index_va        = existing_tls_opt->index_va;
            zero_fill       = existing_tls_opt->size_of_zero_fill;
            characteristics = existing_tls_opt->characteristics;
        } else {
            // No existing TLS — point AddressOfIndex at our own
            // 4-byte scratch slot inside .mxpack.
            index_va = image_base + stub_rva + tls_index_slot_offset_in_stub;
        }
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x00, start_va);
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x08, end_va);
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x10, index_va);
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x18, cb_array_va);
        write_u32_le(pack_sec.data, tls_dir_offset_in_stub + 0x20, zero_fill);
        write_u32_le(pack_sec.data, tls_dir_offset_in_stub + 0x24, characteristics);

        // 4. Point the PE header's TLS data directory at our new
        //    in-.mxpack directory.
        const Rva tls_dir_rva =
            static_cast<Rva>(stub_rva + tls_dir_offset_in_stub);
        std::visit([&](auto& nt) {
            if (pe::IMAGE_DIRECTORY_ENTRY_TLS < nt.OptionalHeader.NumberOfRvaAndSizes) {
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
                    = tls_dir_rva;
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].Size
                    = 40;
            }
        }, ctx.pe_image().nt_headers());

        ctx.log_fmt("PackerPass: P4 TLS callback planted @ RVA=0x{:08X}, "
                    "chain length {} (existing={}, ours=1), "
                    "corrupts key[layer={}, byte={}]",
            stub_rva + tls_cb.body_offset,
            static_cast<uint32_t>(tls_cb_array_entries - 1),
            existing_tls_opt.has_value()
                ? static_cast<uint32_t>(existing_tls_opt->callbacks.size())
                : 0u,
            tls_cb.key_layer_index,
            tls_cb.key_byte_offset_in_key);
        (void)tls_dir_va;  // reserved for future use (direct self-reference)
    }

    // ----------------------------------------------------------
    // P6 — stub-self-integrity hash + effective-key derivation.
    //
    // Every rel32 inside the cipher body has been patched (layer
    // keys, sections, sbox, ImageBase, reprotect table, IAT wipe,
    // optional VM-lift call, TLS plumbing outside the hash range).
    // We now:
    //
    //   1. Patch the runtime self-hash loop's `count imm32` slot
    //      with the finalised `hash_range_end_offset`. The count
    //      is INSIDE the hashed range, so this write must happen
    //      before we compute the build-time hash.
    //
    //   2. Compute `fnv1a_32` over `pack_sec.data[0 ..
    //      hash_range_end_offset)`. Bit-exact against what the
    //      runtime self-hash loop will produce on a clean host.
    //      Any tamper that changes any byte in this range at
    //      runtime — debugger INT3, hotpatch, NOP'd anti-debug
    //      probe, hooked reprotect syscall, etc. — will cascade
    //      through the per-layer key derivation and produce a
    //      diverged effective key.
    //
    //   3. For each cipher layer, copy the base key into a
    //      scratch `effective` buffer and apply
    //      `derive_effective_key_in_place(hash, effective)`. The
    //      stub's runtime derivation loop produces the same
    //      32 bytes per layer, so encrypting the target sections
    //      with `effective` here gives the runtime a cascade that
    //      unwinds to plaintext on a clean host.
    //
    //   4. Encrypt every target section by running RC4 with the
    //      per-layer effective key in BUILD order (0 → N-1). The
    //      runtime decrypts in reverse order (N-1 → 0) and each
    //      RC4 round is self-inverse, so the cascade unwinds.
    //      Build-time anti-debug bias is 0 (clean host), matching
    //      layer 0's runtime seed when no debugger is attached.
    //
    // Base keys remain unmodified inside the stub's data tail —
    // the runtime re-derives effective keys from `base + hash`
    // every time the process starts. An attacker who statically
    // reads the keys out of `.mxpack` no longer has enough
    // information to decrypt the sections offline; they must
    // also simulate the exact FNV-1a hash over the stub code
    // AND the FNV-1a-chain derivation. That's a real bump in
    // reverser effort for mass-protected samples.
    {
        const uint32_t hash_range_end = patches.hash_range_end_offset;
        if (hash_range_end == 0 ||
            hash_range_end > pack_sec.data.size())
        {
            ctx.log("PackerPass: P6 — некорректный hash_range_end, пропуск");
            return std::unexpected(
                MxError{ProtectionErrorCode::pass_failed,
                        "P6: hash_range_end_offset out of bounds"});
        }

        // (1) Patch the runtime count imm32 with the finalised byte count.
        write_i32(pack_sec.data,
                  patches.self_hash.count_imm32_offset,
                  static_cast<int32_t>(hash_range_end));

        // (2) Compute FNV-1a over the now-finalised hashed range.
        const uint32_t stub_hash = fnv1a_32(
            ByteView{pack_sec.data.data(), hash_range_end});

        ctx.log_fmt("PackerPass: P6 stub self-hash = 0x{:08X} over [0, 0x{:X})",
            stub_hash, hash_range_end);

        // (3) + (4) Derive effective keys and encrypt every target
        //           section with them. We reuse the base key buffers
        //           already written into the stub at build time — the
        //           derivation is applied to a local COPY so the stub's
        //           in-section bytes stay as base keys (which is what
        //           the runtime derivation loop consumes).
        for (uint32_t layer = 0; layer < layer_count; ++layer) {
            ByteBuffer effective = layer_keys[layer];
            derive_effective_key_in_place(
                stub_hash,
                MutableByteView{effective.data(), effective.size()});

            Rc4State rc4{};
            rc4_init(rc4,
                     ByteView{effective.data(), effective.size()},
                     /*anti_debug_bias=*/0);
            for (const auto& tgt : encrypted) {
                auto& sec = ctx.pe_image().sections()[tgt.image_index];
                rc4_process(rc4,
                            MutableByteView{sec.data.data(), sec.data.size()});
            }
        }

        for (const auto& tgt : encrypted) {
            const auto& sec = ctx.pe_image().sections()[tgt.image_index];
            ctx.log_fmt("PackerPass: зашифрована (RC4 ×{}, P6) '{}' "
                        "(RVA=0x{:08X}, {} байт)",
                layer_count, sec.name, sec.virtual_address, tgt.size);
        }
    }

    ctx.log("PackerPass: упаковка завершена");
    return {};
}

} // anonymous namespace

bool PackerPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    // The self-unpacking stub is assembled in x64 PE form; other targets
    // need their own packer implementations.
    if (!ctx.config().enable_packer)      return false;
    if (!ctx.target().is_windows_pe_x64()) return false;

    // Kernel drivers enter via DriverEntry (PDRIVER_OBJECT, PUNICODE_STRING)
    // and still need their own stub variant — auto-skip them.
    // DLLs enter via DllMain (HINSTANCE, DWORD reason, LPVOID). The DLL
    // path below emits a forwarding-only stub for now (no encryption yet);
    // full DLL packing will layer on top of that in a follow-up.
    const auto pe_type = ctx.pe_image().pe_type();
    if (pe_type != PeType::executable &&
        pe_type != PeType::dynamic_library) {
        return false;
    }

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
    return {};
}


} // namespace mx
