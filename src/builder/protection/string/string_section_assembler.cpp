/**
 * @file string_section_assembler.cpp
 * @brief Implementation of `assemble_string_section` — see header.
 */

#include "mxprotector/protection/string/string_section_assembler.hpp"

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx::string_protect {

namespace {

/// Attempt to lift the mx_str_get XOR loop (`kMxStrGetLoopOffset..
/// kMxStrGetLoopOffset + kMxStrGetLoopSize`) into a VM runtime blob
/// appended to `section_buf`. On success, fills `out.vm_blob_offset`
/// / `vm_blob_entry_offset` / `vm_lift_succeeded`. On any failure
/// logs and leaves the section buffer untouched (the pipeline
/// silently falls back to the plain stub).
///
/// VM-lift is exclusive with the S3 ephemeral decryptor — the two
/// variants have different body shapes and the loop-window offsets
/// kMxStrGetLoopOffset/End are S2b-specific. S3 doesn't need VM
/// protection anyway: its per-call scratch allocator already
/// prevents the sticky-plaintext leak that VM lifting exists to hide.
void try_append_vm_lift(
    ProtectionContext&     ctx,
    const GatheredStrings& gathered,
    const StringArtifacts& artifacts,
    Randomizer&            rng,
    StringSectionLayout&   out)
{
    if (ctx.config().string_protection != StringProtectionMode::virtualized) return;
    if (gathered.is_ephemeral_mode)                                           return;

    auto* disasm = ctx.disassembler().get();
    if (disasm == nullptr) {
        ctx.log("StringProtectionPass: --strings=vm: disassembler "
                "отсутствует, откат на S2b stub");
        return;
    }

    ByteView body_view{
        artifacts.decryptor_code.data() + kMxStrGetLoopOffset,
        kMxStrGetLoopSize};

    vm::VmLifter lifter(*disasm);
    // `base_va` only affects intra-body branch resolution; the
    // concrete value is arbitrary as long as it's consistent within
    // this lift.
    constexpr Va kFakeBaseVa = 0x0000000140000000ULL;
    auto lift_result = lifter.lift(body_view, kFakeBaseVa);
    if (!lift_result) {
        ctx.log_fmt("StringProtectionPass: --strings=vm: лифтинг mx_str_get "
                    "не удался ({}), откат на S2b stub",
            lift_result.error().message());
        return;
    }

    auto [vm_insns, report] = *lift_result;
    ctx.log_fmt("StringProtectionPass: --strings=vm: лифтинг mx_str_get "
                "OK — total={}, generic={}, native={}",
        report.total_insns, report.generic_ops, report.native_ops);

    vm::VmRuntimeGenerator gen;
    // Same imagebase-key heuristic as VirtualizationPass: only
    // enable when the packer will disable ASLR, so the runtime
    // ImageBase matches the preferred one baked into the handler-
    // table decryption key.
    const bool packer_will_run =
        ctx.config().enable_packer &&
        ctx.pe_image().pe_type() == PeType::executable;
    vm::VmGenOptions opts{
        .emit_exit_as_jmp     = false,
        .use_imagebase_key    = packer_will_run,
        .preferred_image_base =
            static_cast<uint64_t>(ctx.pe_image().image_base()),
        // The S2c sub-VM lives inside `.mxstr`, which stays R+W+X
        // at runtime (the decryptor XOR-writes the data pool and
        // flips the descriptor sticky flag). The default anti-tamper
        // page-protection probe asks its own section's protection
        // mask and corrupts the handler-table key when it observes
        // WRITE — that's the correct signal for `.mxvm` but a false
        // positive here.
        .skip_anti_tamper_checks = true,
    };

    auto gen_result = gen.generate(vm_insns, rng, opts);
    if (!gen_result) {
        ctx.log_fmt("StringProtectionPass: --strings=vm: генерация "
                    "VM runtime не удалась ({}), откат на S2b stub",
            gen_result.error().message());
        return;
    }

    // Align the VM blob to a 16-byte boundary inside the section so
    // the handler table loads are naturally aligned — same
    // convention VirtualizationPass uses.
    while (out.section_buf.size() % 16 != 0) {
        out.section_buf.push_back(asm64::kInt3);
    }
    out.vm_blob_offset       = out.section_buf.size();
    out.vm_blob_entry_offset = gen_result->entry_offset;
    out.section_buf.insert(out.section_buf.end(),
                           gen_result->blob.begin(),
                           gen_result->blob.end());
    out.vm_lift_succeeded = true;
    ctx.log_fmt("StringProtectionPass: --strings=vm: VM blob {} байт, "
                "entry @ section+0x{:X}",
        gen_result->blob.size(),
        out.vm_blob_offset + out.vm_blob_entry_offset);
}

} // anonymous namespace

StringSectionLayout assemble_string_section(
    ProtectionContext&     ctx,
    const GatheredStrings& gathered,
    const StringArtifacts& artifacts,
    Randomizer&            rng)
{
    StringSectionLayout out;

    // Reserve rough upper bound. Trampoline payload + descriptor
    // table + worst-case data pool + scratch ring.
    out.section_buf.reserve(
        artifacts.decryptor_code.size() +
        artifacts.trampolines.size() * kTrampolineSizeVolatile +
        artifacts.encrypted.size()    * kDescriptorSize +
        artifacts.encrypted.size()    * 4096 +
        kEphemeralRingTotalSize);

    // --- mx_str_get at the section head ------------------------------
    out.decryptor_offset = out.section_buf.size();
    out.section_buf.insert(out.section_buf.end(),
                           artifacts.decryptor_code.begin(),
                           artifacts.decryptor_code.end());

    // --- Trampolines, one per usable xref ----------------------------
    //
    // Offsets are remembered so the post-commit patcher can
    // translate them into RVAs and the source-side LEA rewriter
    // knows where each trampoline lives.
    out.trampoline_offsets.reserve(artifacts.trampolines.size());
    for (const auto& tr : artifacts.trampolines) {
        out.trampoline_offsets.push_back(out.section_buf.size());
        out.section_buf.insert(out.section_buf.end(),
                               tr.code.begin(),
                               tr.code.end());
    }

    // --- Descriptor table --------------------------------------------
    //
    // One packed 8-byte record per protected string. `data_offset`
    // is measured from the data-pool start (not the section),
    // matching what `mx_str_get` computes internally.
    //
    // NUL-terminator layout: for every protected string we reserve
    // `enc.length + 1` bytes in the data pool. The extra byte is
    // set to `enc.key` at build time; when the runtime decryptor
    // XORs it with `enc.key`, it becomes `0` — a proper NUL
    // terminator. The descriptor's `length` field is bumped to
    // `enc.length + 1` so the runtime decrypt loop processes the
    // terminator too.
    //
    // Callers treat the returned pointer as a classic C string
    // (strlen, printf %s, ...); without the terminator they'd read
    // past the end of the plaintext into the next ciphertext byte
    // and produce garbled output up to the next lucky zero byte.
    out.desc_table_offset = out.section_buf.size();
    {
        size_t data_pool_cursor = 0;
        std::vector<StringDescriptor> descriptors;
        descriptors.reserve(artifacts.encrypted.size());
        for (const auto& enc : artifacts.encrypted) {
            StringDescriptor d{};
            d.data_offset = static_cast<uint32_t>(data_pool_cursor);
            d.length      = static_cast<uint16_t>(enc.length + 1);
            d.key         = enc.key;
            d.flags       = 0;
            descriptors.push_back(d);
            data_pool_cursor += enc.length + 1;
        }
        for (const auto& d : descriptors) {
            const auto packed = pack_descriptor(d);
            out.section_buf.insert(
                out.section_buf.end(), packed.begin(), packed.end());
        }
    }

    // --- Data pool: ciphertext + per-string key (NUL-terminator) -----
    out.data_pool_offset = out.section_buf.size();
    for (const auto& enc : artifacts.encrypted) {
        out.section_buf.insert(out.section_buf.end(),
                               enc.ciphertext.begin(),
                               enc.ciphertext.end());
        out.section_buf.push_back(enc.key);  // key ^ 0 = plain NUL after decrypt
    }

    // --- S3 scratch ring (ephemeral mode only) -----------------------
    //
    // Layout:
    //   [ring_counter : u32 = 0]          (kEphemeralRingHeaderSize)
    //   [slot 0 .. kEphemeralRingSlots-1] (each kEphemeralSlotSize bytes)
    //
    // The counter is zero-initialised so the first `lock xadd` at
    // runtime returns 0 and picks slot index 0. The slots are
    // pre-zeroed so stale bytes don't leak out the first time each
    // slot is used (before the copy loop overwrites them).
    if (gathered.is_ephemeral_mode) {
        // Align the ring to 4 bytes so the `lock xadd` on the
        // counter hits a naturally aligned dword. The section buf
        // may be odd at this point because ciphertexts are
        // byte-packed.
        while (out.section_buf.size() % 4 != 0) {
            out.section_buf.push_back(0x00);
        }
        out.scratch_ring_offset = out.section_buf.size();
        out.section_buf.insert(out.section_buf.end(),
                               kEphemeralRingTotalSize,
                               static_cast<uint8_t>(0));
    }

    // --- Optional VM lift (S2c: --strings=vm) ------------------------
    try_append_vm_lift(ctx, gathered, artifacts, rng, out);

    return out;
}

} // namespace mx::string_protect
