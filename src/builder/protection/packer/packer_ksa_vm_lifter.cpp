/**
 * @file packer_ksa_vm_lifter.cpp
 * @brief P3 VM-lift of the packer stub's RC4 KSA — implementation.
 *
 * Split out of `packer_pass.cpp` (R2.2). Behaviour and log output
 * are byte-for-byte identical to the inlined block that used to live
 * inside `execute_encrypted_stub` / `PackerPipeline::step4_append_artifacts`.
 */

#include "mxprotector/protection/packer/packer_ksa_vm_lifter.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx::packer {

KsaVmLiftResult try_lift_ksa_to_vm(
    mx::ProtectionContext& ctx,
    ByteBuffer&            stub_buf,
    uint32_t               ksa_block_start_offset,
    uint32_t               ksa_block_end_offset,
    Randomizer&            rng)
{
    KsaVmLiftResult result{};

    if (ctx.disassembler() == nullptr ||
        ksa_block_end_offset <= ksa_block_start_offset)
    {
        return result;
    }

    const size_t ksa_size =
        ksa_block_end_offset - ksa_block_start_offset;
    ByteView ksa_view{
        stub_buf.data() + ksa_block_start_offset,
        ksa_size};

    vm::VmLifter lifter(*ctx.disassembler());
    constexpr Va kFakeKsaBase = 0x0000000140000000ULL;
    auto lift_result = lifter.lift(ksa_view, kFakeKsaBase);
    if (!lift_result) {
        ctx.log_fmt("PackerPass: P3 VM-lift KSA failed ({}), keeping plaintext",
            lift_result.error().message());
        return result;
    }

    auto [vm_insns, report] = *lift_result;
    ctx.log_fmt("PackerPass: P3 VM-lift OK — total={}, generic={}, native={}",
        report.total_insns, report.generic_ops, report.native_ops);

    vm::VmRuntimeGenerator gen;
    // `use_imagebase_key` reads `PEB.ImageBaseAddress` at VM runtime
    // and folds it into the handler-table key via a build-time MBA
    // chain anchored on `preferred_image_base`. For an EXE,
    // PEB.ImageBase == the exe's own preferred base (we strip
    // relocations), so the chain agrees. For a DLL, PEB.ImageBase
    // is the HOST exe's base regardless of which module is running —
    // a DLL VM using this key would compute the wrong table_xor_key
    // and dispatch every handler into garbage. `VirtualizationPass`
    // has the same gate for the same reason.
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
        return result;
    }

    while (stub_buf.size() % 16 != 0) {
        stub_buf.push_back(0xCC);
    }
    result.vm_blob_offset_in_stub = stub_buf.size();
    result.vm_entry_offset        = runtime->entry_offset;
    stub_buf.insert(stub_buf.end(),
                    runtime->blob.begin(),
                    runtime->blob.end());
    result.succeeded = true;
    ctx.log_fmt("PackerPass: P3 VM blob {} байт, entry @ stub+0x{:X}",
        runtime->blob.size(),
        result.vm_blob_offset_in_stub + result.vm_entry_offset);

    return result;
}

} // namespace mx::packer
