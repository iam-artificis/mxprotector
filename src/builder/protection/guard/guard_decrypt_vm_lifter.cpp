/**
 * @file guard_decrypt_vm_lifter.cpp
 * @brief Implementation of `lift_guard_decrypt_to_vm` — see header.
 */

#include "mxprotector/protection/guard/guard_decrypt_vm_lifter.hpp"

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/guard/guard_decrypt_unit.hpp"
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx::guard {

MxResult<GuardDecryptVmBlob>
lift_guard_decrypt_to_vm(ProtectionContext& ctx, Randomizer& rng)
{
    // (1) Emit the native decrypt unit. `native_tmp.buf.back()` is
    //     the trailing `ret` — we overwrite it with `nop` so the
    //     lifter accepts the range (RET is explicitly rejected).
    //     `VmOp::exit` appended below re-creates the return semantics
    //     at the VM level.
    RawEmitter native_tmp{};
    (void)emit_guard_decrypt_unit(native_tmp);
    native_tmp.buf.back() = asm64::kNop;

    // (2) Zydis decode → vm::VmInstructions.
    ByteView      code{native_tmp.buf.data(), native_tmp.buf.size()};
    vm::VmLifter  lifter(*ctx.disassembler());
    auto          lift_result = lifter.lift(code, /*base_va=*/0);
    if (!lift_result) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::pass_failed),
            "GuardPass: VM-lift decrypt unit: " +
                lift_result.error().message()});
    }

    auto [vm_insns, report] = std::move(*lift_result);
    vm_insns.push_back(vm::VmInstruction{.op = vm::VmOp::exit});

    ctx.log_fmt("GuardPass: decrypt unit lifted: "
                "generic={}, native={}, total={}",
        report.generic_ops, report.native_ops, report.total_insns);

    // (3) Generate the VM runtime. Anti-tamper page-protection checks
    //     are skipped because the `.mxguard` section is R+W+X at
    //     runtime (the VEH re-encrypts body bytes in place) — the
    //     default probe would corrupt the handler-table key on a
    //     false-positive write detection.
    vm::VmRuntimeGenerator gen;
    vm::VmGenOptions       opts;
    opts.skip_anti_tamper_checks = true;

    auto vm_result = gen.generate(vm_insns, rng, opts);
    if (!vm_result) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::pass_failed),
            "GuardPass: VM runtime gen: " +
                vm_result.error().message()});
    }

    ctx.log_fmt("GuardPass: decrypt VM blob {} bytes, entry @ +0x{:X}",
        vm_result->blob.size(), vm_result->entry_offset);

    GuardDecryptVmBlob out;
    out.blob         = std::move(vm_result->blob);
    out.entry_offset = vm_result->entry_offset;
    return out;
}

} // namespace mx::guard
