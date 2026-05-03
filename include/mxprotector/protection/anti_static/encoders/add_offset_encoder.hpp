/**
 * @file add_offset_encoder.hpp
 * @brief Balanced `push rax + lea + add + sub + xchg + ret` encoder.
 *
 * Stub layout (25 bytes):
 *
 *     50                            push rax                    (1)
 *     48 8D 05 <std_disp32>         lea rax, [rip + std_disp]   (7)
 *     48 05    <K_imm32>            add rax, sign_ext(K_imm32)  (6)
 *     48 81 E8 <K_imm32>            sub rax, sign_ext(K_imm32)  (7)
 *     48 87 04 24                   xchg rax, qword ptr [rsp]   (4)
 *     C3                            ret                         (1)
 *
 * The `push rax`/`xchg`/`ret` triple is *transparent* to the
 * caller: the original `rax` value is saved at entry, swapped
 * with the computed target right before `ret`, and restored as
 * the callee inherits a normal x64 calling-convention stack
 * frame. This matters for callers that pre-load `rax` before
 * calling (notably MSVC's `__chkstk`, which uses `rax` as the
 * frame-size argument).
 *
 * The `add`/`sub` pair cancels — algebraically the chain is the
 * identity. The LEA's `disp32` is therefore the standard rel32
 * displacement, and `CodeReferenceScanner` keeps it in sync when
 * chaos shuffle moves the target without any new scanner.
 *
 * Why bother emitting a chain at all if it cancels? Three reasons:
 *
 *   * The basic block at the call site no longer has a direct
 *     rel32 edge to the target — call graph builders see only the
 *     edge to the stub, and the stub's disp32 is hidden behind
 *     two arithmetic instructions.
 *   * Pattern matchers looking for `lea + jmp` fail to recognise
 *     the dispatch.
 *   * `K` is randomised per stub, so two stubs to the same target
 *     differ in bytes — frustrates byte-pattern signatures.
 *
 * Sophisticated decompilers (IDA + Hex-Rays) constant-fold the
 * cancel and recover the target. Defeating them is the job of
 * future *non-balanced* encoders that ride the `rel32_with_imm_offset`
 * reference encoding plus a stub-aware refmap scanner.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief `lea + add + jmp` encoder — see header.
 */
class AddOffsetEncoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-offset";
    }

    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 26;
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
