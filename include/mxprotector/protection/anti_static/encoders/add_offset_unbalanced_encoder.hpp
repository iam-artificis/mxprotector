/**
 * @file add_offset_unbalanced_encoder.hpp
 * @brief Non-balanced `push rax + lea + add K + xchg + ret` encoder
 *        (B.4.22).
 *
 * Stub layout (19 bytes):
 *
 *     50                            push rax                    (1)
 *     48 8D 05 <encoded_disp32>     lea rax, [rip + encoded]    (7)
 *     48 05    <K_imm32>            add rax, sign_ext(K_imm32)  (6)
 *     48 87 04 24                   xchg rax, qword ptr [rsp]   (4)
 *     C3                            ret                         (1)
 *
 * The chain is **non-balanced**: `K != 0`, and the LEA's
 * `encoded_disp32` is `target - lea_anchor - K`, **not** the
 * standard rel32. After the `add rax, K` rotates the LEA's value,
 * `rax = target` exactly, so the `xchg`/`ret` dispatches as in the
 * balanced encoders.
 *
 * **Why this is harder to fingerprint than `AddOffsetEncoder`.**
 *
 * `AddOffsetEncoder` emits `add K, sub K` whose constants are
 * literally identical bytes 6 LOC apart. A pattern matcher
 * recognises the `add rax, imm32; sub rax, imm32` pair instantly
 * and constant-folds the chain. `AddOffsetUnbalanced` emits ONE
 * arithmetic op with a single `K`; the cancel partner does not
 * exist in the bytes — `K` is folded into the LEA's `disp32` at
 * encode time. To recover the target a static analyser must:
 *
 *   1. Decode the LEA's `disp32` (call it `D`).
 *   2. Decode the `add rax, K`.
 *   3. Compute `target = (lea_anchor) + D + K`.
 *
 * That is symbolic constant propagation across two instructions,
 * not a byte pattern. Decompilers that understand x86 algebra
 * still recover the target; cheap reverse-engineering tools
 * (linear-walk disassemblers, call-graph builders that match
 * `lea + jmp` shapes) do not.
 *
 * **Refmap interaction.**
 *
 * `K != 0` means the LEA's on-disk `disp32` does *not* decode to
 * the actual target — `CodeReferenceScanner` would compute
 * `target' = lea_anchor + disp32 = target - K`, not `target`. The
 * pass that emits the stub registers a
 * `pe::PreScannedRefSlot {slot, target, K}` on the stub's section;
 * the chaos pipeline appends one
 * `ReferenceEncoding::rel32_with_imm_offset` reference per entry
 * AFTER the standard scanner runs, and the patcher's per-encoding
 * dispatch overwrites the wrong `rel`-encoded patch with the
 * correct `(target - slot - 4) - K` value. See
 * `pre_scanned_ref_slot.hpp` for the full plumbing.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief Non-balanced `lea + add + jmp` encoder — see file header.
 */
class AddOffsetUnbalancedEncoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-offset-unbalanced";
    }

    /// 1 + 7 + 6 + 4 + 1 = 19 bytes. The pass that emits the stub
    /// pads the layout to a 4-byte multiple so the chunk planner
    /// treats each stub as one chunk-aligned movable atom; the
    /// stub itself stays 19 bytes.
    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 19;
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
