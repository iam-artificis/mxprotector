/**
 * @file indirect_call_encoder_pass.hpp
 * @brief [PROTECTION] Pass that hides direct `call rel32` edges
 *        by routing every internal call through a per-target
 *        dispatch stub.
 *
 * ### What it does
 *
 * For every `call rel32` instruction whose target is an internal
 * function (not an IAT thunk, not outside `.text`), the pass:
 *
 *   1. Picks an `IIndirectCallEncoder` at random from the
 *      registry.
 *   2. Reserves enough bytes in the call-stub section for that
 *      encoder's stub.
 *   3. Emits the stub at the reserved RVA — `lea rax, [rip+disp];
 *      <opcode chain>; jmp rax`.
 *   4. Rewrites the original `call rel32` so its disp32 points at
 *      the stub instead of the original target.
 *
 * The original CFG edge `call_site → target` becomes
 * `call_site → stub_X → ???`. A naïve call-graph builder that
 * walks `call rel32` displacements no longer sees the direct
 * connection.
 *
 * ### Encoder abstraction
 *
 * The pass is encoder-agnostic. New encoders plug in via
 * `EncoderRegistry::register_encoder` and immediately enter the
 * random rotation. The pass calls only `name()`, `stub_size()`,
 * and `emit()` — there is no encoder-specific logic in the pass.
 *
 * ### Reference handling
 *
 * Each emitted stub contains a `lea rax, [rip + disp32]` whose
 * disp32 is the *standard* `target_rva - lea_pc - 7`. The chaos-
 * shuffle reference patcher (`CodeReferenceScanner` + standard
 * `rel` encoding) detects the LEA, remaps the target through the
 * `RvaRemapper`, and rewrites disp32 — all without any new
 * scanner. Encoders that would store a non-zero algebraic offset
 * `K` in the disp32 use the
 * `ReferenceEncoding::rel32_with_imm_offset` encoding committed
 * in B.4.19; the shipped balanced encoders use `K = 0` so the
 * standard `rel` encoding suffices.
 *
 * SOLID:
 *   * SRP — exactly one task: route call sites through stubs.
 *     Encoder choice, byte emission, and stub layout live in
 *     dedicated classes the pass composes.
 *   * OCP — adding a new encoder is a registry registration
 *     change, not a pass change.
 *
 * Threading: single-threaded by construction; the pass mutates
 * the `PeImage` and uses a single `Randomizer`.
 */

#pragma once

#include <string_view>

#include "mxprotector/protection/pass.hpp"

namespace mx::protection::anti_static {

/**
 * @brief Indirect-call dispatch pass — see file header.
 */
class IndirectCallEncoderPass final : public IProtectionPass {
public:
    IndirectCallEncoderPass() = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "IndirectCallEncoderPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::anti_analysis;
    }

    /// Priority 230 — runs in the obfuscation window (200-299),
    /// **after** mutation but **before** virtualization. The
    /// rewritten calls are still plain `call rel32` so the VM
    /// lifter and CFG flattener that come later handle them
    /// exactly as before.
    [[nodiscard]] std::uint32_t priority() const noexcept override {
        return 230;
    }

    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;

    [[nodiscard]] bool is_applicable(
        const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx::protection::anti_static
