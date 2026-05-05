/**
 * @file x86_arch_emitter.hpp
 * @brief Adapter that wraps `X86CodeEmitter` to satisfy `arch::ICodeEmitter`.
 *
 * @details `X86CodeEmitter` predates the `arch::ICodeEmitter` abstraction
 *          and uses a fluent API with x86-rich types (`x86::Reg`,
 *          `analysis::Label`, `ConditionCode`). New code that wants to be
 *          arch-agnostic — and future arm64 backends — talk to
 *          `arch::ICodeEmitter` instead, with `arch::Reg{id, width}` and
 *          `MxStatus`-returning methods.
 *
 *          `X86ArchEmitter` is the thin adapter: it owns an
 *          `X86CodeEmitter`, translates each abstract call to the
 *          corresponding x86 fluent call, and translates labels back and
 *          forth between `arch::Label` and `analysis::Label`.
 *
 *          Why an adapter (not "make X86CodeEmitter inherit from
 *          ICodeEmitter") — the existing fluent API is used by ~20
 *          callers and changing the return type from `X86CodeEmitter&`
 *          to `MxStatus` would break every chain. The adapter keeps the
 *          old surface stable and adds the new abstract surface for
 *          callers that opt in.
 */

#pragma once

#include <cstdint>
#include <unordered_map>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/arch/code_emitter.hpp"
#include "mxprotector/arch/arch_info.hpp"

namespace mx::analysis {

/**
 * @brief x86/x64 implementation of `arch::ICodeEmitter`.
 *
 * Maps `arch::Reg{id}` directly onto `x86::Reg` (the x86 enum is
 * 0..15 for rax..r15, so the abstract id passes through as-is).
 * `arch::Reg::width` is informational — the underlying X86CodeEmitter
 * picks operand size from the active mode (`is_64bit`).
 *
 * Construction takes a 64-bit flag, mirroring `X86CodeEmitter`. The
 * factory below picks the flag from `arch::ArchInfo`.
 */
class X86ArchEmitter final : public arch::ICodeEmitter {
public:
    explicit X86ArchEmitter(arch::ArchInfo info) noexcept;

    [[nodiscard]] arch::ArchInfo arch() const noexcept override { return info_; }

    [[nodiscard]] size_t current_size() const noexcept override {
        return inner_.current_size();
    }

    [[nodiscard]] MxResult<ByteBuffer> build() override;

    MxStatus raw(ByteView bytes) override;

    [[nodiscard]] arch::Label create_label() override;
    MxStatus bind_label(arch::Label label) override;

    MxStatus mov_rr(arch::Reg dst, arch::Reg src) override;
    MxStatus mov_ri(arch::Reg dst, uint64_t imm) override;
    MxStatus load(arch::Reg dst, arch::Reg base, int32_t disp) override;
    MxStatus store(arch::Reg base, int32_t disp, arch::Reg src) override;

    MxStatus add_rr(arch::Reg dst, arch::Reg src) override;
    MxStatus sub_rr(arch::Reg dst, arch::Reg src) override;
    MxStatus xor_rr(arch::Reg dst, arch::Reg src) override;
    MxStatus and_rr(arch::Reg dst, arch::Reg src) override;
    MxStatus or_rr (arch::Reg dst, arch::Reg src) override;

    MxStatus add_ri(arch::Reg dst, int32_t imm) override;
    MxStatus sub_ri(arch::Reg dst, int32_t imm) override;
    MxStatus xor_ri(arch::Reg dst, int32_t imm) override;
    MxStatus cmp_ri(arch::Reg lhs, int32_t imm) override;

    MxStatus jmp(arch::Label target) override;
    MxStatus jcc(arch::CondCode cc, arch::Label target) override;
    MxStatus call(arch::Label target) override;
    MxStatus ret() override;

private:
    /// Translate `arch::Reg` to the underlying `x86::Reg`. `id` must be
    /// in 0..15; otherwise the caller gets a `pass_failed` MxStatus
    /// (returned by the public methods that consume the register).
    [[nodiscard]] static MxResult<x86::Reg> to_x86(arch::Reg r) noexcept;

    /// Resolve an `arch::Label` to the underlying `analysis::Label`.
    /// Auto-creates the mapping on first reference.
    [[nodiscard]] Label resolve(arch::Label label);

    arch::ArchInfo  info_;
    X86CodeEmitter  inner_;
    std::unordered_map<uint32_t, Label> label_map_;
};

/**
 * @brief Factory that produces `X86ArchEmitter` for the x64 family.
 *
 * Selected by the pipeline based on `ctx.target().arch`. Future arm64
 * factory sits alongside this one.
 */
class X86CodeEmitterFactory final : public arch::ICodeEmitterFactory {
public:
    [[nodiscard]] arch::ArchFamily supported_family() const noexcept override {
        return arch::ArchFamily::x64;
    }

    [[nodiscard]] std::unique_ptr<arch::ICodeEmitter>
        create(arch::ArchInfo info) override;
};

} // namespace mx::analysis
