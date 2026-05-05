/**
 * @file x86_arch_emitter.cpp
 * @brief Implementation of `X86ArchEmitter` and `X86CodeEmitterFactory`.
 *
 * @details Translates `arch::ICodeEmitter` calls into `X86CodeEmitter`
 *          fluent calls. Register translation is direct: `arch::Reg::id`
 *          0..15 maps onto `x86::Reg` enum values 0..15. Width is
 *          informational; mode (32-bit vs 64-bit) is fixed at adapter
 *          construction time from `ArchInfo`.
 */

#include "mxprotector/analysis/x86_arch_emitter.hpp"

#include <utility>

namespace mx::analysis {

namespace {

[[nodiscard]] ConditionCode to_x86_cond(arch::CondCode cc) noexcept {
    using arch::CondCode;
    switch (cc) {
        case CondCode::overflow:      return ConditionCode::overflow;
        case CondCode::no_overflow:   return ConditionCode::not_overflow;
        case CondCode::below:         return ConditionCode::below;
        case CondCode::above_equal:   return ConditionCode::above_or_equal;
        case CondCode::equal:         return ConditionCode::equal;
        case CondCode::not_equal:     return ConditionCode::not_equal;
        case CondCode::below_equal:   return ConditionCode::below_or_equal;
        case CondCode::above:         return ConditionCode::above;
        case CondCode::sign:          return ConditionCode::sign;
        case CondCode::no_sign:       return ConditionCode::not_sign;
        case CondCode::parity_even:   return ConditionCode::parity;
        case CondCode::parity_odd:    return ConditionCode::not_parity;
        case CondCode::less:          return ConditionCode::less;
        case CondCode::greater_equal: return ConditionCode::greater_or_equal;
        case CondCode::less_equal:    return ConditionCode::less_or_equal;
        case CondCode::greater:       return ConditionCode::greater;
    }
    return ConditionCode::equal;
}

[[nodiscard]] MxError reg_out_of_range(arch::Reg r) {
    return MxError(
        ProtectionErrorCode::pass_failed,
        std::format("X86ArchEmitter: register id {} is out of x86/x64 range "
                    "(0..15)", static_cast<unsigned>(r.id)));
}

} // namespace

X86ArchEmitter::X86ArchEmitter(arch::ArchInfo info) noexcept
    : info_(info), inner_(info.is_64bit())
{}

MxResult<x86::Reg> X86ArchEmitter::to_x86(arch::Reg r) noexcept {
    if (r.id > 15) {
        return std::unexpected(reg_out_of_range(r));
    }
    return static_cast<x86::Reg>(r.id);
}

Label X86ArchEmitter::resolve(arch::Label label) {
    auto [it, inserted] = label_map_.try_emplace(label.id, Label{});
    if (inserted) {
        it->second = inner_.create_label();
    }
    return it->second;
}

MxResult<ByteBuffer> X86ArchEmitter::build() {
    return inner_.build();
}

MxStatus X86ArchEmitter::raw(ByteView bytes) {
    inner_.raw(bytes);
    return {};
}

arch::Label X86ArchEmitter::create_label() {
    arch::Label out{static_cast<uint32_t>(label_map_.size() + 1)};
    label_map_[out.id] = inner_.create_label();
    return out;
}

MxStatus X86ArchEmitter::bind_label(arch::Label label) {
    inner_.bind_label(resolve(label));
    return {};
}

// ---------------------------------------------------------------------------
//                             Data movement
// ---------------------------------------------------------------------------

MxStatus X86ArchEmitter::mov_rr(arch::Reg dst, arch::Reg src) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    auto s = to_x86(src); if (!s) return std::unexpected(s.error());
    inner_.mov(*d, *s);
    return {};
}

MxStatus X86ArchEmitter::mov_ri(arch::Reg dst, uint64_t imm) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    inner_.mov(*d, imm);
    return {};
}

MxStatus X86ArchEmitter::load(arch::Reg dst, arch::Reg base, int32_t disp) {
    auto d = to_x86(dst);  if (!d) return std::unexpected(d.error());
    auto b = to_x86(base); if (!b) return std::unexpected(b.error());
    inner_.mov(*d, MemOperand::reg_indirect(*b, disp));
    return {};
}

MxStatus X86ArchEmitter::store(arch::Reg base, int32_t disp, arch::Reg src) {
    auto b = to_x86(base); if (!b) return std::unexpected(b.error());
    auto s = to_x86(src);  if (!s) return std::unexpected(s.error());
    inner_.mov(MemOperand::reg_indirect(*b, disp), *s);
    return {};
}

// ---------------------------------------------------------------------------
//                              Arithmetic
// ---------------------------------------------------------------------------

MxStatus X86ArchEmitter::add_rr(arch::Reg dst, arch::Reg src) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    auto s = to_x86(src); if (!s) return std::unexpected(s.error());
    inner_.add(*d, *s);
    return {};
}

MxStatus X86ArchEmitter::sub_rr(arch::Reg dst, arch::Reg src) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    auto s = to_x86(src); if (!s) return std::unexpected(s.error());
    inner_.sub(*d, *s);
    return {};
}

MxStatus X86ArchEmitter::xor_rr(arch::Reg dst, arch::Reg src) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    auto s = to_x86(src); if (!s) return std::unexpected(s.error());
    inner_.xor_(*d, *s);
    return {};
}

MxStatus X86ArchEmitter::and_rr(arch::Reg dst, arch::Reg src) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    auto s = to_x86(src); if (!s) return std::unexpected(s.error());
    inner_.and_(*d, *s);
    return {};
}

MxStatus X86ArchEmitter::or_rr(arch::Reg dst, arch::Reg src) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    auto s = to_x86(src); if (!s) return std::unexpected(s.error());
    inner_.or_(*d, *s);
    return {};
}

MxStatus X86ArchEmitter::add_ri(arch::Reg dst, int32_t imm) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    inner_.add(*d, imm);
    return {};
}

MxStatus X86ArchEmitter::sub_ri(arch::Reg dst, int32_t imm) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    inner_.sub(*d, imm);
    return {};
}

MxStatus X86ArchEmitter::xor_ri(arch::Reg dst, int32_t imm) {
    auto d = to_x86(dst); if (!d) return std::unexpected(d.error());
    inner_.xor_(*d, imm);
    return {};
}

MxStatus X86ArchEmitter::cmp_ri(arch::Reg lhs, int32_t imm) {
    auto l = to_x86(lhs); if (!l) return std::unexpected(l.error());
    inner_.cmp(*l, imm);
    return {};
}

// ---------------------------------------------------------------------------
//                              Control flow
// ---------------------------------------------------------------------------

MxStatus X86ArchEmitter::jmp(arch::Label target) {
    inner_.jmp(resolve(target));
    return {};
}

MxStatus X86ArchEmitter::jcc(arch::CondCode cc, arch::Label target) {
    inner_.jcc(to_x86_cond(cc), resolve(target));
    return {};
}

MxStatus X86ArchEmitter::call(arch::Label /*target*/) {
    return std::unexpected(MxError(
        ProtectionErrorCode::pass_failed,
        "X86ArchEmitter: label-form direct call not supported by the "
        "underlying X86CodeEmitter; use rel32 form via raw() bytes"));
}

MxStatus X86ArchEmitter::ret() {
    inner_.ret();
    return {};
}

// ============================================================================
//                          X86CodeEmitterFactory
// ============================================================================

std::unique_ptr<arch::ICodeEmitter>
X86CodeEmitterFactory::create(arch::ArchInfo info) {
    return std::make_unique<X86ArchEmitter>(info);
}

} // namespace mx::analysis
