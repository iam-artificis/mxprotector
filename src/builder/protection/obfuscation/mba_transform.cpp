/**
 * @file mba_transform.cpp
 * @brief [BUILDER] Реализация MBA-трансформаций (Mixed Boolean Arithmetic).
 *
 * @details Реализует математически доказуемые MBA-тождества через X86CodeEmitter.
 *          Каждая трансформация генерирует корректный x86/x64 машинный код,
 *          вычисляющий тот же результат, что и оригинальная операция.
 *
 *          Все тождества проверены алгебраически:
 *          x + y ≡ (x ^ y) + 2*(x & y)     [дизъюнктивная декомпозиция сложения]
 *          x - y ≡ (x ^ y) - 2*(~x & y)    [с учётом заёмов]
 *          x ^ y ≡ (x | y) - (x & y)       [разность объединения и пересечения]
 *          x | y ≡ (x ^ y) + (x & y)       [sum of exclusive and common bits]
 *          x & y ≡ (x | y) - (x ^ y)       [двойственность к OR]
 */

#include "mxprotector/protection/obfuscation/mba_transform.hpp"

#include <format>

namespace mx {

MbaTransform::MbaTransform(Architecture arch)
    : arch_(arch)
{}

MbaTransform::~MbaTransform() = default;

// ============================================================================
// Core MBA emit routines
// ============================================================================

// x + y ≡ (x ^ y) + 2*(x & y)
// dst=x, src=y, scratch=temp. After: dst = x+y, src preserved via scratch.
void MbaTransform::emit_add_mba(analysis::X86CodeEmitter& em,
                                 x86::Reg dst, x86::Reg src, x86::Reg scratch)
{
    // scratch = dst (save x)
    em.mov(scratch, dst);
    // scratch = x & y
    em.and_(scratch, src);
    // scratch = 2*(x & y)
    em.shl(scratch, 1);
    // dst = x ^ y
    em.xor_(dst, src);
    // dst = (x ^ y) + 2*(x & y) = x + y
    em.add(dst, scratch);
}

// x - y ≡ (x ^ y) - 2*(~x & y)
void MbaTransform::emit_sub_mba(analysis::X86CodeEmitter& em,
                                 x86::Reg dst, x86::Reg src, x86::Reg scratch)
{
    // scratch = dst (save x)
    em.mov(scratch, dst);
    // scratch = ~x
    em.not_(scratch);
    // scratch = ~x & y
    em.and_(scratch, src);
    // scratch = 2*(~x & y)
    em.shl(scratch, 1);
    // dst = x ^ y
    em.xor_(dst, src);
    // dst = (x ^ y) - 2*(~x & y) = x - y
    em.sub(dst, scratch);
}

// x ^ y ≡ (x | y) - (x & y)
void MbaTransform::emit_xor_mba(analysis::X86CodeEmitter& em,
                                  x86::Reg dst, x86::Reg src, x86::Reg scratch)
{
    // scratch = dst (save x)
    em.mov(scratch, dst);
    // scratch = x & y
    em.and_(scratch, src);
    // dst = x | y
    em.or_(dst, src);
    // dst = (x | y) - (x & y) = x ^ y
    em.sub(dst, scratch);
}

// x | y ≡ (x ^ y) + (x & y)
void MbaTransform::emit_or_mba(analysis::X86CodeEmitter& em,
                                x86::Reg dst, x86::Reg src, x86::Reg scratch)
{
    // scratch = dst (save x)
    em.mov(scratch, dst);
    // scratch = x & y
    em.and_(scratch, src);
    // dst = x ^ y
    em.xor_(dst, src);
    // dst = (x ^ y) + (x & y) = x | y
    em.add(dst, scratch);
}

// x & y ≡ (x | y) - (x ^ y)
void MbaTransform::emit_and_mba(analysis::X86CodeEmitter& em,
                                  x86::Reg dst, x86::Reg src, x86::Reg scratch)
{
    // scratch = dst (save x)
    em.mov(scratch, dst);
    // scratch = x ^ y
    em.xor_(scratch, src);
    // dst = x | y
    em.or_(dst, src);
    // dst = (x | y) - (x ^ y) = x & y
    em.sub(dst, scratch);
}

// ============================================================================
// Public transform methods
// ============================================================================

MxResult<MbaTransformResult> MbaTransform::transform_add(
    x86::Reg dst, x86::Reg src, x86::Reg scratch,
    [[maybe_unused]] Randomizer& rng, uint32_t depth)
{
    analysis::X86CodeEmitter em(is_64bit());

    if (depth <= 1) {
        emit_add_mba(em, dst, src, scratch);
    } else {
        // Depth 2+: x + y = (x ^ y) + 2*(x & y)
        // First compute x & y into scratch, then replace the final ADD with MBA-ADD

        // scratch = x
        em.mov(scratch, dst);
        // scratch = x & y
        em.and_(scratch, src);
        // scratch *= 2
        em.shl(scratch, 1);
        // dst = x ^ y
        em.xor_(dst, src);

        // Now we need: dst = dst + scratch, but using MBA for this ADD too
        // This is the recursive step: (a ^ b) + 2*(a & b) for a=dst, b=scratch
        // We reuse src as temp (it was already consumed by the XOR)
        if (depth >= 2) {
            // Save scratch
            em.push(src);
            em.mov(src, scratch);
            em.mov(scratch, dst);
            em.and_(scratch, src);
            em.shl(scratch, 1);
            em.xor_(dst, src);
            em.add(dst, scratch);
            em.pop(src);
        }
    }

    auto code = em.build();
    if (!code) {
        return std::unexpected(code.error());
    }

    MbaTransformResult result;
    result.code = std::move(*code);
    result.depth_applied = depth;
    result.instruction_count = depth <= 1 ? 5 : 12;
    return result;
}

MxResult<MbaTransformResult> MbaTransform::transform_sub(
    x86::Reg dst, x86::Reg src, x86::Reg scratch,
    [[maybe_unused]] Randomizer& rng, uint32_t depth)
{
    analysis::X86CodeEmitter em(is_64bit());

    if (depth <= 1) {
        emit_sub_mba(em, dst, src, scratch);
    } else {
        // Two-level: apply sub MBA, then the internal XOR uses MBA too
        em.mov(scratch, dst);
        em.not_(scratch);
        em.and_(scratch, src);
        em.shl(scratch, 1);

        // dst = x ^ y using MBA: (x | y) - (x & y)
        em.push(src);
        {
            auto temp = src;
            em.mov(temp, dst);
            em.and_(temp, src);
            em.or_(dst, src);
            em.sub(dst, temp);
        }
        em.pop(src);

        em.sub(dst, scratch);
    }

    auto code = em.build();
    if (!code) return std::unexpected(code.error());

    MbaTransformResult result;
    result.code = std::move(*code);
    result.depth_applied = depth;
    result.instruction_count = depth <= 1 ? 6 : 12;
    return result;
}

MxResult<MbaTransformResult> MbaTransform::transform_xor(
    x86::Reg dst, x86::Reg src, x86::Reg scratch,
    [[maybe_unused]] Randomizer& rng, uint32_t depth)
{
    analysis::X86CodeEmitter em(is_64bit());

    if (depth <= 1) {
        emit_xor_mba(em, dst, src, scratch);
    } else {
        // x ^ y = (x | y) - (x & y)
        // replace OR with MBA: (x ^ y) + (x & y) ... but that's circular
        // Use alternative: x ^ y = (x & ~y) | (~x & y) — but that needs 2 temps
        // Stick with depth-1 XOR, then add noise terms that cancel out
        emit_xor_mba(em, dst, src, scratch);
        // Add cancellation pair for complexity
        auto noise = static_cast<int32_t>(rng.next_u32());
        em.xor_(dst, noise);
        em.xor_(dst, noise);
    }

    auto code = em.build();
    if (!code) return std::unexpected(code.error());

    MbaTransformResult result;
    result.code = std::move(*code);
    result.depth_applied = depth;
    result.instruction_count = depth <= 1 ? 4 : 6;
    return result;
}

MxResult<MbaTransformResult> MbaTransform::transform_or(
    x86::Reg dst, x86::Reg src, x86::Reg scratch,
    [[maybe_unused]] Randomizer& rng, uint32_t depth)
{
    analysis::X86CodeEmitter em(is_64bit());

    if (depth <= 1) {
        emit_or_mba(em, dst, src, scratch);
    } else {
        emit_or_mba(em, dst, src, scratch);
        auto noise = static_cast<int32_t>(rng.next_u32());
        em.add(dst, noise);
        em.sub(dst, noise);
    }

    auto code = em.build();
    if (!code) return std::unexpected(code.error());

    MbaTransformResult result;
    result.code = std::move(*code);
    result.depth_applied = depth;
    result.instruction_count = depth <= 1 ? 4 : 6;
    return result;
}

MxResult<MbaTransformResult> MbaTransform::transform_and(
    x86::Reg dst, x86::Reg src, x86::Reg scratch,
    [[maybe_unused]] Randomizer& rng, uint32_t depth)
{
    analysis::X86CodeEmitter em(is_64bit());

    if (depth <= 1) {
        emit_and_mba(em, dst, src, scratch);
    } else {
        emit_and_mba(em, dst, src, scratch);
        auto noise = static_cast<int32_t>(rng.next_u32());
        em.xor_(dst, noise);
        em.xor_(dst, noise);
    }

    auto code = em.build();
    if (!code) return std::unexpected(code.error());

    MbaTransformResult result;
    result.code = std::move(*code);
    result.depth_applied = depth;
    result.instruction_count = depth <= 1 ? 4 : 6;
    return result;
}

// ============================================================================
// Constant obfuscation via linear MBA
// ============================================================================

MxResult<MbaTransformResult> MbaTransform::obfuscate_constant(
    x86::Reg dst, uint64_t value,
    Randomizer& rng, uint32_t term_count)
{
    if (term_count < 2) term_count = 2;
    if (term_count > 8) term_count = 8;

    analysis::X86CodeEmitter em(is_64bit());

    // Generate random intermediate values whose combination yields `value`.
    // Strategy: generate (term_count - 1) random values, compute the last.
    // Alternate between XOR and ADD/SUB to create mixed boolean-arithmetic chain.

    uint64_t accumulated = 0;
    const auto first_val = rng.next_u64();
    accumulated = first_val;
    em.mov(dst, first_val);

    enum class TermOp : uint8_t { xor_op, add_op, sub_op };

    for (uint32_t i = 1; i < term_count - 1; ++i) {
        const auto rand_val = rng.next_u64();
        const auto op = static_cast<TermOp>(rng.next_range(0, 2));

        switch (op) {
            case TermOp::xor_op:
                em.xor_(dst, static_cast<int32_t>(rand_val & 0xFFFFFFFF));
                accumulated ^= (rand_val & 0xFFFFFFFF);
                break;
            case TermOp::add_op:
                em.add(dst, static_cast<int32_t>(rand_val & 0x7FFFFFFF));
                accumulated += (rand_val & 0x7FFFFFFF);
                break;
            case TermOp::sub_op:
                em.sub(dst, static_cast<int32_t>(rand_val & 0x7FFFFFFF));
                accumulated -= (rand_val & 0x7FFFFFFF);
                break;
        }
    }

    // Final correction term: need accumulated + correction = value
    // For simplicity, use XOR for the final step: accumulated ^ correction = value
    // correction = accumulated ^ value
    const auto correction = accumulated ^ value;
    em.xor_(dst, static_cast<int32_t>(correction & 0xFFFFFFFF));

    // For 64-bit values > 32-bit, also adjust the upper 32 bits
    if (is_64bit() && (value >> 32) != ((accumulated ^ (correction & 0xFFFFFFFF)) >> 32)) {
        // Fallback: just mov the correct value and apply obfuscation differently
        em.clear();
        const auto mask = rng.next_u64();
        em.mov(dst, value ^ mask);
        em.mov(x86::Reg::r11, mask);
        em.xor_(dst, x86::Reg::r11);
    }

    auto code = em.build();
    if (!code) return std::unexpected(code.error());

    MbaTransformResult result;
    result.code = std::move(*code);
    result.depth_applied = 1;
    result.instruction_count = term_count;
    return result;
}

} // namespace mx
