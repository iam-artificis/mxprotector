/**
 * @file mba_emit_helpers.hpp
 * @brief Shared emit helpers for imm32 MBA rewriters.
 *
 * Every imm32 rewriter pushes a scratch register, runs an MBA body
 * that uses dst + scratch, then pops scratch. The two helpers
 * below capture that boilerplate so the per-family rewriters stay
 * focused on the identity itself:
 *
 *   * `pick_scratch_for(dst)` — returns a caller-saved x64 register
 *     that does not collide with `dst`. Defaults to `r11` (free in
 *     the MS-x64 ABI / sysv-x64 caller-save), falling back to `r10`
 *     when `dst == r11`.
 *
 *   * `wrap_with_push_pop(em, scratch, body)` — emits
 *     `push scratch ; body() ; pop scratch` so the surrounding
 *     register state is preserved. Body is a callable that emits
 *     into `em`. The wrapper makes accidental imbalanced
 *     push/pop impossible by construction.
 *
 * Both helpers are header-only (small, called from every rewriter)
 * and have no link-time footprint — keeping link order independent
 * of where each rewriter family lives.
 */

#pragma once

#include <array>
#include <utility>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx::mutation::mba {

/**
 * @brief Pick a 64-bit scratch register that doesn't alias `dst`.
 *
 * Both `r11` and `r10` are caller-saved in MS-x64 and SysV-x64,
 * so they do not need to be preserved across the original
 * instruction's slot — but the rewriter still wraps its use in
 * push/pop because some niche call sites (TLS callbacks, syscall
 * stubs) treat r10/r11 as live. Push/pop costs 4 bytes; cheap
 * insurance.
 */
[[nodiscard]] inline x86::Reg pick_scratch_for(x86::Reg dst) noexcept {
    return dst == x86::Reg::r11 ? x86::Reg::r10 : x86::Reg::r11;
}

/**
 * @brief Emit `push scratch ; body(em) ; pop scratch` into `em`.
 *
 * Body is invoked with `em` as its only argument. The wrapper
 * guarantees the push/pop pair is balanced regardless of how the
 * body emits — there is no escape hatch that lets the body skip
 * the pop, which prevents future changes from accidentally
 * desyncing the stack.
 */
template <class Body>
void wrap_with_push_pop(
    analysis::X86CodeEmitter& em,
    x86::Reg                  scratch,
    Body&&                    body)
{
    em.push(scratch);
    std::forward<Body>(body)(em);
    em.pop(scratch);
}

/**
 * @brief Pick three 64-bit scratch registers that don't alias `dst`.
 *
 * The affine MBA shapes need three live scratches at once (one for
 * each basis term: OR, AND, XOR). `r10`, `r11`, `r12` are the
 * default — `r10`/`r11` are caller-saved on both Windows-x64 and
 * SysV-x64; `r12` is callee-saved but the rewriter wraps every use
 * in push/pop so the original value is restored before any control
 * transfer. If `dst` collides with one of the defaults, that slot
 * falls back to `r13` (also callee-saved, also push/pop-protected).
 */
[[nodiscard]] inline std::array<x86::Reg, 3>
pick_three_scratches_for(x86::Reg dst) noexcept {
    std::array<x86::Reg, 3> scratches = {
        x86::Reg::r10, x86::Reg::r11, x86::Reg::r12};
    for (auto& reg : scratches) {
        if (reg == dst) reg = x86::Reg::r13;
    }
    return scratches;
}

/**
 * @brief Emit `push s1 ; push s2 ; push s3 ; body(em) ; pop s3 ;
 *        pop s2 ; pop s1` into `em`.
 *
 * Same balance guarantee as `wrap_with_push_pop` — the body cannot
 * skip the pops, so the surrounding stack and register state is
 * always restored. Pop order is the reverse of push order so each
 * scratch's original value lands back in the correct register even
 * if the body trashed all three.
 */
template <class Body>
void wrap_with_push_pop_3(
    analysis::X86CodeEmitter&     em,
    const std::array<x86::Reg, 3>& scratches,
    Body&&                        body)
{
    em.push(scratches[0]);
    em.push(scratches[1]);
    em.push(scratches[2]);
    std::forward<Body>(body)(em);
    em.pop(scratches[2]);
    em.pop(scratches[1]);
    em.pop(scratches[0]);
}

} // namespace mx::mutation::mba
