/**
 * @file hash_opaque_predicate.hpp
 * @brief G6 — hash-based always-true opaque predicates.
 *
 * Plant a short inline x64 sequence that hashes a constant input and
 * compares the result against a build-time-baked target. Both the
 * input and the target are computed at build time so the runtime
 * branch is **always** the "true" path; the "false" branch contains
 * plausible-looking junk that is reachable in code form but never
 * executed.
 *
 * ## Why "hash-based" rather than mathematical
 *
 * Classic algebraic opaque predicates (`x*(x+1) % 2 == 0`,
 * `(x | 1) != 0`, etc.) defeat naive constant folders but fall over
 * to any decompiler that recognises the identity. Hash-based
 * predicates exploit the asymmetry between forward and inverse hash
 * computation:
 *
 *   * **Concrete evaluation** of `H(constant) == target` works fine
 *     for any engine that propagates the constant input through the
 *     hash. The predicate is then statically determinable. So we are
 *     not blocking the strongest engines — and in particular human
 *     reverse engineers can always trace the hash by hand.
 *
 *   * **Symbolic inversion** of `H(x) == target` (find `x` such that
 *     the predicate succeeds) is hard for SAT/SMT-based engines once
 *     the hash mixes integer multiplication with XOR and rotation.
 *     Engines like angr/KLEE/Triton routinely fall over on
 *     multiplication chains and either time out or skip the
 *     constraint entirely.
 *
 *   * **Both-paths exploration** by engines that don't try to prune
 *     the false branch wastes analyser time on dead code. The false
 *     branch contains plausible-looking instructions, so the engine
 *     dutifully decodes and explores them, multiplying its symbolic
 *     state without ever reaching real code.
 *
 * The practical protection is therefore proportional to:
 *   * **the cost of forcing engines to either evaluate the hash or
 *     give up** (proportional to the multiplication chain length),
 *     plus
 *   * **the surface area of the false branch** (inflates the
 *     reachable code set and confuses static disassemblers).
 *
 * ## Polymorphism
 *
 * Every predicate the helper emits is parameterised by a fresh
 * `HashOpaqueParams` (multipliers, XOR masks, rotation amount, input
 * value). Two builds with different RNG seeds produce different
 * constants in every imm32 slot of the predicate, so byte-pattern
 * fingerprints of one build do not match the next.
 *
 * ## Where to plant
 *
 * The helper writes into a `RawEmitter`, so any code emitter can
 * call it at any point. Suitable sites:
 *
 *   * **Packer entry stub** — once per build, runs at process entry.
 *     Highest visibility for static analysers.
 *   * **VM entry stub** — once per VM region, gates the dispatcher.
 *   * **Handler bodies** — multiplies the hash chain across every
 *     handler (highest cost / most polymorphism).
 *
 * The first deployment site is the packer entry stub; later commits
 * may add VM and handler sites.
 *
 * ## Register and flag effects
 *
 * The predicate clobbers `eax` and `rflags`. Callers that need either
 * preserved across the predicate must save them first.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::obf {

/**
 * @brief Per-build random parameters that fully describe one
 *        hash-based opaque predicate.
 *
 * The build-time hash function is:
 *
 *     uint32_t acc = input_value;
 *     acc *= mul1;
 *     acc ^= xor1;
 *     acc *= mul2;
 *     acc  = rotl(acc, rotation);
 *     acc *= mul3;
 *     acc ^= xor2;
 *     return acc;
 *
 * `mul1/mul2/mul3` are required to be **odd** so multiplication
 * stays bijective on `uint32_t` and the chain doesn't lose entropy
 * to trailing-zero collisions. `rotation` is in `[1, 31]` so the
 * `rol eax, imm8` instruction emits a non-degenerate rotation. The
 * other fields are unconstrained.
 *
 * `input_value` is the 4-byte payload that gets embedded inline at
 * the end of the predicate body and loaded via a rip-relative
 * `mov eax, [rip + disp32]` at runtime. The runtime hash sees this
 * value through a memory load (not as an immediate), so engines
 * that do not propagate constants through `[rip + disp]` reads see
 * the input as opaque.
 */
struct HashOpaqueParams {
    uint32_t input_value = 0;
    uint32_t mul1        = 1;
    uint32_t mul2        = 1;
    uint32_t mul3        = 1;
    uint32_t xor1        = 0;
    uint32_t xor2        = 0;
    uint8_t  rotation    = 1;
};

/**
 * @brief Draw a fresh `HashOpaqueParams` from `rng`.
 *
 * Multipliers are forced odd via `| 1`. The rotation amount is
 * uniformly sampled from `[1, 31]`. Two calls to this function with
 * the same RNG state produce identical params (used by tests for
 * determinism checks).
 */
[[nodiscard]] HashOpaqueParams randomize_hash_opaque_params(Randomizer& rng);

/**
 * @brief Run the build-time hash function for the given parameters.
 *
 * Used by the emitter to bake the comparison target into the
 * `cmp eax, imm32` slot of the emitted predicate, and exposed for
 * unit-test verification (a runtime interpreter would have to
 * reproduce this exact value for the predicate to fall through).
 */
[[nodiscard]] uint32_t compute_hash_opaque(const HashOpaqueParams& p) noexcept;

/**
 * @brief Emit one always-true hash-based opaque predicate into `e`.
 *
 * Layout (~50 bytes, exact size depends on which short branches
 * resolve to rel8):
 *
 *     mov   eax, [rip + .input - .past_mov]   ; load 4-byte input
 *     imul  eax, eax, mul1                    ; round 1
 *     xor   eax, xor1
 *     imul  eax, eax, mul2                    ; round 2
 *     rol   eax, rotation
 *     imul  eax, eax, mul3                    ; round 3
 *     xor   eax, xor2
 *     cmp   eax, target                       ; target = compute_hash_opaque(p)
 *     jne   short .false                      ; never taken at runtime
 *     jmp   short .end                        ; always taken — skip data
 *   .false:
 *     <plausible-looking junk>                ; never executed
 *   .input:
 *     dd    input_value                       ; 4 bytes, read by mov above
 *   .end:
 *
 * After the call returns, `rip` (in the emitter sense) points at
 * `.end` — the caller's next emission lands on the post-predicate
 * fall-through path. The predicate clobbers `eax` and `rflags`.
 *
 * @param e    Emitter to append the predicate bytes to.
 * @param p    Hash parameters. Use `randomize_hash_opaque_params` to
 *             draw a fresh polymorphic instance.
 * @param rng  Randomiser for the false-branch junk constants
 *             (independent of `p` so the same predicate parameters
 *             can pair with different junk on different invocations).
 */
void emit_hash_opaque_predicate(RawEmitter&             e,
                                const HashOpaqueParams& p,
                                Randomizer&             rng);

} // namespace mx::obf
