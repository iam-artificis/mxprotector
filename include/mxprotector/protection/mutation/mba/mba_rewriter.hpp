/**
 * @file mba_rewriter.hpp
 * @brief [PROTECTION] Mixed-Boolean-Arithmetic rewriter abstraction.
 *
 * ### Why
 *
 * Symbolic engines (angr, Triton) and SMT solvers (Z3) reduce
 * arithmetic by structural pattern matching: `add reg, K` is
 * trivially folded into a constant offset. MBA rewrites replace
 * each ALU op with an algebraically-equivalent sequence that mixes
 * arithmetic and Boolean operators (`x + y ≡ (x ^ y) + 2*(x & y)`,
 * etc.), forcing the solver to expand the expression and exploding
 * its proof obligation. Chained / non-linear MBA defeats most
 * existing tactics outright.
 *
 * ### Contract
 *
 * One `IMbaRewriter` knows how to:
 *
 *   1. Report whether it can rewrite a particular x86/x64
 *      instruction (`matches`).
 *   2. Emit the equivalent byte sequence (`rewrite`). The engine
 *      routes the result through the existing mutation expansion
 *      sink — so the bytes must be **position-independent** (no
 *      branches/calls/returns; the sink appends the JMP-back
 *      itself).
 *   3. Optionally consume a scratch register; the rewriter is
 *      expected to `push`/`pop` around its body so the surrounding
 *      register state is preserved.
 *
 * ### Variety axis
 *
 * Rewriters live on three axes that compose independently:
 *
 *   * **Identity family** — additive / Boolean / mixed / polynomial.
 *   * **Operand shape** — `<op> reg, imm32` / `<op> reg, reg`.
 *   * **Instruction class** — ADD, SUB, XOR, OR, AND, MOV.
 *
 * New rewriters drop a new file under `mba/rewriters/`, add a
 * one-liner to the registry's `create_default()`, and the rest of
 * the pipeline picks them up — no `MutationEngine` edits.
 *
 * SOLID:
 *   * SRP — one rewriter == one MBA expansion shape.
 *   * OCP — `MbaRewriterRegistry::create_default` is the only seam
 *     new rewriters plug into.
 *   * LSP — every rewriter is interchangeable; the
 *     `MbaSubstitutionRule` adapter picks one at random per site.
 *   * DIP — the adapter depends on `IMbaRewriter`, not concretes.
 *
 * Threading: `rewrite()` may mutate `Randomizer&`; concurrent calls
 * on the same rewriter with the same RNG are not safe. The mutation
 * pipeline is single-threaded by construction.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::mutation::mba {

/**
 * @brief Side-effect-free description of an MBA rewrite output.
 *
 * `bytes` are pure body bytes — no JMP-back, no JMP-out. The
 * mutation expansion sink appends a 5-byte JMP rel32 after these
 * bytes; callers must not include one themselves. `instruction_count`
 * is informational (number of decoded instructions inside `bytes`)
 * and feeds diagnostics + `trace_hints`.
 */
struct MbaRewriteResult {
    ByteBuffer    bytes;
    std::uint32_t instruction_count{0};
};

/**
 * @brief One MBA expansion shape. See header.
 */
class IMbaRewriter {
public:
    virtual ~IMbaRewriter() = default;

    /// Diagnostic / log-friendly name. Lowercase, hyphenated. Must
    /// be unique across registered rewriters so logs disambiguate.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /**
     * @brief Cheap predicate: does this rewriter cover `insn`?
     *
     * Implementations inspect raw bytes (mnemonic + opcode + ModR/M)
     * and never touch global state. Must be side-effect free.
     */
    [[nodiscard]] virtual bool matches(
        const analysis::Instruction& insn) const = 0;

    /**
     * @brief Emit the equivalent MBA body for `insn`.
     *
     * Pre-condition: `matches(insn) == true`. The returned
     * `MbaRewriteResult::bytes` are position-independent — the
     * engine re-decodes them through Zydis and refuses the redirect
     * if any branch/call/ret slips through, so violating this
     * pre-condition fails closed rather than miscompiling.
     *
     * @param insn Original instruction.
     * @param rng  Source of randomness for per-site polymorphism.
     * @return     `MbaRewriteResult` on success, propagated
     *             `MxError` on encoder failure.
     */
    [[nodiscard]] virtual MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const = 0;
};

/**
 * @brief Registry of MBA rewriters — one rewriter per identity.
 *
 * The adapter rule (`MbaSubstitutionRule`) holds a registry and
 * asks it for the matching set per site, then picks one uniformly
 * at random. Empty registries make the adapter a no-op — useful
 * for tests that exercise specific rewriters in isolation.
 *
 * SOLID:
 *   * SRP — registration + lookup only.
 *   * OCP — `register_rewriter` is the single seam. Adding an MBA
 *     family is one new file + one call.
 */
class MbaRewriterRegistry {
public:
    MbaRewriterRegistry()  = default;
    ~MbaRewriterRegistry() = default;

    MbaRewriterRegistry(const MbaRewriterRegistry&)            = delete;
    MbaRewriterRegistry& operator=(const MbaRewriterRegistry&) = delete;
    MbaRewriterRegistry(MbaRewriterRegistry&&) noexcept            = default;
    MbaRewriterRegistry& operator=(MbaRewriterRegistry&&) noexcept = default;

    /// Append `rewriter` to the registry. Insertion order is not
    /// observable — `find_matching` returns all matches and the
    /// caller picks uniformly at random.
    void register_rewriter(std::unique_ptr<IMbaRewriter> rewriter);

    /// Number of registered rewriters. Diagnostic only.
    [[nodiscard]] std::size_t size() const noexcept {
        return rewriters_.size();
    }

    /// Lookup a rewriter by `name()` — diagnostic helper used by
    /// tests that want to exercise one rewriter deterministically.
    [[nodiscard]] const IMbaRewriter* find(
        std::string_view name) const noexcept;

    /// Every rewriter whose `matches(insn)` returns `true`. Returned
    /// pointers are non-owning and live as long as the registry.
    [[nodiscard]] std::vector<const IMbaRewriter*> find_matching(
        const analysis::Instruction& insn) const;

    /**
     * @brief Build a registry pre-populated with every shipped
     *        rewriter. See `mba_rewriter_groups.hpp` for the
     *        per-family registration entry points.
     */
    [[nodiscard]] static MbaRewriterRegistry create_default();

private:
    std::vector<std::unique_ptr<IMbaRewriter>> rewriters_;
};

} // namespace mx::mutation::mba
