/**
 * @file flag_consumer.hpp
 * @brief [BUILDER] EFLAGS read/write predicates over decoded x86/x64 instructions.
 *
 * ### Why this lives in `analysis/`
 *
 * Several mutation/obfuscation rewriters change the *value* of the
 * destination correctly but leave EFLAGS in a state that differs
 * from the original instruction (MBA's final `add` produces wrong
 * OF/AF; some imm8↔imm-neg pairs flip CF). When the very next
 * instruction is a flag-consumer (`JCC`, `SETcc`, `CMOVcc`, `ADC`,
 * `SBB`, `RCL`, `RCR`, `LAHF`, …), miscompiled flags break control
 * flow.
 *
 * The predicates below give the mutation engine a cheap, mnemonic-
 * based way to spot those sites so it can skip the rewrite. Keeping
 * the predicates in `analysis/` (rather than under `mutation/`) makes
 * them reusable by future passes — anti-static encoders, bogus-flow
 * insertion, VM lifters that want to assume a clean flag state — all
 * benefit from the same predicate.
 *
 * ### Conservatism
 *
 * The implementation is **mnemonic-based and conservative**. Mnemonics
 * are stable across Zydis upgrades and don't require parsing the
 * x86 flag-effect table at runtime. False positives (treating a
 * benign instruction as a consumer) are acceptable — they cost a
 * skipped rewrite at one site. False negatives (missing a real
 * consumer) are not — they break the protected binary at runtime.
 *
 * The functions are header-only because they're called from the
 * inner mutation loop (`MutationEngine::mutate_region`) and want to
 * inline cleanly.
 */

#pragma once

#include <string_view>

#include "mxprotector/analysis/instruction.hpp"

namespace mx::analysis {

/**
 * @brief Does `insn` read EFLAGS bits set by a preceding instruction?
 *
 * Returns true for:
 *   * Conditional branches (`JCC`) — read OF/CF/ZF/SF/PF depending on cc.
 *   * Conditional moves (`CMOVcc`) — same flag dependence as JCC.
 *   * Conditional sets (`SETcc`) — same.
 *   * Carry-chain ops: `ADC`, `SBB`, `RCL`, `RCR` — all read CF.
 *   * Flag-to-register transfers: `LAHF`, `INTO`.
 *   * Stack flag transfers: `PUSHF`, `PUSHFQ`, `PUSHFD`.
 *   * Flag-aware loops: `LOOPE`, `LOOPNE` (and zf-named aliases).
 *
 * Branches that do *not* read flags (`JMP`, `JECXZ`, `LOOP`, `CALL`,
 * `RET`) return false — they affect control flow but not via the
 * preceding instruction's flag side-effects.
 */
[[nodiscard]] inline bool consumes_eflags(
    const Instruction& insn) noexcept
{
    if (insn.is_conditional_branch()) return true;

    const std::string_view m = insn.mnemonic();
    if (m.starts_with("set"))  return true;  // setz, setne, setcc...
    if (m.starts_with("cmov")) return true;  // cmovz, cmovne, cmovcc...

    if (m == "adc" || m == "sbb" || m == "rcl" || m == "rcr") return true;
    if (m == "lahf" || m == "into") return true;
    if (m == "pushf" || m == "pushfq" || m == "pushfd") return true;
    if (m == "loope" || m == "loopne" ||
        m == "loopz" || m == "loopnz") return true;

    return false;
}

/**
 * @brief Does `insn` overwrite **the full flag set we care about**?
 *
 * "Care about" means CF + OF + ZF + SF + PF + AF — the bits that
 * MBA-style rewrites disturb relative to their replaced original.
 * A successor that touches a *strict subset* doesn't make the prior
 * site safe: if the rewrite produced a wrong CF, an `inc` (which
 * overwrites ZF/SF/OF/PF/AF but **leaves CF intact**) will let the
 * stale CF leak to a later `jc` and miscompile the program.
 *
 * Returning true is therefore restricted to mnemonics whose
 * encoding-level flag effects clobber every bit in the set:
 *
 *   * `add`, `sub`, `cmp`           — full result-derived set.
 *   * `and`, `or`, `xor`, `test`    — write CF=0/OF=0/ZF/SF/PF and
 *                                     leave AF undefined; the
 *                                     "undefined" verdict from the
 *                                     SDM means a downstream reader
 *                                     of AF is broken in any
 *                                     compilation, not just ours, so
 *                                     treating these as full-killers
 *                                     is sound.
 *   * `neg`                         — writes CF=(op != 0) plus OF/
 *                                     SF/ZF/AF/PF.
 *   * `popf`/`popfq`/`popfd`/`sahf` — overwrite the whole register
 *                                     from memory or AH.
 *
 * Mnemonics deliberately omitted because they preserve at least one
 * bit:
 *
 *   * `inc`, `dec`           — preserve CF.
 *   * `mul`, `imul`, `div`,
 *     `idiv`                 — leave ZF/SF/PF undefined; cannot
 *                              promise full overwrite.
 *   * `shl`, `shr`, `sar`,
 *     `rol`, `ror`,
 *     `shld`, `shrd`         — count-dependent flag effects (count=0
 *                              preserves *all* flags); a static
 *                              walker can't always know the count.
 *   * `bt`, `btc`, `btr`,
 *     `bts`, `bsf`, `bsr`    — narrow CF/ZF effects; other bits
 *                              preserved.
 *   * `stc`, `clc`, `cmc`,
 *     `std`, `cld`           — touch single bits.
 *   * `mov`, `lea`, `xchg`,
 *     `push`, `pop`, `nop`,
 *     prefixes               — preserve flags entirely.
 *
 * Any mnemonic not enumerated above is assumed flag-preserving, so
 * the lookahead keeps walking forward until it either finds a true
 * full-killer or hits a reader / control-flow boundary / the limit.
 */
[[nodiscard]] inline bool writes_eflags(
    const Instruction& insn) noexcept
{
    const std::string_view m = insn.mnemonic();

    if (m == "add" || m == "sub" || m == "cmp") return true;
    if (m == "and" || m == "or"  || m == "xor" || m == "test") return true;
    if (m == "neg") return true;

    if (m == "popf" || m == "popfq" || m == "popfd" || m == "sahf") {
        return true;
    }

    return false;
}

/**
 * @brief Is it safe to clobber EFLAGS at `instructions[index]`?
 *
 * Walks forward from `index + 1` looking for the first instruction
 * that either *consumes* or *overwrites* EFLAGS:
 *
 *   * Hit a writer first → safe (the stale flags die before
 *     reaching a consumer).
 *   * Hit a consumer first → unsafe.
 *   * Hit a branch / call / return → unsafe (we cannot follow
 *     control flow to verify the target's flag dependence).
 *   * Walk runs off the end of the region → unsafe (we don't know
 *     what's beyond the decoded window).
 *
 * `lookahead_limit` caps how many instructions are inspected — the
 * mutation engine processes potentially-long sections, and an
 * unbounded walk would amplify per-site cost without changing the
 * outcome for typical compiled code (carry chains break by the
 * second or third instruction).
 *
 * @tparam InstructionRange   `std::ranges::random_access_range`-like
 *                            container of `Instruction`. Templated
 *                            so unit tests can pass a `std::vector`
 *                            and the engine can pass its own.
 *
 * @param  instructions       Decoded instruction stream.
 * @param  index              Position of the candidate instruction.
 * @param  lookahead_limit    Max number of forward instructions to
 *                            inspect. Default 8.
 *
 * @return `true` iff a flag-writing instruction precedes any
 *         flag-consumer or control-flow boundary within the limit.
 */
template <class InstructionRange>
[[nodiscard]] bool safe_to_clobber_flags_after(
    const InstructionRange& instructions,
    std::size_t             index,
    std::size_t             lookahead_limit = 8) noexcept
{
    const std::size_t n = instructions.size();
    const std::size_t end = (lookahead_limit < n - index)
        ? index + 1 + lookahead_limit
        : n;

    for (std::size_t i = index + 1; i < end; ++i) {
        const auto& next = instructions[i];

        // Control flow ends our visibility — we can't follow the edge
        // to verify the target's dependence on EFLAGS.
        if (next.is_branch() || next.is_call() || next.is_return()) {
            return false;
        }

        if (consumes_eflags(next)) return false;
        if (writes_eflags(next))   return true;
    }

    return false;
}

} // namespace mx::analysis
