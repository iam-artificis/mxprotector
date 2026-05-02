/**
 * @file mutation_engine.cpp
 * @brief Implementation of `MutationEngine` — extracted from
 *        `mutation_pass.cpp` to keep both translation units inside
 *        the project's ~300 LOC soft cap.
 *
 * The engine has one public entry point — `mutate_region` — which
 * walks the disassembled instructions, asks the rule registry for
 * matching substitutions, applies them either in place (size match)
 * or via the optional `IExpansionSink` (size grew, original ≥ 5
 * bytes), and feeds the trace-hints sidecar so the MCP can label
 * substituted bytes after the fact.
 *
 * Position-independence guard: when the sink is consulted, the
 * engine first asks the disassembler to decode the *replacement*
 * bytes and rejects the redirect if any decoded instruction is a
 * branch / call / return. Today's substitution rules emit only
 * register-only ops, so the guard never fires for stock builds; it
 * exists to stop a future rule that emits a relative operand from
 * silently producing miscompiled overflow code.
 */

#include "mxprotector/protection/mutation/mutation_engine.hpp"

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/protection/mutation/overflow/expansion_sink.hpp"
#include "mxprotector/protection/mutation/overflow/jmp_emit.hpp"

#include <algorithm>
#include <utility>

namespace mx {

MutationEngine::MutationEngine(SubstitutionRuleRegistry rules,
                               std::unique_ptr<JunkGenerator> junk,
                               Randomizer& rng)
    : rules_(std::move(rules))
    , junk_gen_(std::move(junk))
    , rng_(rng)
{}

MutationEngine::~MutationEngine() = default;

namespace {

/// Confirm a replacement is safe to relocate to a fresh RVA.
///
/// Re-decode the replacement bytes through the same disassembler the
/// engine already uses. If decoding fails or any decoded instruction
/// is a branch / call / return — all of which encode a relative
/// operand — refuse the redirect. Today's rules are register-only,
/// so the guard never fires; tomorrow's rules will be caught here
/// before they corrupt control flow.
[[nodiscard]] bool replacement_is_position_independent(
    analysis::IDisassembler& disasm,
    ByteView                 replacement,
    Va                       at_va)
{
    auto decoded = disasm.decode_buffer(replacement, at_va);
    if (!decoded) return false;
    for (const auto& ri : *decoded) {
        if (ri.is_branch() || ri.is_call() || ri.is_return()) {
            return false;
        }
    }
    return true;
}

/// Patch a slot of `slot_size` bytes at `code + offset` so that the
/// next executed byte is `JMP rel32 → overflow_rva`. The trailing
/// `slot_size - 5` bytes are filled with `0x90` NOPs so a linear
/// disassembler decoding the slot keeps walking past the JMP without
/// stumbling on garbage. Pre-condition: `slot_size >= 5`.
void patch_jmp_with_nop_pad(MutableByteView code,
                            std::size_t      offset,
                            std::uint32_t    slot_size,
                            Rva              site_rva,
                            Rva              overflow_rva)
{
    const auto jmp = mx::mutation::overflow::encode_jmp_rel32(
        site_rva, overflow_rva);
    std::copy(jmp.begin(), jmp.end(), code.data() + offset);
    std::fill(code.data() + offset + jmp.size(),
              code.data() + offset + slot_size,
              static_cast<std::uint8_t>(0x90));
}

} // anonymous namespace

MxResult<uint32_t> MutationEngine::mutate_region(
    MutableByteView code,
    Va base_address,
    analysis::IDisassembler& disasm,
    ProtectionContext& ctx)
{
    if (code.empty()) {
        ctx.log("  MutationEngine: пустой регион, пропуск");
        return uint32_t{0};
    }

    auto decode_result = disasm.decode_buffer(
        ByteView{code.data(), code.size()}, base_address);

    if (!decode_result) {
        ctx.log_fmt("  MutationEngine: ошибка декодирования по VA 0x{:016X}: {}",
            base_address, decode_result.error().message());
        return std::unexpected(decode_result.error());
    }

    const auto& instructions = *decode_result;
    if (instructions.empty()) {
        ctx.log("  MutationEngine: декодировано 0 инструкций, пропуск");
        return uint32_t{0};
    }

    uint32_t mutations_applied = 0;
    uint32_t junk_inserted = 0;

    for (const auto& insn : instructions) {
        if (insn.is_branch() || insn.is_call() || insn.is_return()) {
            continue;
        }

        auto matching_rules = rules_.find_matching(insn);
        if (matching_rules.empty()) continue;

        if (!rng_.next_bool(substitution_probability_)) continue;

        const uint32_t rule_idx = rng_.next_range(0,
            static_cast<uint32_t>(matching_rules.size() - 1));
        const auto* rule = matching_rules[rule_idx];

        auto replacement = rule->apply(insn, rng_);

        const auto offset = static_cast<size_t>(insn.address() - base_address);
        if (offset + insn.length() > code.size()) {
            ctx.log_fmt("  MutationEngine: запись за пределами буфера для '{}' по VA 0x{:016X}",
                insn.to_string(), insn.address());
            continue;
        }

        // Fast path: rule produced a size-preserving substitution.
        if (replacement.size() == insn.length()) {
            std::copy(replacement.begin(), replacement.end(), code.data() + offset);
            ++mutations_applied;
            ++total_substitutions_;
            if (ctx.config().emit_trace_hints) {
                const auto rva = static_cast<std::uint32_t>(
                    insn.address() - ctx.pe_image().image_base());
                ctx.trace_hints().add_mutation_site(
                    rva,
                    static_cast<std::uint32_t>(insn.length()),
                    static_cast<std::uint32_t>(replacement.size()),
                    analysis::MutationSiteKind::substitution);
            }
            continue;
        }

        // Size mismatch. Three cases:
        //   1. Replacement shorter — would need padding shrink; not
        //      handled (skip).
        //   2. Replacement longer + no sink + slot < 5 — cannot fit
        //      `JMP rel32`; skip.
        //   3. Replacement longer + sink + slot ≥ 5 + replacement is
        //      position-independent — redirect via sink.
        if (replacement.size() < insn.length() ||
            expansion_sink_ == nullptr      ||
            insn.length() < mx::mutation::overflow::kJmpRel32Size)
        {
            ctx.log_fmt("  MutationEngine: правило '{}' вернуло {} байт вместо {} для '{}' по VA 0x{:016X} — пропуск",
                rule->name(), replacement.size(), insn.length(),
                insn.to_string(), insn.address());
            continue;
        }

        if (!replacement_is_position_independent(
                disasm,
                ByteView{replacement.data(), replacement.size()},
                insn.address()))
        {
            ctx.log_fmt("  MutationEngine: правило '{}' эмитит position-dependent байты для '{}' — пропуск redirect",
                rule->name(), insn.to_string());
            continue;
        }

        const Rva site_rva = static_cast<Rva>(
            insn.address() - ctx.pe_image().image_base());

        mx::mutation::ExpansionRequest req{
            .site_rva       = site_rva,
            .site_size      = static_cast<std::uint32_t>(insn.length()),
            .expanded_bytes = ByteView{replacement.data(), replacement.size()},
        };

        auto plan = expansion_sink_->plant(req);
        if (!plan) {
            ctx.log_fmt("  MutationEngine: expansion sink '{}' отклонил redirect '{}': {}",
                expansion_sink_->name(), insn.to_string(),
                plan.error().message());
            continue;
        }

        patch_jmp_with_nop_pad(
            code, offset,
            static_cast<std::uint32_t>(insn.length()),
            site_rva, plan->overflow_rva);

        ++mutations_applied;
        ++total_substitutions_;
        ++total_redirected_expansions_;

        if (ctx.config().emit_trace_hints) {
            ctx.trace_hints().add_mutation_site(
                site_rva,
                static_cast<std::uint32_t>(insn.length()),
                plan->overflow_size,
                analysis::MutationSiteKind::substitution);
        }
    }

    total_junk_insertions_ += junk_inserted;

    return mutations_applied;
}

} // namespace mx
