/**
 * @file mba_rewriter_registry.cpp
 * @brief Implementation of `MbaRewriterRegistry` — see header.
 *
 * `create_default()` is the only place that knows which rewriter
 * families ship by default. Each family lives in its own TU and
 * exposes one `register_*_rewriters` entry point. Adding an MBA
 * family is one new file under `mba/rewriters/`, one declaration
 * in `mba_rewriter_groups.hpp`, and one call below — no edits to
 * the registry class itself.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

#include "mxprotector/protection/mutation/mba/mba_rewriter_groups.hpp"

namespace mx::mutation::mba {

void MbaRewriterRegistry::register_rewriter(
    std::unique_ptr<IMbaRewriter> rewriter)
{
    if (rewriter) {
        rewriters_.push_back(std::move(rewriter));
    }
}

const IMbaRewriter* MbaRewriterRegistry::find(
    std::string_view name) const noexcept
{
    for (const auto& rewriter : rewriters_) {
        if (rewriter && rewriter->name() == name) {
            return rewriter.get();
        }
    }
    return nullptr;
}

std::vector<const IMbaRewriter*> MbaRewriterRegistry::find_matching(
    const analysis::Instruction& insn) const
{
    std::vector<const IMbaRewriter*> result;
    result.reserve(rewriters_.size());
    for (const auto& rewriter : rewriters_) {
        if (rewriter && rewriter->matches(insn)) {
            result.push_back(rewriter.get());
        }
    }
    return result;
}

MbaRewriterRegistry MbaRewriterRegistry::create_default() {
    MbaRewriterRegistry registry;

    // Five additive / Boolean MBA identities. They cover every
    // group-1 ALU op the imm32 decoder accepts, so an arbitrary
    // `81 /<op> id` instruction lands on exactly one matching
    // family — no overlap, no gap.
    register_add_imm_rewriters(registry);
    register_sub_imm_rewriters(registry);
    register_xor_imm_rewriters(registry);
    register_or_imm_rewriters(registry);
    register_and_imm_rewriters(registry);

    // MOV-imm family covers both the 5/6-byte `mov r32, imm32`
    // (`B8+rd id`) and the 10/11-byte `mov r64, imm64`
    // (`REX.W B8+rd iq`) encodings — three shapes per width.
    register_mov_imm_rewriters(registry);

    return registry;
}

} // namespace mx::mutation::mba
