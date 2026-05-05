/**
 * @file unary_aggregator.cpp
 * @brief Per-family aggregator for the unary (NOT/NEG) MBA rewriters.
 *
 * Two shapes per op (4 rewriters total) — the MBA adapter picks one
 * uniformly per call site so two NOT or two NEG instructions in the
 * same binary land on visually-different bodies even though both
 * reduce to the same arithmetic operation.
 *
 * The targeted instructions are 2 bytes (no REX) or 3 bytes (with
 * REX) — below the 5-byte JMP rel32 redirect threshold. The engine's
 * multi-instruction redirect (Phase 11) drags 1..3 following ops
 * into the slot to widen it to ≥ 5 bytes.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_groups.hpp"

#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

namespace mx::mutation::mba {

void register_unary_rewriters(MbaRewriterRegistry& registry) {
    // NOT shapes: two-complement (NEG + SUB-1) and xor-cancel
    // (XOR K + XOR ~K). Different defeat strategies — TWO emits NEG
    // (changing the unary signal opcode), XOR-CANCEL emits no unary
    // ops at all.
    registry.register_rewriter(factories::make_not_rm_twocomplement());
    registry.register_rewriter(factories::make_not_rm_xor_cancel());

    // NEG shapes: not-add1 (NOT + ADD-1, leans on NOT to materialise
    // -x) and zero-sub (MOV + XOR + SUB, no unary ops at all).
    registry.register_rewriter(factories::make_neg_rm_not_add1());
    registry.register_rewriter(factories::make_neg_rm_zero_sub());
}

} // namespace mx::mutation::mba
