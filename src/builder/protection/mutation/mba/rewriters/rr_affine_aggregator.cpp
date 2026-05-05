/**
 * @file rr_affine_aggregator.cpp
 * @brief Per-family aggregator for the r-r (register-register) affine
 *        MBA rewriters.
 *
 * Five r-r affine shapes — one per ALU op family (ADD/SUB/XOR/OR/
 * AND) — share the same coefficient algebra as the imm32 affine
 * shapes. Each registers exactly one rewriter; the substitution
 * adapter picks among them by op when the engine encounters a
 * matching `01 /r ... 33 /r` site.
 *
 * Why a separate aggregator instead of folding into the existing
 * imm32 per-op aggregators (`register_add_imm_rewriters`, etc.):
 * the imm32 and r-r decoders match different encoding patterns
 * (memory-vs-register, imm-vs-reg). Putting them in the same
 * aggregator would couple the imm32 file to the r-r decoder for no
 * functional reason. Single-responsibility per aggregator file.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_groups.hpp"

#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

namespace mx::mutation::mba {

void register_rr_affine_rewriters(MbaRewriterRegistry& registry) {
    // One affine shape per r-r ALU family. Each shape opens a
    // 14-element coefficient family parameterised by per-site `t`,
    // matching the variety the imm32 affine shapes provide.
    registry.register_rewriter(factories::make_add_rr_affine());
    registry.register_rewriter(factories::make_sub_rr_affine());
    registry.register_rewriter(factories::make_xor_rr_affine());
    registry.register_rewriter(factories::make_or_rr_affine());
    registry.register_rewriter(factories::make_and_rr_affine());
}

} // namespace mx::mutation::mba
