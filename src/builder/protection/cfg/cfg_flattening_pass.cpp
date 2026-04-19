/**
 * @file cfg_flattening_pass.cpp
 * @brief `CfgFlatteningPass` — thin `IProtectionPass` facade.
 *
 * Everything the pass does lives inside `CfgFlatteningPipeline`. The
 * pass class only provides the IProtectionPass contract: name,
 * category, priority, applicability gate, and a single-line `execute`
 * that builds a pipeline and runs it.
 *
 * Pipeline layout (see per-file headers for detail):
 *
 *   * `state_reg_picker`       — Zydis scan for a free state-var GPR.
 *   * `cff_safety_filters`     — MSVC prologue + unwind-flags filters.
 *   * `cff_function_source`    — markers / `.map` / `.pdata` gather.
 *   * `cff_relocation_fixup`   — rel32 / disp32 rewrite after moves.
 *   * `cff_trampoline_writer`  — `jmp rel32 + 0xCC` emitter.
 *   * `cff_trampoline_section` — `.mxprot1` builder + commit.
 *   * `cfg_flattener`          — per-function flattening algorithm.
 *   * `cfg_flattening_pipeline`— per-execution orchestrator.
 *
 * The shape mirrors the `PackerPass` → `PackerPipeline` split from
 * R2.7 so every large pass follows the same thin-facade convention.
 */

#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/cfg/cfg_flattening_pipeline.hpp"

#include "mxprotector/core/context.hpp"

namespace mx {

bool CfgFlatteningPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    return ctx.config().enable_cfg_flattening;
}

MxStatus CfgFlatteningPass::execute(ProtectionContext& ctx) {
    return cff::CfgFlatteningPipeline{ctx}.execute();
}

} // namespace mx
