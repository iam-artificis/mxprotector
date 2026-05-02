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
    if (!ctx.config().enable_cfg_flattening) return false;
    // Dispatcher generation, MBA transitions and trampoline writers
    // all emit x64 instructions through `x86_code_emitter`. Gate on
    // `is_windows_pe_x64()` so non-PE / non-x64 inputs skip cleanly.
    // Driver and EFI targets are accepted: CFF rewrites only flow
    // control via `cmov` + indirect jumps and never relies on user-
    // mode runtime infrastructure.
    if (!ctx.target().is_windows_pe_x64()) return false;
    return true;
}

MxStatus CfgFlatteningPass::execute(ProtectionContext& ctx) {
    return cff::CfgFlatteningPipeline{ctx}.execute();
}

} // namespace mx
