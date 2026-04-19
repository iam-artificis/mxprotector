/**
 * @file string_protection_pass.cpp
 * @brief [BUILDER] `IProtectionPass` facade for StringProtectionPass.
 *
 * The orchestration logic lives in `StringProtectionPipeline`; this
 * file is only the `IProtectionPass` contract.
 *
 * Pipeline walk-through (for reference — implemented in the leaf
 * files that the pipeline drives):
 *
 *   1. For every non-executable initialized-data section (typically
 *      `.rdata`), scan printable-ASCII candidates.
 *   2. For every executable section, find LEA xrefs that load a
 *      candidate's RVA. Candidates with zero xrefs are dropped.
 *   3. Filter strings whose bytes are base-relocation targets
 *      (overwriting them would break non-code consumers) and xrefs
 *      whose LEA shape / register can't carry a call rel32 rewrite.
 *   4. Assign a dense 0-based id to every surviving string.
 *   5. XOR-encrypt each surviving string with a per-string key.
 *   6. Emit `mx_str_get` (sticky / ephemeral) + one trampoline per
 *      usable xref.
 *   7. Compose the `.mxstr` section:
 *         [mx_str_get][trampolines][descriptor table][data pool]
 *      Optionally VM-lift the decryptor's XOR loop and append the
 *      VM blob to the section.
 *   8. Add the section via `SectionManager`, which assigns the
 *      final RVA. Patch the two (or three) disp32 slots inside
 *      `mx_str_get` and each trampoline's `call rel32`.
 *   9. Overwrite every LEA site in place with `call rel32
 *      <trampoline>` plus NOP padding. Wipe the plaintext bytes
 *      so `strings` output on the packed binary reveals nothing.
 */

#include "mxprotector/protection/string/string_protection_pass.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/protection/string/string_protection_pipeline.hpp"

namespace mx {

bool StringProtectionPass::is_applicable(
    const ProtectionContext& ctx) const noexcept
{
    // Only runs when the user asked for string protection.
    if (ctx.config().string_protection == StringProtectionMode::disabled) {
        return false;
    }
    // x64 PE only: the codegen emits AMD64 bytes and the layout
    // assumes 64-bit RIP-relative LEA encoding.
    if (!ctx.target().is_windows_pe_x64()) return false;
    return true;
}

MxStatus StringProtectionPass::execute(ProtectionContext& ctx) {
    return string_protect::StringProtectionPipeline{ctx}.execute();
}

} // namespace mx
