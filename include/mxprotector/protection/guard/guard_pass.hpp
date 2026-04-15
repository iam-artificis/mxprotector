/**
 * @file guard_pass.hpp
 * @brief [BUILDER] `GuardPass` — relocates MX_GUARD blocks to `.mxguard`.
 *
 * ## What this commit does (Commit 2 of the runtime-guards milestone)
 *
 * `GuardPass` is the first pass that actually touches guarded regions.
 * For every `MX_GUARD_BEGIN` / `MX_GUARD_END` pair discovered by the
 * marker scanner it does the following:
 *
 *   1. Reads the body bytes between the markers from the source
 *      (`.text`-like) section.
 *   2. Builds a `kGuardPageSize`-byte page via `build_guard_page`:
 *      `[body][jmp rel32 placeholder][polymorphic junk]`.
 *   3. Inserts every page contiguously into a newly-added section
 *      named via `ctx.section_names().guard`.
 *   4. Patches the source section: the entire marker+body+marker
 *      region becomes `jmp rel32 <page_rva>` followed by NOP padding.
 *   5. Back-patches each page's exit `jmp rel32` with the delta to
 *      the instruction immediately after the `MX_GUARD_END` marker
 *      in the source section, so that after the body finishes
 *      execution control flow returns to the original caller site.
 *
 * Commit 2 deliberately keeps the pages at rest as plaintext R+X
 * code. Encryption, the entry/exit `int3 + tag` triggers, and the
 * VEH dispatcher all arrive in Commits 3-7 as additive layers on
 * top of the plumbing established here.
 *
 * ## Why `jmp` (not `call`) into the page
 *
 * Relocated body bytes are raw compiler output and frequently access
 * the enclosing function's stack frame through `rsp` or `rbp`. A
 * `call` into the relocated body would push a return address onto
 * the stack, shifting `rsp` by 8 bytes and silently mis-aligning
 * every subsequent `rsp`-relative operand inside the body. A `jmp`
 * preserves the stack shape the compiler expected, and pairs with
 * a trailing `jmp <return_rva>` at the end of the relocated body to
 * hop back into the source section. No return address ever exists on
 * the stack for the guard, so there is nothing for the body to
 * mis-reference. This is why the final design has no physical `ret`
 * inside the guard page — see also the Commit 3 VEH contract.
 *
 * ## Pipeline position (priority = 350)
 *
 * `GuardPass` runs after mutation (100), obfuscation (200), and
 * virtualization (300), but BEFORE CFG flattening (400) and the
 * packer (800). Reasons:
 *
 *   * The body bytes we relocate have already been mutated /
 *     obfuscated / virtualised, so the relocated copy inherits
 *     the earlier protection.
 *   * CFG flattening can reorder basic blocks inside functions.
 *     Running before CFF means CFF sees the `jmp <page>` + NOPs
 *     we leave in `.text` as a single terminator instruction,
 *     which it leaves alone (jumps into a foreign section are
 *     CFG boundaries). Running AFTER CFF would risk CFF having
 *     already moved the function body to its trampoline section,
 *     and our marker-RVA lookup would fall into the NOP'd hole
 *     CFF left behind.
 *   * The packer at 800 runs last and picks up `.text` (plus VM
 *     and CFF sections) for encryption. It does NOT pick up
 *     `.mxguard` by name today, so the relocated bodies remain
 *     plaintext at runtime — which is exactly the Commit 2
 *     contract. Commit 3 will add VEH-driven encryption for
 *     `.mxguard` entirely outside the packer's section sweep.
 *
 * ## Failure semantics
 *
 * Every failure mode is per-guard:
 *
 *   * Body empty, body too large for a page, body read error, or
 *     patch range overflow → the offending guard is logged and
 *     skipped, no section changes.
 *
 *   * No guards applicable → pass reports "no guards, skip" and
 *     returns success without creating an empty `.mxguard`
 *     section. This keeps the binary identical to a marker-free
 *     input and avoids an easy fingerprint (empty `.mxguard` on
 *     every build).
 *
 * A fatal error returns `std::unexpected(MxError)` from `execute`.
 */

#pragma once

#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/pass.hpp"

namespace mx {

class ProtectionContext;

class GuardPass final : public IProtectionPass {
public:
    GuardPass() = default;
    ~GuardPass() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "GuardPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::anti_analysis;
    }

    [[nodiscard]] uint32_t priority() const noexcept override {
        return 350;
    }

    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
