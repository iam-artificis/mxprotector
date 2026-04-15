/**
 * @file guard_page_layout.hpp
 * @brief Pure builder that produces one `.mxguard` page from a body.
 *
 * Factored out of `GuardPass` to keep the page layout byte-level
 * operation testable in isolation. The function consumes a body byte
 * range and a `Randomizer`, emits a `kGuardPageSize`-byte page that
 * the pass later inserts into the `.mxguard` section, and reports
 * the patch-site offsets the pass uses to finalise:
 *
 *   * the body bytes verbatim at `body_offset`,
 *   * a 5-byte `jmp rel32 0` placeholder at `exit_jmp_offset` that
 *     the pass back-patches with the final return-RVA delta after
 *     `.mxguard` has been placed and its runtime RVA is known,
 *   * polymorphic junk filling the remainder of the page up to
 *     `kGuardPageSize`.
 *
 * Commit 2 layout (no encryption, no VEH yet):
 *
 * ```
 *     [0 .. body_size)                   body bytes (verbatim copy)
 *     [body_size .. body_size + 5)       jmp rel32 <return_rva>  (placeholder)
 *     [body_size + 5 .. kGuardPageSize)  polymorphic junk (rng bytes)
 * ```
 *
 * Commit 3 will change the layout to:
 *
 * ```
 *     [0 .. 5)                        int3 + tag (entry trigger — plaintext at rest)
 *     [5 .. 5 + body_size)            body bytes (encrypted at rest)
 *     [5 + body_size .. 5 + body_size + 5)   int3 + tag (exit trigger — plaintext at rest)
 *     [5 + body_size + 5 .. kGuardPageSize)  polymorphic junk (encrypted at rest)
 * ```
 *
 * That shape is a deliberate refinement, not a rewrite — the
 * `body_offset` and descriptor plumbing we introduce here stays the
 * same; only the trailing trampoline changes from a physical
 * `jmp rel32` to a VEH-emulated `Rip = return_rva` in Commit 3.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"

namespace mx::guard {

/**
 * @brief Per-page patch slots produced by `build_guard_page`.
 *
 * `GuardPass` reads these back after calling `build_guard_page`
 * and knows exactly where to apply the exit-jump relocation once
 * the final runtime RVA of the page is known. Keeping the offsets
 * in their own struct (rather than returning a pair or re-deriving
 * them on the caller side) means the layout invariant "exit jmp is
 * always at `body_offset + body_size`" lives in exactly one place.
 */
struct GuardPageLayout {
    /// 4 KiB of page bytes — body + jmp + junk, ready for `.mxguard`.
    ByteBuffer bytes;

    /// Offset inside `bytes` where the user body starts. In Commit 2
    /// this is always 0. Commit 3 will bump it to 5 to leave room for
    /// the plaintext entry `int3 + tag` window.
    uint32_t body_offset = 0;

    /// Number of body bytes copied from the source. Matches the
    /// `body` argument passed to `build_guard_page`.
    uint32_t body_size = 0;

    /// Offset inside `bytes` of the `0xE9` byte of the exit
    /// `jmp rel32`. The 4-byte rel32 slot lives at
    /// `exit_jmp_offset + 1 .. exit_jmp_offset + 5` and is emitted as
    /// a zero placeholder that `GuardPass::apply_exit_jump` later
    /// writes with the final return-RVA delta.
    uint32_t exit_jmp_offset = 0;

    /// First byte of polymorphic junk filling, i.e. the byte right
    /// after the 5-byte exit jump. Runs up to `bytes.size()`.
    uint32_t junk_offset = 0;
};

/**
 * @brief Build one `.mxguard` page from a guard-body byte range.
 *
 * Fails with a clear error when the body + trailing jump cannot fit
 * in a single page — in that case the caller should skip the guard
 * (and log a warning). Multi-page bodies are a future-commit concern
 * and deliberately unsupported here.
 *
 * The emitted `jmp rel32` is a placeholder filled with zeros for the
 * 4-byte rel32. `GuardPass` patches the real rel32 after the page
 * has been injected into the `.mxguard` section and its runtime RVA
 * is known.
 *
 * The polymorphic junk is drawn from `rng.next_u8()` — a uniform
 * byte distribution. These bytes are never executed in Commit 2
 * (the exit jump terminates the page's live region) and will become
 * encrypted ciphertext in Commit 3, so any plausible distribution
 * is fine; uniform noise matches what the encrypted tail will look
 * like in future builds and avoids an accidental "all zeros at rest"
 * fingerprint.
 *
 * @param body       Body bytes extracted from the source section,
 *                   between the `MX_GUARD_BEGIN` and `MX_GUARD_END`
 *                   markers (markers themselves excluded).
 * @param rng        Randomizer used to generate the polymorphic junk.
 *                   The same `rng` instance is advanced by exactly
 *                   `kGuardPageSize - body.size() - 5` bytes.
 * @param page_size  Page granularity. Defaults to `kGuardPageSize`
 *                   (4 KiB); the override exists for unit tests that
 *                   want smaller pages to cover edge cases without
 *                   allocating 4 KiB buffers.
 * @return           Filled `GuardPageLayout` on success, or an
 *                   `MxError` with a descriptive message on failure.
 */
[[nodiscard]] MxResult<GuardPageLayout> build_guard_page(
    ByteView    body,
    Randomizer& rng,
    uint32_t    page_size = kGuardPageSize);

} // namespace mx::guard
