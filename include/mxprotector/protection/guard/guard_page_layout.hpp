/**
 * @file guard_page_layout.hpp
 * @brief Pure builder that produces one `.mxguard` page from a body.
 *
 * Factored out of `GuardPass` to keep the page layout byte-level
 * operation testable in isolation. The function consumes a body byte
 * range plus a build-time `guard_id`, emits a `kGuardPageSize`-byte
 * page that the pass later inserts into the `.mxguard` section, and
 * reports the offsets of every field the pass needs to finalise.
 *
 * ## Page layout (Commit 3a onwards — final shape)
 *
 * ```
 *     [0 .. 5)                         int3 + 4-byte guard_id (entry trigger)
 *     [5 .. 5 + body_size)             body bytes (verbatim copy)
 *     [5 + body_size .. 5 + body_size + 5)   int3 + 4-byte guard_id (exit trigger)
 *     [5 + body_size + 5 .. kGuardPageSize)  polymorphic junk
 * ```
 *
 * Both `int3 + tag` windows are ALWAYS plaintext. The CPU reaches
 * these bytes twice per guard activation — once at entry (the
 * source-side `jmp rel32 <page>` lands on offset 0) and once at exit
 * (after the last body instruction executes). Each `int3` triggers
 * `EXCEPTION_BREAKPOINT`, the Vectored Exception Handler catches it,
 * decodes the 4-byte tag that follows to confirm identity, and
 * rewrites `CONTEXT.Rip` to either the body start (entry) or the
 * `return_rva` stored in the descriptor table (exit). No physical
 * `ret` or `jmp` lives on the page — the control transfer is
 * implemented entirely through `CONTEXT.Rip` modification from the
 * VEH, which is why the user explicitly asked for "давай не эмитеть
 * ret" during the design phase.
 *
 * Commit 3b adds encryption-at-rest for the body and junk regions
 * while keeping the two 5-byte int3+tag windows as plaintext (the
 * "skip windows" invariant). The encryption plumbing reuses the
 * offsets this builder already reports:
 *   * plaintext windows: `[0 .. 5)` and `[exit_int3_offset ..
 *     exit_int3_offset + 5)`
 *   * encrypted regions: `[body_offset .. exit_int3_offset)` and
 *     `[junk_offset .. kGuardPageSize)`
 *
 * ## Why the body is preceded by int3, not reached directly
 *
 * An earlier draft had the source-side `jmp` land directly on the
 * first body byte and used a trailing `jmp rel32 <return_rva>` as
 * the exit mechanism (Commit 2 prototype). That shape cannot survive
 * Commit 3b's encryption: once the body is ciphertext at rest, the
 * very first byte the CPU tries to execute after the `jmp` is
 * garbage, and the VEH never gets a chance to decrypt. The int3+tag
 * window sits at a fixed plaintext offset so the CPU always lands
 * on a valid breakpoint instruction regardless of the body's
 * encryption state, and the VEH decodes the tag to identify which
 * guard was entered.
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
 * `GuardPass` reads these back after calling `build_guard_page` and
 * uses them to fill the per-guard `GuardDescriptor` record once the
 * page's runtime RVA is known. Keeping the offsets in their own
 * struct means the layout invariant "entry int3 at 0, body at 5,
 * exit int3 at 5+body_size" lives in exactly one place.
 */
struct GuardPageLayout {
    /// `kGuardPageSize` bytes of page content — ready for `.mxguard`.
    ByteBuffer bytes;

    /// Offset of the entry int3 instruction inside the page.
    /// Always `0` — every guard starts at the page boundary.
    uint32_t entry_int3_offset = 0;

    /// Offset of the first body byte inside the page. Always `5`
    /// (right past the entry int3 + 4-byte guard_id tag).
    uint32_t body_offset = 0;

    /// Number of body bytes copied from the source. Matches the
    /// `body.size()` argument passed to `build_guard_page`.
    uint32_t body_size = 0;

    /// Offset of the exit int3 instruction inside the page.
    /// Equals `body_offset + body_size`. The 4-byte exit tag lives
    /// at `exit_int3_offset + 1 .. exit_int3_offset + 5`.
    uint32_t exit_int3_offset = 0;

    /// First byte of polymorphic junk filling, i.e. the byte right
    /// after the 5-byte exit int3+tag window. Runs up to
    /// `bytes.size()`.
    uint32_t junk_offset = 0;
};

/// Plaintext window size in bytes — `int3` (`0xCC`) opcode followed
/// by a 4-byte little-endian `guard_id` tag. Both entry and exit
/// windows share this layout so the VEH code path is symmetric.
inline constexpr uint32_t kGuardInt3TagSize = 5;

/**
 * @brief Build one `.mxguard` page from a guard body + guard id.
 *
 * Fails with a clear error when the body + two int3+tag windows
 * cannot fit in a single page. Multi-page bodies are deliberately
 * unsupported — in the design discussion we agreed to reject them
 * rather than chain pages, because concurrent-thread re-entry plus
 * multi-page decryption would explode the VEH state machine.
 *
 * The emitted tags are little-endian 4-byte copies of `guard_id`,
 * placed immediately after each `0xCC` byte. They are not strictly
 * needed for VEH dispatch (the handler matches Rip against the
 * descriptor table directly), but embedding them makes static
 * fingerprints less useful — every guard's int3 windows look
 * distinct byte-wise.
 *
 * The polymorphic junk tail is drawn from `rng.next_u8()`. Commit 3b
 * will encrypt this range at build time, so the distribution is
 * intentionally indistinguishable from ciphertext.
 *
 * @param body       Body bytes copied from the source section
 *                   between the `MX_GUARD_BEGIN` and `MX_GUARD_END`
 *                   markers.
 * @param guard_id   Build-time identifier baked into both int3 tags.
 * @param rng        Randomizer used to fill the junk tail.
 * @param page_size  Page granularity (defaults to `kGuardPageSize`;
 *                   overridable for unit tests that want small pages).
 * @return           Filled `GuardPageLayout` or an `MxError`.
 */
[[nodiscard]] MxResult<GuardPageLayout> build_guard_page(
    ByteView    body,
    uint32_t    guard_id,
    Randomizer& rng,
    uint32_t    page_size = kGuardPageSize);

} // namespace mx::guard
