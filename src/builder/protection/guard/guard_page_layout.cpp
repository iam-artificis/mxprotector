/**
 * @file guard_page_layout.cpp
 * @brief Implementation of `build_guard_page` — see the header for
 *        the layout contract and rationale.
 */

#include "mxprotector/protection/guard/guard_page_layout.hpp"

#include <format>

namespace mx::guard {

namespace {

/// Size of the trailing `jmp rel32` trampoline in Commit 2. The slot
/// is always 5 bytes (`0xE9` + 4-byte rel32) regardless of where the
/// page ultimately lands — the rel32 is a delta, not an absolute, and
/// gets back-patched by `GuardPass::apply_exit_jump`.
constexpr uint32_t kExitJmpSize = 5;

} // anonymous namespace

MxResult<GuardPageLayout> build_guard_page(
    ByteView    body,
    Randomizer& rng,
    uint32_t    page_size)
{
    // The layout must hold the body AND the exit trampoline in a
    // single page. We reject anything larger here so the caller can
    // skip the offending guard with a clear log line instead of
    // silently producing a corrupted page.
    const uint64_t body_size = body.size();
    if (body_size == 0) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::region_too_small),
            "GuardPageLayout: тело пусто — нечего релоцировать"});
    }
    if (body_size + kExitJmpSize > page_size) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::pass_failed),
            std::format("GuardPageLayout: тело {} байт + {} байт exit jmp "
                        "не помещается в страницу {} байт",
                body_size, kExitJmpSize, page_size)});
    }

    GuardPageLayout out{};
    out.bytes.resize(page_size);

    // ----- Body ------------------------------------------------------
    // Commit 2 places the body at offset 0 — the caller's `call` or
    // `jmp` to `page_rva` lands directly on the first body byte.
    // Commit 3 will bump body_offset to 5 to leave a plaintext window
    // for the entry `int3 + tag` trigger.
    out.body_offset = 0;
    out.body_size   = static_cast<uint32_t>(body_size);
    if (body_size > 0) {
        std::copy(body.begin(), body.end(), out.bytes.begin() + out.body_offset);
    }

    // ----- Exit trampoline (placeholder rel32) -----------------------
    // `GuardPass::apply_exit_jump` fills the 4-byte rel32 slot once
    // the page's runtime RVA and the return RVA are both known. Until
    // then we emit an explicit zero so a premature execution (e.g. a
    // loader mis-jump during development) fails fast at the intended
    // slot instead of silently branching into polymorphic junk.
    out.exit_jmp_offset = out.body_offset + out.body_size;
    out.bytes[out.exit_jmp_offset] = 0xE9;
    out.bytes[out.exit_jmp_offset + 1] = 0x00;
    out.bytes[out.exit_jmp_offset + 2] = 0x00;
    out.bytes[out.exit_jmp_offset + 3] = 0x00;
    out.bytes[out.exit_jmp_offset + 4] = 0x00;

    // ----- Polymorphic junk tail -------------------------------------
    // Uniform random bytes fill the remainder of the page. Never
    // executed at runtime (the exit jump leaves the page before
    // reaching here), encrypted by Commit 3, so the distribution is
    // intentionally indistinguishable from ciphertext.
    out.junk_offset = out.exit_jmp_offset + kExitJmpSize;
    for (uint32_t i = out.junk_offset; i < page_size; ++i) {
        out.bytes[i] = rng.next_u8();
    }

    return out;
}

} // namespace mx::guard
