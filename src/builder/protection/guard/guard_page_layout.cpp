/**
 * @file guard_page_layout.cpp
 * @brief Implementation of `build_guard_page` — see header for the
 *        layout contract and rationale.
 */

#include "mxprotector/protection/guard/guard_page_layout.hpp"

#include "mxprotector/core/asm_builder.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace mx::guard {

namespace {

/// Write a 5-byte `int3 + 4-byte guard_id` window at `buf[offset]`.
/// `offset` must be a valid slot — the caller guarantees bounds via
/// the page-size check earlier in `build_guard_page`.
void write_int3_tag(ByteBuffer& buf, uint32_t offset, uint32_t guard_id) noexcept {
    buf[offset] = asm64::kInt3;
    std::memcpy(buf.data() + offset + 1, &guard_id, sizeof(guard_id));
}

} // anonymous namespace

MxResult<GuardPageLayout> build_guard_page(
    ByteView    body,
    uint32_t    guard_id,
    Randomizer& rng,
    uint32_t    page_size)
{
    // The layout must hold: one 5-byte entry int3+tag + body +
    // one 5-byte exit int3+tag, all in a single page. We reject
    // oversized bodies here so `GuardPass` can log a clear "guard
    // too big, skipping" line and move on.
    const uint64_t body_size = body.size();
    if (body_size == 0) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::region_too_small),
            "GuardPageLayout: тело пусто — нечего релоцировать"});
    }
    const uint64_t required = 2ULL * kGuardInt3TagSize + body_size;
    if (required > page_size) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::pass_failed),
            std::format("GuardPageLayout: тело {} байт + 2×{} байт int3+tag "
                        "не помещается в страницу {} байт",
                body_size, kGuardInt3TagSize, page_size)});
    }

    GuardPageLayout out{};
    out.bytes.resize(page_size);

    // ----- Entry int3+tag -------------------------------------------
    // The source-side `jmp rel32 <page>` lands on offset 0 → CPU
    // executes `int3` → `EXCEPTION_BREAKPOINT` → VEH advances Rip
    // past the tag to `body_offset`.
    out.entry_int3_offset = 0;
    write_int3_tag(out.bytes, out.entry_int3_offset, guard_id);

    // ----- Body -----------------------------------------------------
    // Verbatim copy of the user's bytes. Commit 3b will encrypt this
    // region at rest with the entry/exit int3+tag windows kept in
    // plaintext as "skip windows".
    out.body_offset = out.entry_int3_offset + kGuardInt3TagSize;
    out.body_size   = static_cast<uint32_t>(body_size);
    if (body_size > 0) {
        std::copy(body.begin(), body.end(), out.bytes.begin() + out.body_offset);
    }

    // ----- Exit int3+tag --------------------------------------------
    // The last real body instruction falls through into this int3.
    // The exit VEH decodes the tag, re-encrypts the body (commit 3b),
    // and sets Rip = descriptor.return_rva so control returns to the
    // source section right past the `MX_GUARD_END` marker.
    out.exit_int3_offset = out.body_offset + out.body_size;
    write_int3_tag(out.bytes, out.exit_int3_offset, guard_id);

    // ----- Polymorphic junk tail ------------------------------------
    // Random bytes — never executed at runtime (the exit VEH jumps
    // away before reaching here) and encrypted as part of the
    // body-range in Commit 3b, so any plausible byte distribution
    // works. Uniform random avoids an "all zeros at rest" fingerprint
    // for the unencrypted Commit 3a binaries.
    out.junk_offset = out.exit_int3_offset + kGuardInt3TagSize;
    for (uint32_t i = out.junk_offset; i < page_size; ++i) {
        out.bytes[i] = rng.next_u8();
    }

    return out;
}

} // namespace mx::guard
