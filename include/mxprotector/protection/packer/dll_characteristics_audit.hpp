/**
 * @file dll_characteristics_audit.hpp
 * @brief Pure bit-level policy for adjusting
 *        `OptionalHeader.DllCharacteristics` on a protected output.
 *
 * The packer injects new executable sections (`.mxpack`, and whatever
 * earlier passes added — `.mxvm`, CFF trampolines, `.mxstr`) whose
 * bytes are absent from every piece of compiler-generated metadata
 * the loader normally consults: there is no Control Flow Guard
 * bitmap entry for them, and their mutation invalidates any
 * embedded-signature integrity claim the input might have had.
 *
 * This module owns the bit-level decision: given an input
 * `DllCharacteristics` value and the target shape (kernel driver
 * or not), compute the masked-out bits that must come off. The
 * packer's orchestrator then writes the result back into the PE
 * header and logs each cleared bit with its rationale.
 *
 * Keeping the policy pure — `uint16_t` in, `uint16_t` out, no
 * `PeImage` or `ProtectionContext` dependency — makes the rule set
 * unit-testable in isolation: every target-shape × relevant-bit
 * combination is one assertion on the returned struct.
 */

#pragma once

#include <cstdint>

namespace mx::packer {

/**
 * @brief Result of `audit_dll_characteristics`.
 */
struct DllCharacteristicsAuditResult {
    /// Value to write back into `OptionalHeader.DllCharacteristics`.
    uint16_t output  = 0;
    /// Bits present in the input that have been removed. Exactly
    /// `input & ~output`. Callers log this (split by bit) so each
    /// decision has an audit trail.
    uint16_t cleared = 0;
};

/**
 * @brief Decide which `DllCharacteristics` bits to clear for a
 *        packed output.
 *
 * Rules:
 *   * Always clear `IMAGE_DLLCHARACTERISTICS_GUARD_CF`. The packer's
 *     injected sections have no Control Flow Guard bitmap entries,
 *     so a CFG-aware indirect call hitting them at runtime would be
 *     flagged as an invalid target and trip the loader's CFG
 *     dispatch into a fail-fast path.
 *   * When `is_kernel_driver` is true, additionally clear
 *     `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`. The kernel image
 *     loader refuses to load a `FORCE_INTEGRITY` image that is not
 *     embedded-signed by Microsoft, and our packer rewrites the
 *     `.text` bytes — invalidating any pre-existing signature.
 *
 * User-mode images keep `FORCE_INTEGRITY` untouched: it is rare on
 * EXE / DLL outputs and the user's own post-build signing step (if
 * any) is what keeps it valid after packing. ASLR-related bits
 * (`DYNAMIC_BASE`, `HIGH_ENTROPY_VA`) are deliberately untouched —
 * `disable_relocations` clears `DYNAMIC_BASE` for OS-loaded EXE / DLL
 * only, and the driver / manual-map paths rely on the bit staying as
 * in the input to tell the loader "feel free to relocate me".
 *
 * @param input             The `DllCharacteristics` value from the
 *                          input PE.
 * @param is_kernel_driver  True for `PeType::kernel_driver` targets.
 */
[[nodiscard]] constexpr DllCharacteristicsAuditResult
audit_dll_characteristics(uint16_t input, bool is_kernel_driver) noexcept
{
    // `GUARD_CF` = 0x4000, `FORCE_INTEGRITY` = 0x0080. We use the
    // literal constants here (rather than pulling in pe_types.hpp)
    // so this header stays dependency-free for tests; the matching
    // assertion lives in the unit test.
    constexpr uint16_t kGuardCf         = 0x4000;
    constexpr uint16_t kForceIntegrity  = 0x0080;

    uint16_t mask = kGuardCf;
    if (is_kernel_driver) {
        mask |= kForceIntegrity;
    }
    const uint16_t output  = static_cast<uint16_t>(input & ~mask);
    const uint16_t cleared = static_cast<uint16_t>(input & mask);
    return {output, cleared};
}

} // namespace mx::packer
