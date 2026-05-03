/**
 * @file self_crc_refinalizer.hpp
 * @brief Re-finalise post-shuffle self-CRC anti-tamper checks (B.4.15).
 *
 * The VM backend's anti-tamper layer emits CRC32C self-integrity
 * checks over the entry-stub prefix (see
 * `protection/anti_tamper/self_crc_check.cpp`). The check's
 * **expected CRC** sits in a `cmp eax, imm32` placeholder that the
 * X64 backend back-fills via `finalize_self_crc_patches` once every
 * other deferred patch has been applied.
 *
 * Critically, that finalisation happens **before** the chaos
 * shuffle. Chaos then rewrites RIP-relative LEA `rel32` slots inside
 * the CRC range whenever those LEAs point at handler-table or
 * key-table targets that the shuffle has moved. The byte content of
 * the CRC range therefore changes AFTER the expected CRC was
 * computed — at runtime the CRC mismatches, the check corrupts the
 * VM key slot, and the next dispatch lands on garbage.
 *
 * `SelfCrcRefinalizer` runs as the final step inside
 * `apply_fragment_shuffle`. It walks every code section, identifies
 * self-CRC checks by their fixed 36-byte signature, decodes the
 * range start (`rel32` of the leading LEA) and length (the `mov ecx,
 * imm32` immediate), recomputes the CRC32C over the post-shuffle
 * bytes, and writes the new value into the `cmp` imm32 slot.
 *
 * The refinaliser is **idempotent** — running it twice produces the
 * same result on a stable image. It is also **stateless**, holding
 * no per-image data; instantiate freely per call.
 *
 * SOLID:
 *   * SRP — exactly one task: refresh the self-CRC placeholder.
 *   * OCP — a sibling class can be added for any other deferred-
 *     hash check that depends on the post-shuffle byte content.
 *
 * Threading: not safe for concurrent invocation against the same
 * `PeImage`. Use one instance per build.
 */

#pragma once

#include <cstddef>

namespace mx {
class PeImage;
}

namespace mx::pe::chaos {

/**
 * @brief Self-CRC refinaliser — see file header.
 */
class SelfCrcRefinalizer {
public:
    SelfCrcRefinalizer() = default;

    /**
     * @brief Walk every code section in `image`, find self-CRC
     *        patterns, recompute the CRC over the post-shuffle bytes,
     *        and patch the expected-value placeholder in each.
     *
     * No-op when:
     *   * The image is not 64-bit.
     *   * No code section contains a recognised self-CRC pattern.
     *
     * Decoder errors and read-past-section conditions are absorbed
     * silently: the refinaliser must never throw and must never
     * fault the build.
     *
     * @return Number of self-CRC checks refinalised. Useful for
     *         diagnostics; callers may discard the value.
     */
    std::size_t refinalize(PeImage& image) const;
};

} // namespace mx::pe::chaos
