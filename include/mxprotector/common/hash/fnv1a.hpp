/**
 * @file fnv1a.hpp
 * @brief FNV-1a 32-bit hash — pure non-cryptographic primitive.
 *
 * FNV-1a is a small, fast, well-distributed non-cryptographic hash.
 * In MxProtector it is used wherever we need a deterministic 32-bit
 * digest that is cheap to recompute at runtime *and* trivially
 * reproducible at build time:
 *
 *   - Packer P6: stub-integrity self-hash + per-layer effective-key
 *     derivation (`protection/packer/stub_self_hash`).
 *   - Guard pass: VEH-handler CRC stamped into the TLS installer at
 *     build time and re-walked at runtime to detect handler tampering.
 *
 * This header is the **single source of truth** for the FNV-1a-32
 * offset basis, prime, and the canonical reference implementation.
 * The byte-level x64 emitters that recreate the loop in protected
 * binaries pull their constants from here so build-side and runtime
 * paths can never disagree (a single `imul` constant drift would make
 * every protected binary decrypt to garbage).
 *
 * Design rules:
 *   - Header-only. The constexpr reference implementation costs
 *     nothing at runtime and lets unit tests pin canonical values
 *     in static_assert form.
 *   - No dependencies beyond `core/types.hpp` (for `ByteView`).
 *   - Namespace `mx::hash`. Pure utility — never reach for a pass
 *     header to compute a hash.
 *   - Non-cryptographic by construction. Do not use for anything
 *     that needs collision resistance against a determined adversary.
 *
 * Cryptographic strength is **explicitly out of scope**: every byte
 * of the FNV-1a state is forward-derivable from the input, and an
 * attacker can replicate the digest trivially. The protection value
 * comes from *coupling* the hash to a runtime artefact (stub bytes,
 * VEH handler bytes) and to a build-time secret (per-build base keys),
 * so the attacker has to instrument or simulate the runtime path —
 * not from any security property of the hash itself.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx::hash {

/// Canonical FNV-1a 32-bit offset basis.
///
/// Per the original FNV specification: the seed every FNV-1a-32
/// computation starts from. `fnv1a_32` of an empty input must equal
/// this value, and the byte-level emitters bake exactly this constant
/// into their `mov reg, imm32` initialiser slots so the runtime walk
/// produces the same digest the build side computes.
inline constexpr std::uint32_t kFnv1aOffsetBasis = 0x811C9DC5u;

/// Canonical FNV-1a 32-bit prime — the multiplicative step constant.
///
/// The runtime self-hash and key-derivation loops `imul` the running
/// state by this value once per input byte. Build-side and runtime
/// paths share the constant by reading it from this header — see the
/// guard tests in `EmitSelfHashEmbedsFnv1aConstantsMatchingBuildSide`
/// for the cross-check.
inline constexpr std::uint32_t kFnv1aPrime = 0x01000193u;

/**
 * @brief Compile-time FNV-1a-32 over an arbitrary byte range.
 *
 * Bit-exact reference implementation of the runtime emitter. Used by
 * build-side code to:
 *   - Pre-compute effective keys for every cipher layer in the packer
 *     P6 pipeline.
 *   - Stamp a build-time CRC into the guard TLS installer that the
 *     runtime walk must reproduce.
 *
 * Constexpr — invocation on compile-time data is folded; unit tests
 * pin canonical values via `static_assert`. No allocations, no
 * dependencies beyond `ByteView`.
 *
 * @param bytes  Input byte range. May be empty (returns the offset
 *               basis unchanged, matching the canonical FNV-1a-32
 *               specification).
 * @return       The 32-bit FNV-1a-32 digest of @p bytes.
 *
 * @note         The byte count walked at runtime must match exactly,
 *               byte-for-byte, the range fed here. Off-by-one or wrong
 *               start address makes the runtime digest diverge — the
 *               packer caller derives the range from the
 *               `StubSelfHashEmit` patch slots in `stub_self_hash.hpp`
 *               and feeds the same slice here.
 */
[[nodiscard]] constexpr std::uint32_t fnv1a_32(ByteView bytes) noexcept {
    std::uint32_t hash = kFnv1aOffsetBasis;
    for (const std::uint8_t b : bytes) {
        hash ^= static_cast<std::uint32_t>(b);
        hash *= kFnv1aPrime;
    }
    return hash;
}

} // namespace mx::hash
