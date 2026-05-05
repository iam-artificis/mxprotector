/**
 * @file hash_interface.hpp
 * @brief Abstract hash contract — `mx::hash::IHash`.
 *
 * @details The current build leans on `fnv1a_32` (declared in
 *          `fnv1a.hpp`) for every hash need: packer P6 stub
 *          self-hash, packer P6 effective-key derivation, guard
 *          VEH-handler CRC. FNV-1a is fast, but its docstring is
 *          explicit that it provides ZERO cryptographic strength —
 *          an attacker can replicate the digest trivially.
 *
 *          `IHash` is the seam we want for future migrations. Once a
 *          stronger hash (SipHash-2-4 keyed for collision-resistance,
 *          or BLAKE3 for cryptographic-grade) is wired into the
 *          runtime stub side, the build side switches to a different
 *          `IHash` implementation by selecting a different factory
 *          line. Call sites stay unchanged.
 *
 *          **Why not migrate call sites in this branch.** Every
 *          existing FNV-1a usage is a BUILD + RUNTIME contract —
 *          the protected binary's runtime stub recomputes the same
 *          digest at load time. Swapping the hash on the build side
 *          alone would make every protected binary decrypt to
 *          garbage. The migration is gated on the runtime stub
 *          getting an x64 implementation of the new hash; that is
 *          a separate, follow-up task.
 *
 *          **Design choices.**
 *            * Streaming-friendly via reset/update/finalize so future
 *              cryptographic hashes (BLAKE3, SHA-256) plug in
 *              naturally without forcing a full-buffer allocation.
 *            * One-shot `hash(data, out)` convenience for the common
 *              case (entire input in one ByteView) — implementations
 *              may override for a faster path when state-machine
 *              overhead matters.
 *            * `digest_size()` and `is_cryptographic()` so callers
 *              can size buffers and gate use ("require crypto" vs
 *              "any hash will do") without knowing the concrete
 *              algorithm.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::hash {

/**
 * @brief Hash function interface — backs every dynamic hash needed by
 *        the protector pipeline.
 *
 * Implementations are stateful: between `reset()` and `finalize()` a
 * caller may call `update()` any number of times. After `finalize()`
 * the state is consumed; another `reset()` is required before reuse.
 */
class IHash {
public:
    virtual ~IHash() = default;

    /// Reset the running state. Called once before the first
    /// `update()` of a hash session.
    virtual void reset() noexcept = 0;

    /// Append `data` to the running state.
    virtual void update(ByteView data) noexcept = 0;

    /// Finalize and copy the digest into @p out. `out.size()` must
    /// equal `digest_size()`. Implementations are not required to
    /// re-initialise — call `reset()` again before reuse.
    virtual void finalize(MutableByteView out) noexcept = 0;

    /// One-shot helper: reset + update + finalize.
    void hash(ByteView data, MutableByteView out) noexcept {
        reset();
        update(data);
        finalize(out);
    }

    /// Digest output size in bytes (4 for FNV-1a-32, 8 for SipHash,
    /// 32 for BLAKE3 / SHA-256).
    [[nodiscard]] virtual std::size_t digest_size() const noexcept = 0;

    /// True iff this hash provides cryptographic-grade collision
    /// resistance against an active adversary. FNV-1a returns
    /// `false`; SipHash-2-4 (keyed) and BLAKE3 return `true`.
    /// Pass-side guards that need anti-tamper integrity should
    /// assert this before accepting the hash for that role.
    [[nodiscard]] virtual bool is_cryptographic() const noexcept = 0;

    /// Human-readable algorithm name for logs / diagnostics.
    [[nodiscard]] virtual std::string_view algorithm_name() const noexcept = 0;
};

} // namespace mx::hash
