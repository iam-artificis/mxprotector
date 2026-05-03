/**
 * @file encoder_registry.hpp
 * @brief [PROTECTION] Pluggable registry of indirect-call encoders.
 *
 * The pass that rewrites `call rel32` sites into stub-dispatched
 * variants does not hard-code which encoders exist; it asks the
 * registry for one at random per call site. Adding a new encoder
 * is a one-line registration in the registry's seed function and
 * a new file under `protection/anti_static/encoders/`.
 *
 * SOLID:
 *   * SRP — registration only. No emission policy, no logging.
 *   * OCP — `register_encoder` is the single seam new encoders
 *     plug into.
 *   * Dependency inversion — consumers depend on the abstract
 *     `IIndirectCallEncoder` interface, not concrete encoders.
 */

#pragma once

#include <memory>
#include <vector>

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx {
class Randomizer;
}

namespace mx::protection::anti_static {

/**
 * @brief Holds zero or more encoders and picks one uniformly at
 *        random per call site.
 *
 * Empty registries return `nullptr` from `pick`. The pass treats
 * `nullptr` as "skip this site" so the registry is safe to use
 * with no encoders registered (lets unit tests instantiate the
 * pass without booting up the real encoder set).
 */
class EncoderRegistry {
public:
    EncoderRegistry() = default;

    EncoderRegistry(const EncoderRegistry&)            = delete;
    EncoderRegistry& operator=(const EncoderRegistry&) = delete;
    EncoderRegistry(EncoderRegistry&&) noexcept            = default;
    EncoderRegistry& operator=(EncoderRegistry&&) noexcept = default;

    /// Append `encoder` to the registry. Insertion order is
    /// irrelevant — `pick` samples uniformly at random.
    void register_encoder(std::unique_ptr<IIndirectCallEncoder> encoder);

    /// Number of registered encoders. Useful for diagnostics.
    [[nodiscard]] std::size_t size() const noexcept {
        return encoders_.size();
    }

    /// Pick one encoder uniformly at random; `nullptr` when empty.
    [[nodiscard]] const IIndirectCallEncoder* pick(Randomizer& rng) const;

    /// Lookup an encoder by `name()` — diagnostic helper used by
    /// tests that want to exercise a specific encoder
    /// deterministically.
    [[nodiscard]] const IIndirectCallEncoder* find(
        std::string_view name) const noexcept;

private:
    std::vector<std::unique_ptr<IIndirectCallEncoder>> encoders_;
};

/**
 * @brief Build a registry pre-populated with the default encoder
 *        set shipped with mxprotector. Updated as new encoders
 *        land — call sites do not need to know which encoders
 *        exist.
 */
[[nodiscard]] EncoderRegistry make_default_registry();

} // namespace mx::protection::anti_static
