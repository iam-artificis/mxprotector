/**
 * @file check_registry.hpp
 * @brief Registry of anti-emulation checks, plus random selection.
 *
 * Every concrete check (`RdtscZeroDeltaCheck`, `CpuidHypervisorCheck`, ...)
 * is instantiated once into a `CheckRegistry`. Passes that want to embed
 * anti-emulation signals ask the registry for a random subset via
 * `pick_random(n, rng)`.
 *
 * Adding a new technique is a 2-step change: write the check class in its
 * own `.cpp`, and register its factory inside `check_registry.cpp`. No
 * other file needs to know about it.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/anti_emulation/check.hpp"

namespace mx::anti_emulation {

class CheckRegistry final {
public:
    /// Constructs the registry and instantiates every built-in check.
    CheckRegistry();

    CheckRegistry(const CheckRegistry&)            = delete;
    CheckRegistry& operator=(const CheckRegistry&) = delete;
    CheckRegistry(CheckRegistry&&)                 = default;
    CheckRegistry& operator=(CheckRegistry&&)      = default;

    /// Total number of registered checks.
    [[nodiscard]] size_t size() const noexcept { return checks_.size(); }

    /// Direct access to a specific check (useful for tests).
    [[nodiscard]] const ICheck& at(size_t index) const { return *checks_.at(index); }

    /**
     * @brief Pick `count` distinct checks uniformly at random.
     *
     * @param count  Number of checks to pick. Clamped to [0, size()].
     * @param rng    Per-build randomizer.
     * @return Pointers into registry-owned memory; valid for the lifetime
     *         of this `CheckRegistry` instance.
     */
    [[nodiscard]] std::vector<const ICheck*>
        pick_random(size_t count, Randomizer& rng) const;

private:
    std::vector<std::unique_ptr<ICheck>> checks_;
};

} // namespace mx::anti_emulation
