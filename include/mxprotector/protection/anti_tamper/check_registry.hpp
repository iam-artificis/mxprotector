/**
 * @file check_registry.hpp
 * @brief Registry of anti-tamper checks, plus random selection.
 *
 * Mirrors `anti_emulation::CheckRegistry` in shape — same
 * `pick_random` / `at` / `size` API — but keeps a separate pool of
 * checks. The X64 backend instantiates one of each registry and
 * picks from both during entry-stub emission.
 *
 * Adding a new technique:
 *   1. Write the check class in
 *      `src/builder/protection/anti_tamper/<name>_check.cpp`.
 *   2. Add a factory `make_<name>_check(SyscallResolver&)` if the
 *      check needs a resolved SSN, or `make_<name>_check()` if not.
 *   3. Register it in `check_registry.cpp`.
 *   4. Append the source file to `src/builder/CMakeLists.txt`.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/anti_tamper/check.hpp"

namespace mx::anti_tamper {

class CheckRegistry final {
public:
    /// Constructs the registry. Internally instantiates a
    /// `SyscallResolver` to resolve any SSNs required by the
    /// built-in checks. Checks whose SSN failed to resolve are
    /// silently dropped — the registry holds only checks that are
    /// known to be functional on the current builder host.
    CheckRegistry();

    CheckRegistry(const CheckRegistry&)            = delete;
    CheckRegistry& operator=(const CheckRegistry&) = delete;
    CheckRegistry(CheckRegistry&&)                 = default;
    CheckRegistry& operator=(CheckRegistry&&)      = default;

    [[nodiscard]] size_t size() const noexcept { return checks_.size(); }
    [[nodiscard]] const ICheck& at(size_t index) const { return *checks_.at(index); }

    /// Pick `count` distinct checks at random. Clamped to `size()`.
    [[nodiscard]] std::vector<const ICheck*>
        pick_random(size_t count, Randomizer& rng) const;

private:
    std::vector<std::unique_ptr<ICheck>> checks_;
};

} // namespace mx::anti_tamper
