/**
 * @file check_registry.hpp
 * @brief Registry of anti-tamper checks, plus random selection.
 *
 * Mirrors `anti_emulation::CheckRegistry` in shape — same
 * `pick_random` / `at` / `size` API — but keeps a separate pool of
 * checks. The X64 backend instantiates one of each registry and
 * picks from both during entry-stub emission.
 *
 * Anti-tamper checks that need an NTDLL SSN do not look it up at
 * builder time. Instead, the X64 backend emits a runtime Hell's
 * Gate resolver (`hells_gate_resolver.cpp`) once per region, and
 * the check reads the resolved SSN from `r13d` inside the
 * protected binary's own process. This keeps the SSN correct on
 * any Windows version the protected binary runs on, independent
 * of what the builder host happens to be.
 *
 * Adding a new technique:
 *   1. Write the check class in
 *      `src/builder/protection/anti_tamper/<name>_check.cpp`.
 *   2. Add a factory `make_<name>_check()` with no parameters.
 *   3. Register it in `check_registry.cpp`.
 *   4. Append the source file to `src/builder/CMakeLists.txt`.
 *
 * If the check needs a DIFFERENT SSN than NtGetContextThread,
 * extend the resolver to carry a second target and place it in
 * another register (e.g. r14). The check reads from there.
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
    /// Constructs the registry and instantiates every built-in
    /// anti-tamper check. No builder-side SSN resolution — any
    /// syscall-based check receives its SSN via the runtime
    /// Hell's Gate resolver that the X64 backend emits into the
    /// entry stub alongside the check itself.
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
