/**
 * @file check_registry.cpp
 * @brief Wires anti-tamper check factories into the registry.
 *
 * Unlike the anti-emulation registry, anti-tamper checks do not need
 * any build-time host probing here. Every check that requires an
 * NTDLL SSN gets it at protected-binary runtime via the
 * Hell's Gate resolver (see `hells_gate_resolver.cpp`), so the
 * registry just instantiates every built-in check unconditionally.
 */

#include "mxprotector/protection/anti_tamper/check_registry.hpp"

#include <algorithm>
#include <numeric>

namespace mx::anti_tamper {

// ----------------------------------------------------------------------------
// Factory forward declarations — defined in the per-check .cpp files.
// ----------------------------------------------------------------------------
std::unique_ptr<ICheck> make_hw_breakpoint_sweep_check();
std::unique_ptr<ICheck> make_import_hook_detect_check();
std::unique_ptr<ICheck> make_self_crc_check();
std::unique_ptr<ICheck> make_page_protection_check();
std::unique_ptr<ICheck> make_debug_object_handle_check();

CheckRegistry::CheckRegistry() {
    checks_.push_back(make_hw_breakpoint_sweep_check());
    checks_.push_back(make_import_hook_detect_check());
    checks_.push_back(make_self_crc_check());
    checks_.push_back(make_page_protection_check());
    checks_.push_back(make_debug_object_handle_check());
}

std::vector<const ICheck*>
CheckRegistry::pick_random(size_t count, Randomizer& rng) const
{
    if (checks_.empty() || count == 0) return {};
    const size_t n = std::min(count, checks_.size());

    // Fisher–Yates over an index vector, take first n.
    std::vector<size_t> indices(checks_.size());
    std::iota(indices.begin(), indices.end(), static_cast<size_t>(0));
    for (size_t i = indices.size() - 1; i > 0; --i) {
        const uint32_t j = rng.next_range(0, static_cast<uint32_t>(i));
        std::swap(indices[i], indices[j]);
    }

    std::vector<const ICheck*> result;
    result.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        result.push_back(checks_[indices[i]].get());
    }
    return result;
}

} // namespace mx::anti_tamper
