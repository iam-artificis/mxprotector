/**
 * @file check_registry.cpp
 * @brief Wires anti-tamper check factories into the registry.
 */

#include "mxprotector/protection/anti_tamper/check_registry.hpp"

#include <algorithm>
#include <numeric>

#include "mxprotector/protection/anti_tamper/syscall_resolver.hpp"

namespace mx::anti_tamper {

// ----------------------------------------------------------------------------
// Factory forward declarations — defined in the per-check .cpp files.
// SSN-dependent factories take the resolved SSN as a parameter; if the
// resolver returned 0 the registry constructor skips the factory call.
// ----------------------------------------------------------------------------
std::unique_ptr<ICheck> make_hw_breakpoint_sweep_check(uint32_t nt_get_context_thread_ssn);

CheckRegistry::CheckRegistry() {
    SyscallResolver resolver;

    // HW breakpoint sweep — needs NtGetContextThread.
    const uint32_t nt_get_ctx_ssn = resolver.resolve("NtGetContextThread");
    if (nt_get_ctx_ssn != 0) {
        checks_.push_back(make_hw_breakpoint_sweep_check(nt_get_ctx_ssn));
    }
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
