/**
 * @file check_registry.cpp
 * @brief Wires all anti-emulation check factories into a single registry.
 *
 * To add a new technique:
 *   1. Create `src/builder/protection/anti_emulation/<name>_check.cpp`
 *      with a class implementing `ICheck` and a factory function
 *      `std::unique_ptr<ICheck> make_<name>_check();`
 *   2. Declare the factory below in the `factories` namespace.
 *   3. Append a `checks_.push_back(factories::make_<name>_check());`
 *      call in the `CheckRegistry` constructor.
 *   4. Add the new `.cpp` to `src/builder/CMakeLists.txt`.
 *
 * Nothing in `vm_runtime_gen.cpp` or any other pass changes — the VM
 * runtime generator just asks the registry for `pick_random(N)` and
 * emits whatever it gets.
 */

#include "mxprotector/protection/anti_emulation/check_registry.hpp"

#include <algorithm>
#include <numeric>

namespace mx::anti_emulation {

// ----------------------------------------------------------------------------
// Factory forward declarations — defined in the per-check .cpp files
// alongside their respective `ICheck` subclasses, in the same
// `mx::anti_emulation` namespace this file is in.
// ----------------------------------------------------------------------------
std::unique_ptr<ICheck> make_rdtsc_zero_delta_check();
std::unique_ptr<ICheck> make_rdtsc_huge_delta_check();
std::unique_ptr<ICheck> make_cpuid_hypervisor_check();
std::unique_ptr<ICheck> make_eflags_reserved_bit_check();

// ----------------------------------------------------------------------------
// REJECTED: AC flag fidelity (EFLAGS bit 18 round-trip).
//
// The ROADMAP listed it as a candidate, and on paper it's elegant — set
// AC via popfq, read it back via pushfq, real CPUs preserve, dumb
// emulators don't. Implementation works.
//
// In practice: setting EFLAGS.AC=1 in user mode on Windows x64 ARMS the
// alignment-check trap. Windows enables CR0.AM (or an equivalent
// behaviour, exact mechanism is build-specific) — once AC is set, the
// next unaligned multi-byte access raises #AC. The CRT, vectorised
// memcpy, exception unwinding, and most third-party libraries do
// unaligned reads constantly, so the protected binary crashes within
// microseconds of the check running.
//
// We confirmed this empirically: replacing the bit-test logic with a
// forced `xor eax, eax` (so the corruption mask is always 0) STILL
// crashed ~25% of stress builds, but removing the `or rax, 0x40000`
// (so AC is never set) made the same byte sequence 40/40 OK.
//
// Conclusion: AC fidelity probing is fundamentally unsafe on Windows
// targets. Do NOT add it back without first guaranteeing the protected
// process never executes another unaligned access — which is not
// achievable for general-purpose Windows binaries. If we ever ship a
// Linux ELF backend, AC fidelity is fair game there (Linux leaves
// CR0.AM cleared) — but it must live in a Linux-only registry, never
// the cross-platform default.
// ----------------------------------------------------------------------------

CheckRegistry::CheckRegistry() {
    checks_.push_back(make_rdtsc_zero_delta_check());
    checks_.push_back(make_rdtsc_huge_delta_check());
    checks_.push_back(make_eflags_reserved_bit_check());
    // NOTE: CPUID hypervisor-bit check is intentionally NOT in the default
    // registry. Windows 11 with VBS, Hyper-V, WSL2, Docker, or
    // Credential Guard all runs user mode under a type-1 hypervisor and
    // sets CPUID.1:ECX[31]. Using that bit as an anti-emulation signal
    // produces false positives on a very large fraction of legitimate
    // consumer machines. The check is implemented (see
    // `cpuid_hypervisor_check.cpp`) for callers that know their deployment
    // is bare-metal-only, but it's opt-in — wire it via a future CLI flag
    // or a build-time override if you need it.
    //   checks_.push_back(make_cpuid_hypervisor_check());
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

} // namespace mx::anti_emulation
