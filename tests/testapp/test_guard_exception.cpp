// Smoke target for MX_GUARD + C++ exception coexistence
// (runtime-guards[5/7] milestone). Verifies two invariants:
//
//   1. A `throw` in user code OUTSIDE a guarded block unwinds
//      correctly through the protected binary. The guard runtime
//      (VEH handler + int3+tag windows + descriptor table) does
//      not interfere with the standard SEH unwinder.
//
//   2. A guarded block that executes and exits cleanly can be
//      followed by a subsequent `throw` on the same call stack
//      — the VEH's exit re-encryption must leave the thread in a
//      consistent state so later exception handling works.
//
// Limitation NOT covered here by design: raising an exception
// FROM INSIDE a guarded block is explicitly unsupported — the
// body between MX_GUARD_BEGIN and MX_GUARD_END must execute to
// the end without propagating an exception out. See the
// `MX_GUARD_BEGIN` docblock in mxprotector_sdk/markers.hpp for
// the contract.

#include <cstdio>
#include <stdexcept>
#include <string>

#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) static int compute_guarded_hash(int x) {
    volatile int acc = 0;
    MX_GUARD_BEGIN;
    acc = (x * 7) ^ 0x55;
    acc += (x >> 1);
    acc ^= (x << 3);
    MX_GUARD_END;
    return acc;
}

[[gnu::noinline]] static void raise_domain_error(int code) {
    // Throw from OUTSIDE any guard block. The guard runtime has
    // already re-encrypted on the last `compute_guarded_hash`
    // exit, so there is no open state to unwind through.
    throw std::runtime_error("domain error #" + std::to_string(code));
}

int main() {
    int caught_ok = 0;
    int total = 0;

    // Invariant (1) — guard block coexists with try/catch around
    // an unrelated throw path.
    try {
        for (int i = 0; i < 5; ++i) {
            total += compute_guarded_hash(i);
        }
        raise_domain_error(total);
    } catch (const std::runtime_error& e) {
        caught_ok += 1;
        std::printf("[test_guard_exception] caught: %s\n", e.what());
    }

    // Invariant (2) — after a caught exception, the thread can
    // re-enter a guard block and execute normally. This exercises
    // the "guard state is clean after exception" property.
    for (int i = 0; i < 3; ++i) {
        total += compute_guarded_hash(i + 100);
    }

    std::printf("[test_guard_exception] total=%d caught=%d\n", total, caught_ok);
    return (caught_ok == 1 && total != 0) ? 0 : 1;
}
