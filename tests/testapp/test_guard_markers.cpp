// Smoke target for the MX_GUARD_BEGIN / MX_GUARD_END SDK markers
// (Commit 1 of the runtime-guards milestone). At this commit the
// markers are SDK-side only — the builder's scanner recognises and
// logs them, but no protection pass touches them yet, so the
// protected binary should behave identically to the original.
//
// Running this through `mxprotector_builder` with any protection
// level should produce a "Найдено маркированных регионов: 1"
// line for the guarded block, followed by a
// `GUARD : RVA [... - ...] (N байт)` entry.

#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

[[gnu::noinline]] static int compute_secret(int x) {
    int acc = 0;
    MX_GUARD_BEGIN;
    // Tiny body: a couple of arithmetic ops so the region is
    // non-empty at the IR level even under /O2.
    acc = (x * 7) ^ 0x55;
    acc += (x >> 1);
    acc ^= (x << 3);
    MX_GUARD_END;
    return acc;
}

int main() {
    int total = 0;
    for (int i = 0; i < 5; ++i) {
        total += compute_secret(i);
    }
    std::printf("[test_guard_markers] total=%d\n", total);
    return (total != 0) ? 0 : 1;
}
