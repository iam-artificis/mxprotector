#include <cstdio>
#include <cstdint>
#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) uint64_t loop_kernel(uint64_t n) {
    uint64_t acc = 0;
    uint64_t i = 0;
    MX_VM_BEGIN
    // Use explicit goto to prevent MSVC optimization
top:
    if (i >= n) goto out;
    acc += i;
    i += 1;
    goto top;
out:
    acc ^= 0xFF;
    MX_VM_END
    return acc;
}

int main() {
    auto ex = [](uint64_t n) -> uint64_t {
        uint64_t acc = 0;
        for (uint64_t i = 0; i < n; i++) acc += i;
        return acc ^ 0xFF;
    };
    uint64_t ns[] = {0, 1, 2, 5, 10};
    bool ok = true;
    for (uint64_t n : ns) {
        uint64_t got = loop_kernel(n);
        uint64_t want = ex(n);
        std::printf("n=%llu got=0x%llX want=0x%llX %s\n",
            (unsigned long long)n, (unsigned long long)got, (unsigned long long)want,
            got==want ? "OK" : "FAIL");
        if (got != want) ok = false;
    }
    std::printf(ok ? "ALL OK\n" : "FAILED\n");
    return ok ? 0 : 1;
}
