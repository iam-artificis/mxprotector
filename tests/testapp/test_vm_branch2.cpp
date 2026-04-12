#include <cstdio>
#include <cstdint>
#include "mxprotector_sdk/markers.hpp"

// Simplest possible: one conditional, no loop
__declspec(noinline) uint64_t simple_branch(uint64_t x) {
    uint64_t r = x;
    MX_VM_BEGIN
    r += 100;
    if (r > 200) goto big;
    r += 1;
    goto end;
big:
    r += 1000;
end:
    r ^= 0xFF;
    MX_VM_END
    return r;
}

int main() {
    // x=50: r=150, 150<=200, r=151, xor 0xFF = 151^255 = 0x68
    // x=150: r=250, 250>200, r=1250, xor 0xFF = 1250^255 = 0x4E1  
    auto ex = [](uint64_t x) {
        uint64_t r = x + 100;
        if (r > 200) r += 1000; else r += 1;
        return r ^ 0xFF;
    };
    uint64_t tests[][2] = {{50,0},{150,0},{0,0},{200,0}};
    bool ok = true;
    for (auto& t : tests) {
        t[1] = simple_branch(t[0]);
        uint64_t w = ex(t[0]);
        bool p = (t[1] == w);
        std::printf("x=%llu got=0x%llX want=0x%llX %s\n",
            (unsigned long long)t[0], (unsigned long long)t[1], (unsigned long long)w,
            p ? "OK" : "FAIL");
        if (!p) ok = false;
    }
    std::printf(ok ? "ALL OK\n" : "FAILED\n");
    return ok ? 0 : 1;
}
