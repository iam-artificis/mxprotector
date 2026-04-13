/**
 * @file test_dll_loader.cpp
 * @brief Loader harness for `test_dll_basic.dll`.
 *
 * Arguments:
 *     test_dll_loader.exe [dll_path]
 *
 * Reports the full failure path in plain text — LoadLibrary error,
 * GetProcAddress error, or computation mismatch — so protector runs
 * can be triaged without a debugger.
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>

using mx_compute_fn = uint64_t(*)(uint64_t);

int main(int argc, char** argv) {
    const char* dll_path = (argc > 1) ? argv[1] : "test_dll_basic.dll";
    std::printf("[loader] LoadLibraryA(\"%s\")\n", dll_path);

    HMODULE h = LoadLibraryA(dll_path);
    if (!h) {
        std::printf("[loader] LoadLibrary FAILED, GetLastError=%lu\n",
                    GetLastError());
        return 1;
    }

    auto fn = reinterpret_cast<mx_compute_fn>(
        GetProcAddress(h, "mx_compute"));
    if (!fn) {
        std::printf("[loader] GetProcAddress(\"mx_compute\") FAILED, GLE=%lu\n",
                    GetLastError());
        FreeLibrary(h);
        return 2;
    }

    const uint64_t seed = 0x1111111122222222ULL;
    const uint64_t got  = fn(seed);

    // Expected: mirror of the kernel inside MX_VM_BEGIN/END.
    uint64_t expected = seed;
    expected ^= 0xDEADBEEFULL;
    expected += 0x1337ULL;
    expected ^= 0xA5A5A5A5ULL;

    std::printf("[loader] mx_compute(seed=0x%016llX) = 0x%016llX\n",
                static_cast<unsigned long long>(seed),
                static_cast<unsigned long long>(got));
    std::printf("[loader] expected                     = 0x%016llX\n",
                static_cast<unsigned long long>(expected));

    FreeLibrary(h);

    if (got != expected) {
        std::printf("[loader] MISMATCH\n");
        return 3;
    }

    std::printf("[loader] OK\n");
    return 0;
}
