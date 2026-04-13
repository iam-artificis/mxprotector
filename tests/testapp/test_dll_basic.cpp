/**
 * @file test_dll_basic.cpp
 * @brief Minimal test DLL for the protector's DLL path.
 *
 * Exports a single function `mx_compute(seed) -> uint64_t` that runs
 * a deterministic ALU kernel inside a `MX_VM_BEGIN/END` region, so
 * the baseline binary exercises both the DLL entry-point semantics
 * (DllMain) and the marker pipeline.
 *
 * Includes one real kernel32 import (`OutputDebugStringA`) so the
 * IAT has something live in it — if the packer wipes imports and
 * does not restore them in DLL context, `LoadLibrary` will fail with
 * a predictable error and we can report it.
 */

#include <windows.h>

#include <cstdint>

#include "mxprotector_sdk/markers.hpp"

extern "C" __declspec(dllexport) uint64_t mx_compute(uint64_t seed) {
    // Real kernel32 import — not dead-code-eliminable.
    OutputDebugStringA("");

    uint64_t acc = seed;
    uint64_t t   = 0;
    MX_VM_BEGIN
    t    = 0xDEADBEEFULL;
    acc ^= t;
    acc += 0x1337ULL;
    t    = 0xA5A5A5A5ULL;
    acc ^= t;
    MX_VM_END
    return acc;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
