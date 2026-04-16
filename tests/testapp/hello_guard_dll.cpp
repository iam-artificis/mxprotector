/**
 * @file hello_guard_dll.cpp
 * @brief Proof-of-concept DLL for injection + memory-dump testing
 *        of the runtime-guards subsystem.
 *
 * Load this DLL via `hello_inject_loader.exe hello_guard_dll.protected.dll`
 * and dump the loader process with Process Hacker / x64dbg / any
 * memory-dump tool WHILE the DLL is running.
 *
 * Three guarded functions are exercised on a worker thread that
 * sleeps 5 seconds between invocations. A dump taken DURING the
 * 5-second sleep window should show the `.mxguard` section with
 * all three guard bodies as ciphertext. A dump taken at exactly the
 * wrong moment (during the ~few-microseconds VEH-decrypt-execute-
 * re-encrypt cycle) may catch ONE body as plaintext for the
 * duration of its execution — that is the documented
 * concurrent-thread race limitation of runtime-guards.
 *
 * Each guarded function computes a deterministic value so you can
 * verify on the host side that the protected DLL matches the
 * unprotected baseline run:
 *
 *   Iteration 0:
 *     lic=1 key=0x... block=<hex>
 *   Iteration 1:
 *     ...
 *
 * `volatile` locals are used inside every guard body to prevent
 * MSVC /O2 from hoisting the arithmetic out of the marker region.
 * Without `volatile` the body compiles down to a zero-size region
 * and GuardPass refuses it.
 *
 * All output goes to OutputDebugStringA (visible in DebugView / a
 * debugger) plus an append-only log file at
 * `C:\Users\Public\mxprotector_guard.log` so proof of injection is
 * observable in any host environment.
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

namespace {

// ---------------------------------------------------------------------------
// Guarded function #1 — license-check-shaped kernel.
//
// Takes a user id and a license seed, mixes them through an FNV-
// like hash chain, and returns a bool. The constant "acceptance
// byte" 0x42 means every iteration produces a deterministic
// lic==0 / lic==1 value the host can verify.
// ---------------------------------------------------------------------------
__declspec(noinline)
bool license_check_guarded(uint32_t user_id, uint32_t license_seed) {
    volatile uint64_t h = 0;
    MX_GUARD_BEGIN;
    h = static_cast<uint64_t>(user_id);
    h ^= 0xDEADBEEFCAFEBABEULL;
    h = h * 0x100000001B3ULL;
    h ^= static_cast<uint64_t>(license_seed);
    h = h * 0x100000001B3ULL;
    h ^= (h >> 32);
    MX_GUARD_END;
    return (static_cast<uint8_t>(h) & 0x01u) != 0u;
}

// ---------------------------------------------------------------------------
// Guarded function #2 — session-key-derivation-shaped kernel.
//
// Takes a master secret and a nonce, rotates + multiplies through 8
// rounds, returns the derived 64-bit key.
// ---------------------------------------------------------------------------
__declspec(noinline)
uint64_t derive_session_key_guarded(uint64_t master, uint64_t nonce) {
    volatile uint64_t k = 0;
    MX_GUARD_BEGIN;
    k = master ^ nonce;
    k = (k << 7) | (k >> 57);
    k *= 0x9E3779B97F4A7C15ULL;
    k ^= nonce + 1ULL;
    k = (k << 13) | (k >> 51);
    k *= 0x9E3779B97F4A7C15ULL;
    k ^= nonce + 2ULL;
    k = (k << 23) | (k >> 41);
    k ^= (k >> 32);
    MX_GUARD_END;
    return k;
}

// ---------------------------------------------------------------------------
// Guarded function #3 — 8-byte block transformer.
//
// Writes to `block` via the pointer, which the compiler cannot
// elide. The `volatile` on the local scratch guarantees the
// arithmetic happens inside the guard region even when the block
// writes themselves might otherwise be reordered.
// ---------------------------------------------------------------------------
__declspec(noinline)
void transform_block_guarded(uint8_t* block, uint32_t subkey) {
    volatile uint32_t s = subkey;
    MX_GUARD_BEGIN;
    for (int i = 0; i < 8; ++i) {
        const uint8_t k = static_cast<uint8_t>(s >> ((i * 4) & 0x1F));
        block[i] = static_cast<uint8_t>((block[i] ^ k) + static_cast<uint8_t>(i));
        s = (s << 1) | (s >> 31);
    }
    MX_GUARD_END;
}

// ---------------------------------------------------------------------------
// Log utilities — identical to hello_inject_dll.cpp pattern.
// ---------------------------------------------------------------------------

void log_to_file(const char* line) {
    HANDLE f = CreateFileA(
        "C:\\Users\\Public\\mxprotector_guard.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, nullptr, FILE_END);
    DWORD written = 0;
    const DWORD len = static_cast<DWORD>(lstrlenA(line));
    WriteFile(f, line, len, &written, nullptr);
    CloseHandle(f);
}

void emit_line(const char* line) {
    OutputDebugStringA(line);
    log_to_file(line);
}

// ---------------------------------------------------------------------------
// Worker thread.
//
// Sleeps 5 seconds → calls all three guarded kernels with fresh
// inputs → logs the results → repeat. The 5-second sleep is the
// intended dump window: during those 5 seconds, ALL guard pages
// are encrypted at rest in .mxguard. A memory dump of the host
// process during sleep should show ciphertext for every body.
// ---------------------------------------------------------------------------
DWORD WINAPI guard_worker(LPVOID /*param*/) {
    emit_line("[mxguard] worker thread started — dump window = 5s idle "
              "between iterations\n");

    uint64_t iter = 0;
    for (;;) {
        Sleep(5000);  // <<< memory dumps during this window see ciphertext

        emit_line("[mxguard] ---- iteration begin ----\n");

        const bool lic = license_check_guarded(
            static_cast<uint32_t>(iter),
            0xDEADBEEFu);
        const uint64_t session_key = derive_session_key_guarded(
            0x0123456789ABCDEFULL,
            iter);

        uint8_t block[8] = {
            0xA0u, 0xB1u, 0xC2u, 0xD3u, 0xE4u, 0xF5u, 0x06u, 0x17u
        };
        transform_block_guarded(block, static_cast<uint32_t>(iter));

        char line[256];
        const int n = std::snprintf(
            line, sizeof(line),
            "[mxguard] #%llu lic=%d key=0x%016llX "
            "block=%02X%02X%02X%02X%02X%02X%02X%02X\n",
            static_cast<unsigned long long>(iter),
            lic ? 1 : 0,
            static_cast<unsigned long long>(session_key),
            block[0], block[1], block[2], block[3],
            block[4], block[5], block[6], block[7]);
        if (n > 0) {
            emit_line(line);
        }

        iter++;
    }
}

} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                                DWORD     reason,
                                LPVOID    /*lpvReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE thr = CreateThread(
            nullptr, 0, guard_worker, nullptr, 0, nullptr);
        if (thr != nullptr) {
            CloseHandle(thr);
        }
    }
    return TRUE;
}
