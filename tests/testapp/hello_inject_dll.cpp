/**
 * @file hello_inject_dll.cpp
 * @brief Proof-of-concept payload DLL for testing mxprotector end-to-end
 *        via real process injection.
 *
 * On PROCESS_ATTACH the DLL:
 *   1. Tells the loader to skip THREAD_ATTACH/DETACH for this module
 *      (`DisableThreadLibraryCalls`) so no loader-lock interactions
 *      happen for every CreateThread in the host process.
 *   2. Spawns a single worker thread — the "hello world" loop cannot
 *      run from DllMain itself because DllMain executes under the
 *      loader lock and any nontrivial work there deadlocks the
 *      Win32 loader.
 *   3. Returns TRUE immediately so the host's LoadLibrary resolves.
 *
 * The worker thread:
 *   * Tries `AllocConsole` first — for a GUI host (no stdio by
 *     default) this opens a fresh console window named
 *     `mxprotector injected DLL`. For console hosts AllocConsole
 *     fails silently and the worker falls back to writing to the
 *     existing stdout.
 *   * As an always-on fallback, every line also goes through
 *     `OutputDebugStringA` — visible to DebugView / the debugger,
 *     so even if the console call fails completely the injection
 *     is observable.
 *   * Computes a small VM-protected mix per iteration so the
 *     protected DLL exercises both the packer decrypt path AND
 *     the VM dispatch / handler_table integrity / trampoline
 *     chains on every loop turn, not just at module load time.
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

namespace {

/// VM-protected mix kernel. Declared `__declspec(noinline)` so the
/// compiler can't fold the marker instructions past the body or
/// eliminate them as dead code — both outcomes produce a zero-sized
/// marker region that the protector refuses. The function takes a
/// `counter` parameter that is never constant, so the optimiser
/// cannot pre-compute the result at build time either.
__declspec(noinline)
uint64_t mix_kernel(uint64_t counter) {
    uint64_t mix = counter;
    uint64_t tmp = 0;
    MX_VM_BEGIN
    tmp  = 0xA5A5A5A5A5A5A5A5ULL;
    mix ^= tmp;
    mix += 0x1337ULL;
    tmp  = mix;
    mix += tmp;                 // mix = 2*mix
    tmp  = 0xDEADBEEFULL;
    mix ^= tmp;
    mix += counter;
    MX_VM_END
    return mix;
}

/// Append `line` to the persistent injection log at a fixed path
/// that any user can read without admin rights. Used as a last-
/// resort fallback when `AllocConsole` fails (AppContainer / UWP
/// target) AND `OutputDebugStringA` is invisible (no DebugView
/// running). Opening the file on every call is inefficient but
/// robust — if the host process crashes we still flushed the
/// previous line to disk.
void log_to_file(const char* line) {
    HANDLE f = CreateFileA(
        "C:\\Users\\Public\\mxprotector_inject.log",
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

/// Thread entry for the hello-world loop. Gets spawned from DllMain
/// (not called from it) so we never run long operations under the
/// loader lock.
DWORD WINAPI hello_thread(LPVOID /*param*/) {
    // Initial ping so the user can immediately confirm injection
    // worked, even before the loop starts printing. Writes through
    // ALL three channels so at least one lands somewhere visible.
    const char* banner =
        "[mxprotector inject] DLL thread started\n";
    OutputDebugStringA(banner);
    log_to_file(banner);

    const bool have_console = (AllocConsole() != FALSE);
    if (have_console) {
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        SetConsoleTitleA("mxprotector injected DLL");
        std::fputs("[mxprotector inject] console attached\n", stdout);
        std::fflush(stdout);
    }

    uint64_t counter = 0;
    for (;;) {
        // VM-protected mix — forces the packer stub AND the VM
        // dispatch to do real work on every iteration. Any bug in
        // the protection pipeline produces a wrong `mix` value or
        // crashes inside the VM region.
        const uint64_t mix = mix_kernel(counter);

        char line[160];
        const int n = std::snprintf(
            line, sizeof(line),
            "[mxprotector inject] hello world #%llu  mix=0x%016llX\n",
            static_cast<unsigned long long>(counter),
            static_cast<unsigned long long>(mix));

        if (n > 0) {
            if (have_console) {
                std::fputs(line, stdout);
                std::fflush(stdout);
            }
            // Always also dump to the debug channel (DebugView) AND
            // the persistent log file. The log file is the most
            // reliable proof-of-injection in sandboxed / UWP hosts
            // where neither console nor OutputDebugStringA are
            // observable.
            OutputDebugStringA(line);
            log_to_file(line);
        }

        counter++;
        Sleep(1000);
    }
    return 0;
}

} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                                DWORD     reason,
                                LPVOID    /*lpvReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // Tell the loader we do not care about THREAD_ATTACH /
        // THREAD_DETACH for this module. Cuts loader-lock traffic
        // in busy hosts and makes no difference to our worker
        // thread which lives independently.
        DisableThreadLibraryCalls(hinstDLL);

        HANDLE thr = CreateThread(nullptr, 0, hello_thread, nullptr, 0, nullptr);
        if (thr != nullptr) {
            CloseHandle(thr);
        }
    }
    return TRUE;
}
