/**
 * @file hello_inject_loader.cpp
 * @brief Minimal GUI-less host that LoadLibrary's a payload DLL
 *        for a configurable duration so mxprotector's packer + VM
 *        + TLS callback + anti-tamper + runtime-guards flow can be
 *        observed end-to-end.
 *
 *        `hello_inject_loader.exe <dll_path> [seconds]`
 *
 *        Defaults to `hello_inject_dll.dll` and 6 seconds. Pass a
 *        larger `seconds` value when you need a wide dump window —
 *        for example, `hello_inject_loader.exe
 *        hello_guard_dll.protected.dll 600` keeps the DLL resident
 *        for 10 minutes so you can attach Process Hacker / x64dbg
 *        and dump the `.mxguard` section at your leisure.
 *
 *        Exit code 0 on success, 1 on LoadLibrary failure.
 */

#include <windows.h>

#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    const char* dll_path = (argc > 1)
        ? argv[1]
        : "hello_inject_dll.dll";
    const int sleep_seconds = (argc > 2)
        ? std::atoi(argv[2])
        : 6;

    std::printf("[hello_loader] LoadLibraryA(\"%s\")\n", dll_path);
    HMODULE h = LoadLibraryA(dll_path);
    if (h == nullptr) {
        std::printf("[hello_loader] LoadLibraryA FAILED, GetLastError=%lu\n",
                    GetLastError());
        return 1;
    }
    std::printf("[hello_loader] LoadLibraryA returned h=%p\n", (void*)h);
    std::printf("[hello_loader] sleeping %d s so the worker thread "
                "can run (and you can dump memory)...\n",
                sleep_seconds);
    Sleep(static_cast<DWORD>(sleep_seconds) * 1000u);

    std::printf("[hello_loader] FreeLibrary\n");
    FreeLibrary(h);
    return 0;
}
