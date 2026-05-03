/**
 * @file inject_target.cpp
 * @brief Plain Win32 host process for validating mxprotector
 *        DLL injection end-to-end.
 *
 * SUBSYSTEM:WINDOWS so it has NO pre-existing console — our
 * payload DLL's `AllocConsole()` will actually spawn a new
 * console window instead of failing with "process already has
 * a console".
 *
 * No AppContainer, no UWP, no .NET. Target processes like
 * `calc.exe` on Windows 11 are Store apps running in restricted
 * sandboxes where AllocConsole, CreateThread, and syscall-level
 * anti-tamper checks can fail or trip false positives — use
 * this host instead.
 *
 * The main thread sleeps forever. Launch it, look up its PID in
 * Process Hacker, then inject the protected DLL via
 * Process Hacker → Miscellaneous → Inject DLL.
 */

#include <windows.h>

// Wide-char stdlib so this compiles as /SUBSYSTEM:WINDOWS without
// pulling in the CRT console startup routines.
int WINAPI wWinMain(HINSTANCE /*hInstance*/,
                    HINSTANCE /*hPrevInstance*/,
                    LPWSTR    /*lpCmdLine*/,
                    int       /*nShowCmd*/)
{
    // Set a recognisable window title via SetConsoleTitleW has no
    // effect here (we have no console), so we just spin. Process
    // Hacker shows the executable name so `inject_target.exe` is
    // easy to spot in the process list.
    for (;;) {
        Sleep(60000);
    }
    return 0;
}
