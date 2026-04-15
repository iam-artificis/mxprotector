/**
 * @file test_exception.cpp
 * @brief Compatibility smoke test for the G3 Phase 2 VEH INT3 trap.
 *
 * A minimal binary that throws and catches a C++ exception. The
 * `--anti-tamper-veh` code path installs a process-wide Vectored
 * Exception Handler in the packer stub; the VEH is supposed to
 * return `EXCEPTION_CONTINUE_SEARCH` for every exception that is
 * NOT a breakpoint at our one planted `int3` address, so the
 * C++ runtime's own exception machinery must keep working.
 *
 * If this binary ever exits with a non-zero status after being
 * protected with `--anti-tamper-veh`, the VEH's address filter is
 * broken and we're silently swallowing user exceptions — a
 * severe correctness regression that would break any protected
 * binary relying on try/catch.
 *
 * The test deliberately throws several different kinds of objects
 * so at least one of them exercises the C++ runtime's EXCEPTION_
 * RECORD path (code 0xE06D7363, "MS C++ exception"). A plain
 * throw of an `int` is enough — the runtime still goes through
 * RaiseException, which fires first-chance exceptions through
 * the same VEH chain we hook.
 */

#include <cstdio>
#include <stdexcept>
#include <string>

namespace {

[[noreturn]] void throw_int_value() {
    throw 42;
}

[[noreturn]] void throw_runtime_error() {
    throw std::runtime_error("cpp exception path");
}

[[noreturn]] void throw_string() {
    throw std::string("stdstring exception path");
}

} // namespace

int main() {
    std::printf("[test_exception] start\n");

    int caught_count = 0;

    // (1) Plain int — simplest possible C++ throw; still goes
    //     through RaiseException(EXCEPTION_MSVCPP, ...) on Windows.
    try {
        throw_int_value();
    } catch (int v) {
        if (v == 42) {
            ++caught_count;
            std::printf("[test_exception] int path OK\n");
        } else {
            std::printf("[test_exception] int path VALUE MISMATCH (%d)\n", v);
            return 1;
        }
    } catch (...) {
        std::printf("[test_exception] int path WRONG HANDLER\n");
        return 1;
    }

    // (2) std::runtime_error — exercises the std::exception
    //     hierarchy so RTTI matching has to work.
    try {
        throw_runtime_error();
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        if (msg == "cpp exception path") {
            ++caught_count;
            std::printf("[test_exception] runtime_error path OK\n");
        } else {
            std::printf("[test_exception] runtime_error MESSAGE MISMATCH\n");
            return 1;
        }
    } catch (...) {
        std::printf("[test_exception] runtime_error WRONG HANDLER\n");
        return 1;
    }

    // (3) std::string — non-std::exception object, uses a different
    //     RTTI descriptor chain than (2).
    try {
        throw_string();
    } catch (const std::string& s) {
        if (s == "stdstring exception path") {
            ++caught_count;
            std::printf("[test_exception] string path OK\n");
        } else {
            std::printf("[test_exception] string path VALUE MISMATCH\n");
            return 1;
        }
    } catch (...) {
        std::printf("[test_exception] string path WRONG HANDLER\n");
        return 1;
    }

    // (4) Nested throw/catch — make sure the VEH isn't stateful
    //     across exceptions (installing once, catching many times
    //     must be idempotent).
    for (int i = 0; i < 4; ++i) {
        try {
            throw i;
        } catch (int v) {
            if (v != i) {
                std::printf("[test_exception] nested iter %d WRONG\n", i);
                return 1;
            }
        }
    }
    std::printf("[test_exception] nested path OK (4 iterations)\n");

    if (caught_count == 3) {
        std::printf("[test_exception] ALL 4 PATHS PASSED\n");
        return 0;
    }

    std::printf("[test_exception] caught_count=%d (expected 3)\n", caught_count);
    return 1;
}
