/**
 * @file test_string.cpp
 * @brief Integration probe for MX_STR / MX_WSTR.
 *
 * Builds with /std:c++20 /O2 and uses both narrow and wide protected
 * strings. The probe markers below are intentionally distinctive so a
 * post-build grep over the compiled .exe can confirm that the
 * plaintext does NOT appear anywhere in the binary — neither in
 * .rdata (because the bytes are encrypted) nor in code (because the
 * decrypt loop runs through volatile loads, defeating
 * constant-folding).
 *
 * Probe markers:
 *   - PROBE_NARROW: "MX_S1_NARROW_PROBE_QWERTYUIOPASDFGHJKL"
 *   - PROBE_WIDE  : L"MX_S1_WIDE_PROBE_ZXCVBNM1234567890"
 *
 * The build script post-checks that neither marker appears in the
 * compiled binary as raw bytes. Run-time output is captured by the
 * stress wrapper to verify the program decoded both strings.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

#include "mxprotector_sdk/strings.hpp"

int main() {
    auto narrow = MX_STR("MX_S1_NARROW_PROBE_QWERTYUIOPASDFGHJKL");
    auto wide   = MX_WSTR(L"MX_S1_WIDE_PROBE_ZXCVBNM1234567890");

    std::printf("[test_string] narrow=%s\n", narrow.c_str());
    std::wprintf(L"[test_string] wide=%ls\n", wide.c_str());

    // Self-check: re-derive the expected lengths and confirm the
    // holders agree. If MX_STR ever silently truncated, this would
    // catch it.
    const size_t narrow_len = std::strlen("MX_S1_NARROW_PROBE_QWERTYUIOPASDFGHJKL");
    const size_t wide_len   = std::wcslen(L"MX_S1_WIDE_PROBE_ZXCVBNM1234567890");
    if (std::strlen(narrow.c_str()) != narrow_len) {
        std::printf("[test_string] FAIL narrow length mismatch\n");
        return 1;
    }
    if (std::wcslen(wide.c_str()) != wide_len) {
        std::printf("[test_string] FAIL wide length mismatch\n");
        return 1;
    }

    std::printf("[test_string] ALL CHECKS PASSED\n");
    return 0;
}
