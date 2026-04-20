/**
 * @file bench_hold.hpp
 * @brief Shared ``--hold N`` helper for corpus sources.
 *
 * Some benchmarks (pe-sieve, any future attach-and-scan workflow)
 * need the corpus binary to stay resident long enough for an
 * external tool to attach after decryption has finished.
 * ``bench_hold_from_argv`` implements that: if the caller passed
 * ``--hold <seconds>`` on the command line, the helper sleeps for
 * that many seconds before returning. Otherwise no-op.
 *
 * Placed in a header rather than a .cpp so every corpus sample can
 * pick it up with a single ``#include`` and one line at the end of
 * ``main`` — no extra translation units, no link-time surprises.
 */

#pragma once

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

/**
 * @brief Sleep for ``--hold <N>`` seconds if present in ``argv``.
 *
 * A sentinel value of zero (or absent flag) is a no-op so plain
 * ``./pure_vm`` still runs as a one-shot compute-and-exit program.
 * Only the first ``--hold`` is honoured; duplicates are ignored.
 */
inline void bench_hold_from_argv(int argc, char** argv) noexcept {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--hold") == 0) {
            int seconds = std::atoi(argv[i + 1]);
            if (seconds > 0) {
                std::this_thread::sleep_for(std::chrono::seconds(seconds));
            }
            return;
        }
    }
}
