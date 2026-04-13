/**
 * @file string_scanner.cpp
 * @brief [BUILDER] Linear-time printable-ASCII run scanner.
 *
 * Implementation notes:
 *
 * The scanner walks the input buffer once and maintains two pieces
 * of state:
 *
 *   `run_start` — the offset of the first byte of the current
 *                 printable run, or `kNoRun` if we're not currently
 *                 inside a run.
 *   `i`         — the current cursor.
 *
 * Each iteration classifies `data[i]`:
 *
 *   * Printable byte → extend the run (set `run_start` if fresh).
 *   * Terminator (0x00 if `require_null_terminator`, otherwise ANY
 *     non-printable byte) → if we have an open run of at least
 *     `min_length` bytes, emit it; reset `run_start`.
 *   * Any other non-printable → the run, if any, is invalid: reset.
 *
 * Termination of the buffer is handled by a final flush step that
 * accepts an open run only if `require_null_terminator` is off —
 * otherwise a run that runs off the end of the buffer is ambiguous
 * and we err on the side of rejecting it.
 *
 * Complexity: O(N) time, O(K) output memory where K is the number
 * of emitted candidates.
 */

#include "mxprotector/protection/string/string_scanner.hpp"

#include <algorithm>
#include <cstddef>

namespace mx::string_protect {

namespace {

/// Sentinel for "not currently inside a run".
constexpr size_t kNoRun = static_cast<size_t>(-1);

} // anonymous namespace

std::vector<FoundString>
StringScanner::scan(ByteView data, Rva base_rva) const
{
    std::vector<FoundString> result;
    if (data.empty()) return result;

    // Reserve a conservative guess so the common case (.rdata of a
    // small binary with ~100 strings) avoids reallocation churn.
    result.reserve(64);

    size_t run_start = kNoRun;

    auto emit_run = [&](size_t run_end_exclusive) {
        // run_start .. run_end_exclusive is a pure-printable range.
        // Validate length constraints, then push a FoundString.
        if (run_start == kNoRun) return;
        const size_t len = run_end_exclusive - run_start;
        if (len >= config_.min_length && len <= config_.max_length) {
            FoundString fs{};
            fs.rva_start = base_rva + static_cast<Rva>(run_start);
            fs.length    = static_cast<uint32_t>(len);
            fs.bytes = std::string_view{
                reinterpret_cast<const char*>(data.data() + run_start),
                len
            };
            result.push_back(fs);
        }
        run_start = kNoRun;
    };

    for (size_t i = 0; i < data.size(); ++i) {
        const uint8_t b = data[i];

        if (is_string_byte(b)) {
            if (run_start == kNoRun) run_start = i;
            continue;
        }

        // Non-printable. If we care about NUL termination, accept the
        // run only when the terminator is exactly 0x00; other non-
        // printable bytes (stray binary garbage) invalidate the run.
        // If the scanner is in "any non-printable ends a run" mode,
        // we accept the run regardless.
        if (config_.require_null_terminator) {
            if (b == 0x00) {
                emit_run(/*run_end_exclusive=*/i);
            } else {
                // Garbage byte — whatever printable run we had is
                // not a C string, drop it.
                run_start = kNoRun;
            }
        } else {
            emit_run(/*run_end_exclusive=*/i);
        }
    }

    // Flush a run that reaches the buffer's end. We only accept this
    // when the caller explicitly doesn't require a NUL terminator;
    // otherwise the run is ambiguous — we don't know whether byte
    // `data.size()` (outside the buffer) would be a NUL or not.
    if (run_start != kNoRun && !config_.require_null_terminator) {
        emit_run(/*run_end_exclusive=*/data.size());
    }

    return result;
}

} // namespace mx::string_protect
