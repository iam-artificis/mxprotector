/**
 * @file cff_safety_filters.hpp
 * @brief Guards that decide whether a function is safe to flatten.
 *
 * CFG flattening rewrites a function's control flow into a dispatcher-
 * driven state machine. A handful of patterns in real MSVC-emitted code
 * don't tolerate that rewrite — either because the flattener mishandles
 * a specific prologue, or because the Windows unwinder expects the
 * body's byte layout to match the `.xdata` it carries. Running CFF on
 * such a function produces a binary that crashes deterministically.
 *
 * The filters here are the whitelist gate: a function only becomes a
 * CFF candidate if every filter returns `false`.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx {
class PeImage;
}

namespace mx::cff {

/**
 * @brief Detect the MSVC "register-save-via-rsp-copy" prologue pattern.
 *
 * The bytes in question are either:
 *   - `48 8B C4` — `mov rax, rsp` (load form), or
 *   - `48 89 E0` — the equivalent post-mutation store form.
 *
 * Both re-encode the same `mov rax, rsp`. The function that follows
 * saves non-volatile registers via `mov [rax+N], reg` instead of
 * `push reg`, and the flattener doesn't reliably preserve the offsets
 * between the rax-load and those mov-based saves. Skipping the entire
 * function is the only robust workaround until the flattener learns
 * this pattern; see the implementation file for the full incident
 * details.
 *
 * @return `true` when the first instruction matches either form.
 */
[[nodiscard]] bool first_instruction_is_mov_rax_rsp(ByteView func_bytes) noexcept;

/**
 * @brief Reject functions whose `.xdata` unwind record is incompatible
 *        with CFF.
 *
 * Any of three flags in `UNWIND_INFO` is a stop-sign:
 *   - `UNW_FLAG_EHANDLER` (0x01) — the function owns an SEH / C++ catch
 *     scope table; flattening invalidates every address inside it.
 *   - `UNW_FLAG_UHANDLER` (0x02) — termination handler
 *     (`__try/__finally`). Same staleness risk.
 *   - `UNW_FLAG_CHAININFO` (0x04) — this record covers a code slice
 *     inside a larger function; linear execution falls through into the
 *     parent, so flattening the slice standalone produces a dispatcher
 *     `jmp exit` that traps the process on the fall-through path.
 *
 * `unwind_info_rva == 0` (no unwind record) returns `false` — leaf
 * functions without unwind data are fine.
 *
 * @param image PE image the function belongs to (for section lookup).
 * @param unwind_info_rva RVA of the `UNWIND_INFO` record from the
 *        function's `RUNTIME_FUNCTION` entry.
 */
[[nodiscard]] bool unwind_info_makes_function_unsafe(
    const PeImage& image,
    uint32_t       unwind_info_rva) noexcept;

} // namespace mx::cff
