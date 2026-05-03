/**
 * @file unwind_info_reference_scanner.hpp
 * @brief Emit references for `UNWIND_INFO`-embedded RVAs (B.4.12.1).
 *
 * Every `RUNTIME_FUNCTION` in `.pdata` carries an `UnwindData` RVA
 * pointing at an `UNWIND_INFO` block (typically in `.rdata` or
 * `.xdata`). When the function's `UNW_FLAG_EHANDLER` /
 * `UNW_FLAG_UHANDLER` flag is set, the block has a trailing
 * 4-byte `ExceptionHandler` RVA pointing back at a function in
 * `.text`. When `UNW_FLAG_CHAININFO` is set, the block has a
 * trailing 12-byte chained `RUNTIME_FUNCTION` whose three fields
 * are also RVAs into the image.
 *
 * Critically, **none of these RVAs live in `.reloc`** — they are
 * 4-byte image-relative offsets baked in at link time, and the
 * Windows loader treats them as RVAs without applying ASLR delta.
 * That means existing `RelocAbsoluteVaScanner` does not see them,
 * yet they point at code that the chaos shuffle moves. Without
 * a dedicated scanner, the post-shuffle binary keeps stale RVAs
 * and crashes the moment SEH dispatches into a handler — or, for
 * MSVC CRT, even in the prologue's `__GSHandlerCheck` thunk
 * called via `RtlVirtualUnwind` during normal stack walks.
 *
 * The scanner walks `.pdata`, follows each `UnwindData` to its
 * `UNWIND_INFO`, parses the header, skips the `UnwindCode` array,
 * applies the 4-byte alignment to reach the optional trailer, and
 * emits one reference per RVA found there.
 *
 * SOLID:
 *   * SRP — exactly one PE-format concern (UNWIND_INFO trailers).
 *   * OCP — adding/removing the scanner is a one-line change in
 *     `chaos_layout.cpp::scan_all_references`.
 *
 * Threading: stateless apart from a `.pdata` parse — re-create the
 * scanner per call.
 */

#pragma once

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

class ReferenceTable;

/**
 * @brief `.pdata`-driven UNWIND_INFO trailer scanner — see file header.
 */
class UnwindInfoReferenceScanner {
public:
    UnwindInfoReferenceScanner() = default;

    /**
     * @brief Walk `.pdata` and emit references for every UNWIND_INFO
     *        trailer field.
     *
     * No-op when:
     *   * Image is not 64-bit.
     *   * `.pdata` directory is missing or smaller than one
     *     `RUNTIME_FUNCTION`.
     *   * The `UnwindData` for an entry resolves to bytes outside
     *     any section.
     *
     * Malformed entries (impossible counts / out-of-bounds reads)
     * are skipped silently — atom sources MUST NOT throw.
     */
    void scan(
        const PeImage& image,
        ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
