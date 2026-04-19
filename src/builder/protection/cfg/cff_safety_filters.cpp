/**
 * @file cff_safety_filters.cpp
 * @brief Implementation of the CFF incompatibility filters.
 *
 * The header covers the "what" and the policy rationale. This file is
 * the full incident log so the reader can see the ground-truth
 * reproduction for every filter.
 */

#include "mxprotector/protection/cfg/cff_safety_filters.hpp"

#include "mxprotector/pe/pe_image.hpp"

namespace mx::cff {

/// Check whether a function's prologue bytes indicate an MSVC
/// "register-save-via-rsp-copy" pattern that the current flattener
/// doesn't handle correctly:
///
///     mov rax, rsp              ; 48 8B C4 (load-form)
///     mov [rax+8], rbx          ; SAVE_NONVOL via the rax alias
///     mov [rax+0x10], rbp
///     ...
///     push r14                  ; THEN the "normal" push saves
///     sub rsp, N
///
/// The ORIGINAL pre-mutation bytes start with `48 8B C4` (opcode 8B
/// = MOV r64, r/m64). After `MutationPass` runs its instruction
/// substitution rules, the same sequence may be re-encoded to the
/// equivalent store-form `48 89 E0` (opcode 89 = MOV r/m64, r64);
/// both encodings produce `mov rax, rsp` with identical semantics.
/// The check below matches either form.
///
/// The failing pattern reproduces deterministically on
/// `test_exception.exe`'s RVA 0x184C CRT helper — a function that
/// saves rbx/rbp/rsi/rdi directly into the caller's shadow space
/// via `mov [rax+N], reg` rather than pushing them. The flattener
/// shuffles blocks and inserts its dispatcher jumps between the
/// `mov rax, rsp` and the subsequent mov-based saves in a way that
/// subtly breaks the function on some code paths. The root cause
/// wasn't isolated in a reasonable time budget, and a bisect via
/// `MX_CFF_SKIP_RVA=184C` confirmed this specific function is the
/// only crash source in the CRT helper window. Skipping it keeps
/// CFF coverage for every standard-prologue function while
/// avoiding the one pattern the flattener gets wrong.
bool first_instruction_is_mov_rax_rsp(ByteView func_bytes) noexcept {
    if (func_bytes.size() < 3) return false;
    // `48 8B C4` — MOV r64 rax, r/m64 rsp (load form)
    // `48 89 E0` — MOV r/m64 rax, r64 rsp (store form, post-mutation)
    if (func_bytes[0] == 0x48 && func_bytes[1] == 0x8B && func_bytes[2] == 0xC4) {
        return true;
    }
    if (func_bytes[0] == 0x48 && func_bytes[1] == 0x89 && func_bytes[2] == 0xE0) {
        return true;
    }
    return false;
}

/// Check whether a function's `.xdata` unwind record makes it unsafe
/// for CFG flattening. Three conditions, any of which is a stop-sign:
///
///   * `UNW_FLAG_EHANDLER (0x01)` — function has a `__try/__except`
///     or C++ catch scope directly attached. The SEH dispatcher
///     reads a language-specific scope table inline after the
///     unwind codes and matches current `Rip` against it to pick
///     the right filter. If CFF rewrites the function body, every
///     address in the scope table becomes stale and the match
///     picks the wrong filter — typical outcome is a silent
///     process abort during CRT startup.
///
///   * `UNW_FLAG_UHANDLER (0x02)` — termination handler
///     (`__try/__finally`). Same staleness risk. MSVC's
///     `__scrt_common_main_seh`, the CRT wrapper that runs
///     `main()` inside a `__try/__except(seh_filter_exe(...))`,
///     always has this flag set.
///
///   * `UNW_FLAG_CHAININFO (0x04)` — this record chains into
///     another record's unwind codes. Chained records are NOT
///     standalone functions: MSVC emits them when a single logical
///     function has multiple prologue phases (e.g., register saves
///     deferred past the main prologue because the saved register
///     is live-in), and each phase needs its own unwind codes.
///     The `begin/end` range of a chained entry covers a code
///     SLICE inside a larger function, and linear execution
///     typically falls out of the slice into the parent. CFF
///     processing this as a standalone function produces code that
///     emits `jmp exit` (= `int3` trap) where the original just
///     continued linearly into the rest of the parent function,
///     aborting the process the moment execution reaches that
///     slice. The test_exception.exe crash under `-l standard` was
///     this exact case at RVA 0x10C1, a chained entry whose parent
///     starts at RVA 0x1070.
///
/// The `.xdata` bytes may live in `.xdata`, `.rdata`, or any other
/// data section — MSVC typically emits unwind info into `.rdata`.
/// We resolve the containing section by RVA rather than by name.
bool unwind_info_makes_function_unsafe(
    const PeImage& image,
    uint32_t       unwind_info_rva) noexcept
{
    if (unwind_info_rva == 0) return false;

    const pe::SectionInfo* sec = image.section_by_rva(unwind_info_rva);
    if (sec == nullptr) return false;

    const uint32_t offset = unwind_info_rva - sec->virtual_address;
    if (offset >= sec->data.size()) return false;

    // UNWIND_INFO first byte: Version(3 bits) | Flags(5 bits).
    const uint8_t first_byte = sec->data[offset];
    const uint8_t flags = static_cast<uint8_t>((first_byte >> 3) & 0x1F);

    constexpr uint8_t kEhandler  = 0x01;
    constexpr uint8_t kUhandler  = 0x02;
    constexpr uint8_t kChainInfo = 0x04;

    return (flags & (kEhandler | kUhandler | kChainInfo)) != 0;
}

} // namespace mx::cff
