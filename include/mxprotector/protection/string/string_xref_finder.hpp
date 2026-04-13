/**
 * @file string_xref_finder.hpp
 * @brief [BUILDER] Finds `LEA reg, [rip+disp32]` sites referencing
 *        discovered string candidates.
 *
 * Second stage of the S2 pipeline. Given a disassembly range of
 * `.text` (a byte buffer + the RVA of the buffer's first byte) and
 * a sorted list of `FoundString` candidates, the finder walks the
 * buffer with Zydis and emits a record for every
 * `LEA destreg, [rip + disp32]` instruction whose resolved target
 * address falls exactly on a candidate's `rva_start`.
 *
 * Only `LEA` is recognised in v1. Other rip-relative forms
 * (`mov reg, [rip+disp]` loads the bytes instead of the address;
 * `cmp [rip+disp], imm` reads bytes; `call [rip+disp]` jumps to a
 * pointer at that address — none of these are "take the address of
 * a string to use as `char*`", so none need rewriting).
 *
 * Only exact `rva_start` matches count. An intra-string reference
 * (LEA pointing halfway into a C string — e.g. `"hello world" + 6`
 * to get `"world"`) is rare but real. v1 drops those by requiring
 * exact match; treating them would need the runtime decryptor to
 * handle partial decode, which is out of scope for MVP.
 *
 * Like the scanner, the finder is a pure in/out module. It takes
 * byte views as input and returns value records — no PE plumbing,
 * no disassembler lifetime management beyond the call.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"

namespace mx::string_protect {

/**
 * @brief One LEA rip-relative reference to a candidate string.
 *
 * `xref_rva`      — the RVA of the LEA instruction itself
 *                   (`.text` + offset in the scanned buffer).
 * `insn_length`   — the instruction length in bytes, typically 7
 *                   for `lea reg, [rip+disp32]` (REX + 8D + ModRM +
 *                   disp32). The rewriter uses this to size the
 *                   replacement + padding.
 * `disp_offset`   — offset inside the instruction bytes where the
 *                   `disp32` field lives. The rewriter never uses
 *                   this (it overwrites the whole instruction), but
 *                   it's kept for diagnostics / future patchers.
 * `dest_reg`      — the Zydis register number of the LEA's
 *                   destination. Stored as a Zydis opaque value so
 *                   downstream code can build the heavyweight
 *                   trampoline that knows which saved-slot to patch.
 * `target_rva`    — the resolved absolute target RVA (= `xref_rva +
 *                   insn_length + disp32`). Always equal to some
 *                   `FoundString::rva_start`.
 * `string_index`  — index into the candidate list passed to
 *                   `find`. Makes it trivial for the rewriter to
 *                   look up the matching string.
 */
struct StringXref {
    Rva      xref_rva      = 0;
    uint8_t  insn_length   = 0;
    uint8_t  disp_offset   = 0;
    uint32_t dest_reg      = 0;   // ZydisRegister, opaquely stored
    Rva      target_rva    = 0;
    size_t   string_index  = 0;
};

class StringXrefFinder {
public:
    StringXrefFinder() = default;

    /**
     * @brief Scan `code` for LEA rip-relative references to any of
     *        the strings in `candidates`.
     *
     * @param code        Raw machine code (typically a `.text`
     *                    section's contents).
     * @param code_rva    The RVA of `code[0]` inside the image.
     * @param candidates  The list from `StringScanner::scan`, MUST
     *                    be sorted by `rva_start` (scanner output
     *                    already satisfies this). Not modified.
     *
     * @return All LEA sites whose resolved target hits a candidate
     *         exactly. Iteration is linear in `code.size()` — one
     *         Zydis decode per byte offset, advancing by the
     *         decoded instruction length (a fall-forward by 1 on
     *         decode failure).
     *
     * Not thread-safe. Constructs a fresh `ZydisDecoder` per call
     * so multiple threads can instantiate their own finders.
     */
    [[nodiscard]] std::vector<StringXref>
    find(ByteView                       code,
         Rva                             code_rva,
         const std::vector<FoundString>& candidates) const;
};

} // namespace mx::string_protect
