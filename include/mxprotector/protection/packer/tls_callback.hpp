/**
 * @file tls_callback.hpp
 * @brief P4 TLS-callback emission + existing-TLS parsing for the packer.
 *
 * The packer installs an extra TLS callback at the head of the TLS
 * callback array so an anti-debug probe runs BEFORE
 * `AddressOfEntryPoint` (for EXEs) or BEFORE `DllMain` (for DLLs).
 * Windows' image loader walks the callback array in order at
 * PROCESS_ATTACH, THREAD_ATTACH, etc., so a callback at position 0
 * fires earlier than any entry point the protector redirected to
 * the packer stub. Breakpoints set on "start" / "main" / "DllMain"
 * symbols do not intercept code run from a TLS callback, so a
 * reverser single-stepping from a classic debugger break lands
 * AFTER the anti-debug probe has already had its say.
 *
 * When the callback detects a debugger it XORs a per-build random
 * mask into one byte of an embedded RC4 key in `.mxpack`. The
 * subsequent packer stub (running from `AddressOfEntryPoint` or the
 * DllMain forwarding stub) then builds its KSA off the corrupted
 * key, produces a different S-box from the build-time one, and
 * every protected section decrypts to garbage. Same silent-kill
 * pattern as the in-stub anti-debug probe, but layered earlier.
 *
 * ## Coexistence with existing TLS data
 *
 * Input PEs built with C++ `__declspec(thread)` statics already
 * ship an `IMAGE_TLS_DIRECTORY64` pointing at a CRT-registered
 * callback chain. `read_existing_tls_directory` parses it so the
 * packer can preserve the non-callback fields verbatim
 * (StartAddressOfRawData / EndAddressOfRawData / AddressOfIndex /
 * SizeOfZeroFill / Characteristics) and prepend its own callback
 * to the front of the existing chain.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"

namespace mx {
class PeImage;
} // namespace mx

namespace mx::packer {

/**
 * @brief Contents of the input PE's existing `IMAGE_TLS_DIRECTORY64`,
 *        if any.
 *
 * We keep the non-callback-array fields verbatim so C++
 * `__declspec(thread)` data that the CRT relies on keeps working,
 * and we prepend our new callback to the existing callback list so
 * every original callback still gets invoked in its original order.
 */
struct ExistingTlsDirectory {
    uint64_t              start_va          = 0;
    uint64_t              end_va            = 0;
    uint64_t              index_va          = 0;
    uint32_t              size_of_zero_fill = 0;
    uint32_t              characteristics   = 0;
    std::vector<uint64_t> callbacks;  ///< raw VAs, preserved order, NULL stripped
};

/**
 * @brief Parse the input's `IMAGE_TLS_DIRECTORY64`.
 *
 * @return `std::nullopt` if the PE has no TLS directory or its
 *         bytes can't be resolved inside an input section. Any
 *         parsing failure is treated as "no TLS" — the packer logs
 *         it and proceeds without TLS protection rather than
 *         aborting the build.
 */
[[nodiscard]] std::optional<ExistingTlsDirectory>
read_existing_tls_directory(const PeImage& image);

/**
 * @brief Stub-relative offsets recorded while `emit_tls_callback_body`
 *        emits its ~32 bytes.
 *
 * The finalizer uses these to back-patch the one rip-relative slot
 * inside the callback body (`xor_key_rel32_offset`) once the stub
 * section's runtime RVA is known, and to pick which embedded RC4
 * key byte to corrupt (per-build random layer index + byte index).
 */
struct TlsCallbackEmit {
    uint32_t body_offset            = 0;  ///< offset of first byte of callback
    uint32_t xor_key_rel32_offset   = 0;  ///< rel32 inside the xor-byte instruction
    uint32_t xor_instruction_end    = 0;  ///< byte right after the xor imm8
    uint32_t body_end_offset        = 0;  ///< one past the last byte (for padding)
    uint32_t key_byte_offset_in_key = 0;  ///< 0..kKeySize-1 — which key byte to corrupt
    uint32_t key_layer_index        = 0;  ///< 0..layer_count-1 — which layer's key
};

/**
 * @brief Emit the TLS-callback body into `buf` and record its patch
 *        sites.
 *
 * Layout:
 *
 *     83 FA 01                   cmp   edx, 1              ; reason == PROCESS_ATTACH?
 *     75 rel8                    jne   .done               ; skip everything else
 *     65 48 8B 04 25 60 00 00 00 mov   rax, gs:[0x60]      ; PEB
 *     0F B6 40 02                movzx eax, byte [rax+2]   ; BeingDebugged
 *     85 C0                      test  eax, eax
 *     74 rel8                    je    .done               ; clean host → skip XOR
 *     80 35 rel32 imm8           xor   byte [rip+rel32], mask ; corrupt one key byte
 *     .done:
 *     31 C0                      xor   eax, eax            ; return 0 (VOID cast)
 *     C3                         ret
 *
 * Registers used: `rax`, `edx` — both volatile in the Windows x64
 * ABI, and the caller is a VOID NTAPI callback so the return value
 * is ignored. `rcx`, `r8` (hModule, lpReserved) are not touched —
 * the callback stays compatible with any existing TLS callback
 * that reads them.
 *
 * @param buf          Buffer the bytes are appended to.
 * @param rng          Randomiser for the XOR mask, target byte, and
 *                     (via `layer_count`) target layer.
 * @param layer_count  Number of cipher layers in the current build.
 *                     Must be ≥ 1; the target layer is drawn
 *                     uniformly from `[0, layer_count)`.
 */
[[nodiscard]] TlsCallbackEmit emit_tls_callback_body(ByteBuffer& buf,
                                                     Randomizer& rng,
                                                     uint32_t    layer_count);

} // namespace mx::packer
