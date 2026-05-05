/**
 * @file decryptor_prologue.hpp
 * @brief Shared 31-byte descriptor-load prologue used by both the
 *        S2b sticky and S3 ephemeral `mx_str_get` variants.
 *
 * @details Pure byte-level codegen, header-only `inline` so the two
 *          variant translation units (`string_decryptor_codegen.cpp`
 *          and `string_decryptor_ephemeral.cpp`) share the
 *          implementation without an extra TU.
 *
 * @note    Internal to the string protection module — do not include
 *          from outside `src/builder/protection/string/`.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace mx::string_protect::detail {

/// Byte offsets (inside the emitted buffer) of the two rip-relative
/// `disp32` slots populated by the shared `mx_str_get` prologue. The
/// caller stores these in its own output struct so the post-link
/// patcher can point them at the final `.mxstr` descriptor table and
/// data pool.
struct MxStrGetPrologueOffsets {
    std::size_t desc_table_disp32_offset;
    std::size_t data_base_disp32_offset;
};

/// Emit the 31-byte `mx_str_get` descriptor-load prologue shared by
/// the S2b (sticky) and S3 (ephemeral) variants.
///
///     lea    r10, [rip + desc_table_disp32]    ; 7 bytes
///     lea    r10, [r10 + rcx*8]                ; 4 bytes
///     mov    eax, dword [r10]                  ; 3 bytes
///     movzx  ecx, word  [r10 + 4]              ; 5 bytes
///     movzx  edx, byte  [r10 + 6]              ; 5 bytes
///     lea    r11, [rip + data_base_disp32]     ; 7 bytes
///
/// After the two `disp32`s are patched, `r10` points at the
/// per-string descriptor entry, `r11` at the data pool base,
/// `eax`/`ecx`/`edx` hold the data_offset / length / key fields.
[[nodiscard]] inline MxStrGetPrologueOffsets
emit_mx_str_desc_prologue(std::vector<std::uint8_t>& c)
{
    MxStrGetPrologueOffsets out{};

    // lea r10, [rip + desc_table_disp32]           (7 bytes)
    // REX.W|R (0x4C) + 0x8D + ModRM(00 010 101 = 0x15) + disp32=0
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x15);
    out.desc_table_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // lea r10, [r10 + rcx*8]                       (4 bytes)
    // REX.W|R|B (0x4D) + 0x8D + ModRM(00 010 100 = 0x14) + SIB(11 001 010 = 0xCA)
    c.push_back(0x4D); c.push_back(0x8D); c.push_back(0x14); c.push_back(0xCA);

    // mov eax, dword [r10]                         (3 bytes)
    // REX.B (0x41) + 0x8B + ModRM(00 000 010 = 0x02)
    c.push_back(0x41); c.push_back(0x8B); c.push_back(0x02);

    // movzx ecx, word [r10 + 4]                    (5 bytes)
    // REX.B + 0x0F B7 + ModRM(01 001 010 = 0x4A) + disp8=4
    c.push_back(0x41); c.push_back(0x0F); c.push_back(0xB7);
    c.push_back(0x4A); c.push_back(0x04);

    // movzx edx, byte [r10 + 6]                    (5 bytes)
    // REX.B + 0x0F B6 + ModRM(01 010 010 = 0x52) + disp8=6
    c.push_back(0x41); c.push_back(0x0F); c.push_back(0xB6);
    c.push_back(0x52); c.push_back(0x06);

    // lea r11, [rip + data_base_disp32]            (7 bytes)
    // REX.W|R + 0x8D + ModRM(00 011 101 = 0x1D) + disp32=0
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x1D);
    out.data_base_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    return out;
}

} // namespace mx::string_protect::detail
