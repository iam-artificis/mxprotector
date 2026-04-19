#include "mxprotector/protection/guard/guard_decrypt_unit.hpp"

#include "mxprotector/core/asm_builder.hpp"

#include <cstdint>

namespace mx::guard {

GuardDecryptUnitEmit emit_guard_decrypt_unit(RawEmitter& e) {
    GuardDecryptUnitEmit out{};
    const uint32_t start = static_cast<uint32_t>(e.size());

    // mov edx, [rsi + 8]            body_start_rva
    e.u8(0x8B); e.u8(0x56); e.u8(0x08);
    // add rdx, rbx                  body_va
    e.u8(0x48); e.u8(0x01); e.u8(0xDA);
    // mov ecx, [rsi + 0x10]         body_size
    e.u8(0x8B); e.u8(0x4E); e.u8(0x10);
    // xor r9d, r9d                  key index = 0
    e.u8(0x45); e.u8(0x31); e.u8(0xC9);
    // mov r8d, r11d                 rolling hash mask
    e.u8(0x45); e.u8(0x89); e.u8(0xD8);
    // test ecx, ecx
    e.u8(0x85); e.u8(0xC9);
    // jz .decrypt_done
    e.u8(0x74);
    const uint32_t jz_done_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    const uint32_t loop_label = static_cast<uint32_t>(e.size());

    // movzx eax, byte [rsi + r9 + 0x18]
    e.u8(0x42); e.u8(0x0F); e.u8(0xB6); e.u8(0x44); e.u8(0x0E); e.u8(0x18);
    // xor al, r8b
    e.u8(0x44); e.u8(0x30); e.u8(0xC0);
    // ror r8d, 8
    e.u8(0x41); e.u8(0xC1); e.u8(0xC8); e.u8(0x08);
    // xor [rdx], al
    e.u8(0x30); e.u8(0x02);
    // inc rdx
    e.u8(0x48); e.u8(0xFF); e.u8(0xC2);
    // inc r9d
    e.u8(0x41); e.u8(0xFF); e.u8(0xC1);
    // cmp r9d, 32
    e.u8(0x41); e.u8(0x83); e.u8(0xF9); e.u8(0x20);
    // jb .no_wrap  (+3 to skip xor r9d, r9d)
    e.u8(0x72); e.u8(0x03);
    // xor r9d, r9d
    e.u8(0x45); e.u8(0x31); e.u8(0xC9);
    // .no_wrap:
    // dec ecx
    e.u8(0xFF); e.u8(0xC9);
    // jnz .decrypt_loop
    e.u8(0x75);
    const uint32_t jnz_loop_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    {
        const int32_t rel8 =
            static_cast<int32_t>(loop_label) -
            static_cast<int32_t>(jnz_loop_slot + 1);
        e.buf[jnz_loop_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    // .decrypt_done:
    const uint32_t done_label = static_cast<uint32_t>(e.size());
    // ret
    e.u8(asm64::kRet);

    // Back-patch jz .decrypt_done
    {
        const int32_t rel8 =
            static_cast<int32_t>(done_label) -
            static_cast<int32_t>(jz_done_slot + 1);
        e.buf[jz_done_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    out.size = static_cast<uint32_t>(e.size()) - start;
    return out;
}

} // namespace mx::guard
