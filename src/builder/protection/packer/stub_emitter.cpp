/**
 * @file stub_emitter.cpp
 * @brief EXE / full-DLL stub assembly — see stub_emitter.hpp.
 */

#include "mxprotector/protection/packer/stub_emitter.hpp"

#include "mxprotector/protection/packer/rc4.hpp"

#include <algorithm>
#include <cstring>

namespace mx::packer {

std::pair<ByteBuffer, ExeStubPatches>
build_exe_stub_bytes(Randomizer& rng,
                     ByteView    stolen_bytes,
                     uint32_t    section_count,
                     uint32_t    layer_count)
{
    RawEmitter e;
    e.buf.reserve(128 + (32 + 32 * section_count) * layer_count +
                  stolen_bytes.size() + kKeySize * layer_count);

    ExeStubPatches patches{};

    // (1) Randomised push/pop register order. Same permutation used
    //     for pushes (top-down) and pops (reversed) so the stack is
    //     balanced across the cipher body.
    std::array<uint8_t, 5> save_order{0x50 /*rax*/, 0x51 /*rcx*/,
                                       0x52 /*rdx*/, 0x56 /*rsi*/,
                                       0x57 /*rdi*/};
    std::shuffle(save_order.begin(), save_order.end(), rng.engine());
    for (uint8_t op : save_order) e.u8(op);

    // (2) Shared decrypt body — anti-debug, KSA, PRGA per section,
    //     reprotect, IAT wipe. Populates the CipherBodyPatches slots
    //     of `patches` via the multi-inheritance base.
    emit_decrypt_body(e, patches, rng, section_count, layer_count);

    // (3) Restore registers in reverse of the saved order (LIFO).
    for (auto it = save_order.rbegin(); it != save_order.rend(); ++it) {
        e.u8(static_cast<uint8_t>(*it + 0x08));
    }

    // (4) Stolen OEP bytes run inline — rsp is now back to what the
    //     OEP would have seen at entry. If none were stolen this is
    //     empty.
    patches.stolen_bytes_offset = static_cast<uint32_t>(e.size());
    e.bytes(stolen_bytes);

    // (5) jmp rel32 → OEP + stolen_size
    e.u8(0xE9);
    patches.rel_to_oep_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    return {std::move(e.buf), patches};
}

std::pair<ByteBuffer, DllFullStubPatches>
build_dll_full_stub_bytes(Randomizer& rng,
                          ByteView    stolen_bytes,
                          uint32_t    section_count,
                          uint32_t    layer_count)
{
    RawEmitter e;
    e.buf.reserve(192 + (32 + 32 * section_count) * layer_count +
                  stolen_bytes.size() + kKeySize * layer_count);

    DllFullStubPatches patches{};

    // (1) Save nonvolatiles + DllMain args. Fixed order — polymorphism
    //     comes from the anti-debug probe and KSA variance. 11 pushes
    //     → rsp mod 16 = 0 before the cipher body starts.
    e.u8(0x53);                    // push rbx
    e.u8(0x55);                    // push rbp
    e.u8(0x56);                    // push rsi
    e.u8(0x57);                    // push rdi
    e.u8(0x41); e.u8(0x54);        // push r12
    e.u8(0x41); e.u8(0x55);        // push r13
    e.u8(0x41); e.u8(0x56);        // push r14
    e.u8(0x41); e.u8(0x57);        // push r15
    e.u8(0x51);                    // push rcx  (HINSTANCE)
    e.u8(0x52);                    // push rdx  (reason — consumed by KSA bias seed)
    e.u8(0x41); e.u8(0x50);        // push r8   (lpReserved)

    // (2) Gate on reason == DLL_PROCESS_ATTACH (1). rdx still holds
    //     the original reason at this point (the cmp is 32-bit safe
    //     because the reason argument is a DWORD).
    //
    //   cmp edx, 1                        83 FA 01
    e.u8(0x83); e.u8(0xFA); e.u8(0x01);
    //   jne .forward (rel32, back-patched below)  0F 85 rel32
    e.u8(0x0F); e.u8(0x85);
    const uint32_t reason_jne_rel32_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    // (3) Shared decrypt body.
    emit_decrypt_body(e, patches, rng, section_count, layer_count);

    // (4) .forward: — back-patch the jne target.
    {
        const uint32_t forward_label = static_cast<uint32_t>(e.size());
        const int32_t rel32 = static_cast<int32_t>(forward_label) -
            static_cast<int32_t>(reason_jne_rel32_at + 4);
        std::memcpy(e.buf.data() + reason_jne_rel32_at, &rel32, sizeof(rel32));
    }

    // (5) Pop nonvolatiles + DllMain args in reverse push order.
    e.u8(0x41); e.u8(0x58);        // pop r8
    e.u8(0x5A);                    // pop rdx
    e.u8(0x59);                    // pop rcx
    e.u8(0x41); e.u8(0x5F);        // pop r15
    e.u8(0x41); e.u8(0x5E);        // pop r14
    e.u8(0x41); e.u8(0x5D);        // pop r13
    e.u8(0x41); e.u8(0x5C);        // pop r12
    e.u8(0x5F);                    // pop rdi
    e.u8(0x5E);                    // pop rsi
    e.u8(0x5D);                    // pop rbp
    e.u8(0x5B);                    // pop rbx

    // (6) Stolen DllMain prologue bytes inline (may be empty).
    patches.stolen_bytes_offset = static_cast<uint32_t>(e.size());
    e.bytes(stolen_bytes);

    // (7) jmp rel32 → DllMain + stolen_size
    e.u8(0xE9);
    patches.rel_to_oep_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    return {std::move(e.buf), patches};
}

} // namespace mx::packer
