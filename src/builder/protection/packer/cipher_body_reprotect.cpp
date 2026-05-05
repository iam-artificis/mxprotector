/**
 * @file cipher_body_reprotect.cpp
 * @brief Implementation of the post-decrypt reprotect block emitter.
 *
 * See cipher_body_reprotect.hpp for the contract. The byte-for-byte
 * emission was extracted verbatim from cipher_body.cpp during R10
 * splitting; runtime behaviour is unchanged.
 */

#include "cipher_body_reprotect.hpp"

#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

#include <cstdint>

namespace mx::packer {

void emit_reprotect_block(RawEmitter&        e,
                          Randomizer&        rng,
                          CipherBodyPatches& patches,
                          uint32_t           section_count)
{
    const uint32_t reprotect_entry_count = section_count;
    patches.reprotect_entry_count = reprotect_entry_count;

    // Save rsp, align, and allocate our scratch+call frame.
    //   mov r12, rsp                 49 89 E4
    //   and rsp, -16                 48 83 E4 F0
    //   sub rsp, 0x50                48 81 EC 50 00 00 00
    //
    // After sub the frame looks like:
    //   [rsp+0x00..0x1F]  shadow space for the callee's arg1..4 homes
    //   [rsp+0x20]        arg5 slot = &old_protect_var (set once)
    //   [rsp+0x30]        base_var  (rdx target, rewritten per iter)
    //   [rsp+0x38]        size_var  (r8 target, rewritten per iter)
    //   [rsp+0x40]        old_protect_var (PULONG output)
    //
    // `and rsp, -16` ensures rsp is 16-aligned BEFORE the `call r13`
    // below — the CALL push will then leave rsp at mod16==8 inside
    // ntdll's stub, which is what the Windows x64 ABI expects.
    e.u8(0x49); e.u8(0x89); e.u8(0xE4);
    e.u8(0x48); e.u8(0x83); e.u8(0xE4); e.u8(0xF0);
    e.u8(0x48); e.u8(0x81); e.u8(0xEC);
    e.u32(0x00000050u);

    // Hell's Gate address resolver → r13 = NtProtectVirtualMemory
    // function body address. The resolver walks the PEB, finds ntdll,
    // and looks up the export by salted DJB2 hash. On failure r13 is
    // left at 0 and we skip the reprotect loop entirely.
    //
    // The per-build random salt kills the "djb2_hash → ntdll API"
    // reverse-lookup dictionary: every build folds a different 32-bit
    // constant into the hash seed, so both the `cmp eax, target_hash`
    // slot and the scan-loop initial seed slot change from build to
    // build even though the target API name is the same.
    {
        RawEmitter tmp{};
        const uint32_t salt = rng.next_u32();
        const uint32_t ntprotect_hash =
            anti_tamper::djb2_ascii_hash_salted(
                "NtProtectVirtualMemory", salt);
        anti_tamper::emit_hells_gate_address_resolver(
            tmp, ntprotect_hash, salt);
        e.bytes(ByteView{tmp.buf.data(), tmp.buf.size()});
    }

    // test r13, r13                          4D 85 ED
    e.u8(0x4D); e.u8(0x85); e.u8(0xED);
    // jz short .reprotect_done               74 rel8 (patched below)
    e.u8(0x74);
    const uint32_t patch_jz_reprotect_done = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // --- One-time setup outside the loop: ImageBase, arg5, table ---

    // rbx = our own module's runtime image base, computed rip-relative.
    // PEB.ImageBaseAddress would give the host EXE's base, which is
    // correct for executables but wrong for DLLs (we'd reprotect pages
    // inside the host's image instead of our own). The rip-relative
    // path works for both.
    //
    //   lea rbx, [rip + 0]                   48 8D 1D 00 00 00 00
    //     rbx = runtime address of the next instruction = ImageBase
    //           + stub_section_rva + `imagebase_lea_anchor_offset`.
    //   sub rbx, <imm32>                     48 81 EB imm32
    //     imm32 = stub_section_rva + imagebase_lea_anchor_offset
    //     → rbx = ImageBase (always, EXE or DLL).
    e.u8(0x48); e.u8(0x8D); e.u8(0x1D);
    e.u8(0x00); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    patches.imagebase_lea_anchor_offset = static_cast<uint32_t>(e.size());
    e.u8(0x48); e.u8(0x81); e.u8(0xEB);
    patches.imagebase_sub_imm32_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    // lea rax, [rsp + 0x40]                  48 8D 44 24 40
    // mov [rsp + 0x20], rax                  48 89 44 24 20
    //   arg5 slot (pointer to old_protect_var) — constant, set once.
    e.u8(0x48); e.u8(0x8D); e.u8(0x44); e.u8(0x24); e.u8(0x40);
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x20);

    // lea r14, [rip + reprotect_table_rel32]  4C 8D 35 rel32
    //   r14 = pointer to the embedded section table. The rel32 is
    //   patched in `execute()` once the stub's section RVA and the
    //   table's offset inside the stub are final. r14 is also
    //   nonvolatile so it survives the CALL.
    e.u8(0x4C); e.u8(0x8D); e.u8(0x35);
    patches.rel_to_reprotect_table_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    // mov r15d, <reprotect_entry_count>      41 BF imm32
    //   r15 = loop countdown. Nonvolatile, so the CALL won't stomp it.
    e.u8(0x41); e.u8(0xBF);
    e.u32(reprotect_entry_count);

    // --- Loop body ---

    const uint32_t loop_start = static_cast<uint32_t>(e.size());

    // test r15, r15                          4D 85 FF
    e.u8(0x4D); e.u8(0x85); e.u8(0xFF);
    // jz short .reprotect_done               74 rel8 (patched below)
    e.u8(0x74);
    const uint32_t patch_jz_loop_done = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // mov eax, [r14]                         41 8B 06
    //   rva (zero-extends to 64-bit in rax)
    e.u8(0x41); e.u8(0x8B); e.u8(0x06);
    // lea rax, [rbx + rax*1]                 48 8D 04 03
    //   rax = ImageBase + rva
    e.u8(0x48); e.u8(0x8D); e.u8(0x04); e.u8(0x03);
    // mov [rsp + 0x30], rax                  48 89 44 24 30
    //   store base_var
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x30);

    // mov eax, [r14 + 4]                     41 8B 46 04
    //   size (zero-extends)
    e.u8(0x41); e.u8(0x8B); e.u8(0x46); e.u8(0x04);
    // mov [rsp + 0x38], rax                  48 89 44 24 38
    //   store size_var
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x38);

    // Prepare call registers (volatile — re-set every iteration because
    // the previous CALL clobbered them):
    //   rcx = -1              (NtCurrentProcess pseudo-handle)
    //   rdx = &base_var       ([rsp + 0x30])
    //   r8  = &size_var       ([rsp + 0x38])
    //   r9d = PAGE_EXECUTE_READ (0x20)

    // mov rcx, -1                            48 C7 C1 FF FF FF FF
    e.u8(0x48); e.u8(0xC7); e.u8(0xC1);
    e.u32(0xFFFFFFFFu);
    // lea rdx, [rsp + 0x30]                  48 8D 54 24 30
    e.u8(0x48); e.u8(0x8D); e.u8(0x54); e.u8(0x24); e.u8(0x30);
    // lea r8, [rsp + 0x38]                   4C 8D 44 24 38
    e.u8(0x4C); e.u8(0x8D); e.u8(0x44); e.u8(0x24); e.u8(0x38);
    // mov r9d, 0x20                          41 B9 20 00 00 00
    e.u8(0x41); e.u8(0xB9);
    e.u32(0x00000020u);

    // call r13                               41 FF D5
    //   Invoke ntdll!NtProtectVirtualMemory. Going through the real
    //   stub means ntdll handles the Windows x64 ABI for the stack
    //   argument at [rsp+0x20] → [rsp+0x28] inside the stub, which
    //   a hand-rolled direct `syscall` from a 16-aligned rsp does
    //   not replicate correctly on Win11 with CET / shadow stack.
    e.u8(0x41); e.u8(0xFF); e.u8(0xD5);

    // add r14, 8                             49 83 C6 08
    e.u8(0x49); e.u8(0x83); e.u8(0xC6); e.u8(0x08);
    // dec r15                                49 FF CF
    e.u8(0x49); e.u8(0xFF); e.u8(0xCF);
    // jmp short .loop_start                  EB rel8
    e.u8(0xEB);
    {
        const uint32_t jmp_end = static_cast<uint32_t>(e.size()) + 1;
        const int32_t rel8 = static_cast<int32_t>(loop_start) -
                             static_cast<int32_t>(jmp_end);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    // .reprotect_done:
    {
        const uint32_t done_at = static_cast<uint32_t>(e.size());
        e.buf[patch_jz_reprotect_done] = static_cast<uint8_t>(
            static_cast<int8_t>(static_cast<int32_t>(done_at) -
                                static_cast<int32_t>(patch_jz_reprotect_done + 1)));
        e.buf[patch_jz_loop_done] = static_cast<uint8_t>(
            static_cast<int8_t>(static_cast<int32_t>(done_at) -
                                static_cast<int32_t>(patch_jz_loop_done + 1)));
    }

    // Restore rsp from r12.
    // mov rsp, r12                           4C 89 E4
    e.u8(0x4C); e.u8(0x89); e.u8(0xE4);
}

} // namespace mx::packer
