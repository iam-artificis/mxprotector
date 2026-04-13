/**
 * @file hells_gate_resolver.cpp
 * @brief [BUILDER] Byte-level emission of the runtime Hell's Gate resolver.
 *
 * See `hells_gate_resolver.hpp` for the rationale. This file is the
 * raw machine-code assembler: ~155 bytes of hand-encoded x64 that
 * walk the PEB, parse ntdll's PE exports, and extract a syscall
 * number into `r13d`.
 *
 * Every instruction is annotated with its byte layout and running
 * offset so the jump rel8 placeholders can be audited. The rel8
 * forward jumps are collected as patch offsets during emission
 * and filled in once the target offsets are known.
 */

#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

namespace mx::anti_tamper {

namespace {

/// Fill a 1-byte rel8 placeholder at `patch` so it branches to `target`.
/// `patch` is the offset of the rel8 byte itself; the branch is taken
/// from the byte AFTER `patch` (which is `patch + 1`).
inline void patch_rel8(RawEmitter& e, size_t patch, size_t target) noexcept {
    const int delta = static_cast<int>(target) - static_cast<int>(patch + 1);
    // rel8 must fit in int8_t; caller sized the resolver to keep all
    // jumps in range, so an out-of-range value here is a bug.
    e.buf[patch] = static_cast<uint8_t>(static_cast<int8_t>(delta));
}

/// Shared body emitter — `return_address` flips the final extract
/// between SSN (r13d = [rdi+4]) and function-address (r13 = rdi).
void emit_hells_gate_common(RawEmitter& e,
                            uint32_t target_name_hash,
                            bool return_address);

} // anonymous namespace

void emit_hells_gate_resolver(RawEmitter& e, uint32_t target_name_hash) {
    emit_hells_gate_common(e, target_name_hash, /*return_address=*/false);
}

void emit_hells_gate_address_resolver(RawEmitter& e, uint32_t target_name_hash) {
    emit_hells_gate_common(e, target_name_hash, /*return_address=*/true);
}

namespace {
void emit_hells_gate_common(RawEmitter& e,
                            uint32_t target_name_hash,
                            bool return_address)
{
    // ------------------------------------------------------------
    // Pre-scan setup: locate ntdll (2nd module in Ldr list) and
    // cache pointers to its export name/ordinal/function tables.
    // ------------------------------------------------------------

    // mov rax, gs:[0x60]                 65 48 8B 04 25 60 00 00 00   (9)
    //   Read the PEB pointer. GS segment points at the TEB; at
    //   offset 0x60 of the TEB sits TEB.ProcessEnvironmentBlock.
    e.u8(0x65); e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0x25);
    e.u8(0x60); e.u8(0x00); e.u8(0x00); e.u8(0x00);

    // mov rax, [rax + 0x18]              48 8B 40 18                  (4)
    //   PEB.Ldr — pointer to PEB_LDR_DATA.
    e.u8(0x48); e.u8(0x8B); e.u8(0x40); e.u8(0x18);

    // lea rcx, [rax + 0x20]              48 8D 48 20                  (4)
    //   &PEB_LDR_DATA.InMemoryOrderModuleList — head of the list.
    e.u8(0x48); e.u8(0x8D); e.u8(0x48); e.u8(0x20);

    // mov rax, [rcx]                     48 8B 01                     (3)
    //   rax = head.Flink → first entry's InMemoryOrderLinks (exe).
    e.u8(0x48); e.u8(0x8B); e.u8(0x01);

    // mov rax, [rax]                     48 8B 00                     (3)
    //   rax = first.Flink → second entry's InMemoryOrderLinks (ntdll).
    //   We exploit the "exe, then ntdll" loader order — true on every
    //   mainstream Windows since XP.
    e.u8(0x48); e.u8(0x8B); e.u8(0x00);

    // mov rbx, [rax + 0x20]              48 8B 58 20                  (4)
    //   Entry start is at (rax - 0x10); DllBase lives at offset 0x30
    //   in the entry, so at (rax - 0x10 + 0x30) = rax + 0x20.
    e.u8(0x48); e.u8(0x8B); e.u8(0x58); e.u8(0x20);

    // ------------------------------------------------------------
    // Parse ntdll PE headers → export directory
    // ------------------------------------------------------------

    // mov eax, [rbx + 0x3C]              8B 43 3C                     (3)
    //   e_lfanew — offset of NT headers inside the DOS header.
    e.u8(0x8B); e.u8(0x43); e.u8(0x3C);

    // mov ecx, [rbx + rax*1 + 0x88]      8B 8C 03 88 00 00 00         (7)
    //   DataDirectory[0].VirtualAddress = Export RVA.
    //   NT headers at (rbx + eax), OptionalHeader starts at +0x18,
    //   DataDirectory[0] at +0x70 into the OptionalHeader → total
    //   +0x88 from NT headers start.
    e.u8(0x8B); e.u8(0x8C); e.u8(0x03);
    e.u8(0x88); e.u8(0x00); e.u8(0x00); e.u8(0x00);

    // lea rdi, [rbx + rcx*1]             48 8D 3C 0B                  (4)
    //   rdi = export directory base = DllBase + ExportRVA.
    e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x0B);

    // mov ecx, [rdi + 0x18]              8B 4F 18                     (3)
    //   NumberOfNames.
    e.u8(0x8B); e.u8(0x4F); e.u8(0x18);

    // mov eax, [rdi + 0x20]              8B 47 20                     (3)
    //   AddressOfNames RVA.
    e.u8(0x8B); e.u8(0x47); e.u8(0x20);
    // lea r8, [rbx + rax*1]              4C 8D 04 03                  (4)
    //   r8 = names table pointer.
    e.u8(0x4C); e.u8(0x8D); e.u8(0x04); e.u8(0x03);

    // mov eax, [rdi + 0x24]              8B 47 24                     (3)
    //   AddressOfNameOrdinals RVA.
    e.u8(0x8B); e.u8(0x47); e.u8(0x24);
    // lea r9, [rbx + rax*1]              4C 8D 0C 03                  (4)
    e.u8(0x4C); e.u8(0x8D); e.u8(0x0C); e.u8(0x03);

    // mov eax, [rdi + 0x1C]              8B 47 1C                     (3)
    //   AddressOfFunctions RVA.
    e.u8(0x8B); e.u8(0x47); e.u8(0x1C);
    // lea r10, [rbx + rax*1]             4C 8D 14 03                  (4)
    e.u8(0x4C); e.u8(0x8D); e.u8(0x14); e.u8(0x03);

    // ------------------------------------------------------------
    // Scan loop: for i in [0, num_names): hash name[i], compare
    // with target_name_hash, on match extract SSN.
    // ------------------------------------------------------------

    // xor r11d, r11d                     45 31 DB                     (3)
    //   i = 0
    e.u8(0x45); e.u8(0x31); e.u8(0xDB);

    // xor r13d, r13d                     45 31 ED                     (3)
    //   Default result = 0 (= "not found / failure").
    e.u8(0x45); e.u8(0x31); e.u8(0xED);

    // --- .scan: ---
    const size_t label_scan = e.size();

    // cmp r11d, ecx                      41 39 CB                     (3)
    //   i vs num_names. REX.B extends rm to r11.
    e.u8(0x41); e.u8(0x39); e.u8(0xCB);
    // jae short .done                    73 rel8                      (2)
    //   Iterated all names without a match — fall through with
    //   r13 = 0.
    e.u8(0x73);
    const size_t patch_jae_done = e.size();
    e.u8(0x00);

    // mov eax, [r8 + r11*4]              43 8B 04 98                  (4)
    //   name_rva = names[i]. REX.RB extends base and index.
    //   SIB: scale=10(×4) index=011(r11&7) base=000(r8&7) = 10 011 000
    e.u8(0x43); e.u8(0x8B); e.u8(0x04); e.u8(0x98);

    // lea rdx, [rbx + rax*1]             48 8D 14 03                  (4)
    //   rdx = name = DllBase + name_rva.
    e.u8(0x48); e.u8(0x8D); e.u8(0x14); e.u8(0x03);

    // mov eax, 5381                      B8 05 15 00 00               (5)
    //   Initialise DJB2 hash accumulator.
    e.u8(0xB8);
    e.u8(0x05); e.u8(0x15); e.u8(0x00); e.u8(0x00);

    // --- .hash_loop: ---
    const size_t label_hash_loop = e.size();

    // movzx r14d, byte [rdx]             44 0F B6 32                  (4)
    //   Load next byte of the name, zero-extend.
    e.u8(0x44); e.u8(0x0F); e.u8(0xB6); e.u8(0x32);

    // test r14b, r14b                    45 84 F6                     (3)
    //   End of name? r14 uses REX; r14b needs REX prefix.
    e.u8(0x45); e.u8(0x84); e.u8(0xF6);
    // jz short .hash_done                74 rel8                      (2)
    e.u8(0x74);
    const size_t patch_jz_hash_done = e.size();
    e.u8(0x00);

    // mov r15d, eax                      41 89 C7                     (3)
    //   h_copy = h (for the h*33 = h*32 + h trick).
    e.u8(0x41); e.u8(0x89); e.u8(0xC7);

    // shl eax, 5                         C1 E0 05                     (3)
    //   h *= 32
    e.u8(0xC1); e.u8(0xE0); e.u8(0x05);

    // add eax, r15d                      44 01 F8                     (3)
    //   h += h_copy → h *= 33
    e.u8(0x44); e.u8(0x01); e.u8(0xF8);

    // add eax, r14d                      44 01 F0                     (3)
    //   h += c (current byte, zero-extended)
    e.u8(0x44); e.u8(0x01); e.u8(0xF0);

    // inc rdx                            48 FF C2                     (3)
    //   Advance to next byte.
    e.u8(0x48); e.u8(0xFF); e.u8(0xC2);

    // jmp short .hash_loop               EB rel8                      (2)
    e.u8(0xEB);
    {
        const size_t patch = e.size();
        e.u8(0x00);
        patch_rel8(e, patch, label_hash_loop);
    }

    // --- .hash_done: ---
    const size_t label_hash_done = e.size();
    patch_rel8(e, patch_jz_hash_done, label_hash_done);

    // cmp eax, <target_name_hash>        3D imm32                     (5)
    e.u8(0x3D);
    e.u32(target_name_hash);

    // jne short .next                    75 rel8                      (2)
    e.u8(0x75);
    const size_t patch_jne_next = e.size();
    e.u8(0x00);

    // --- Match: extract SSN ---

    // movzx eax, word [r9 + r11*2]       43 0F B7 04 59               (5)
    //   ordinal = ordinals[i]. SIB: scale=01 idx=011(r11&7) base=001(r9&7)
    e.u8(0x43); e.u8(0x0F); e.u8(0xB7); e.u8(0x04); e.u8(0x59);

    // mov eax, [r10 + rax*4]             41 8B 04 82                  (4)
    //   func_rva = functions[ordinal]. SIB: scale=10 idx=000(rax) base=010(r10&7)
    e.u8(0x41); e.u8(0x8B); e.u8(0x04); e.u8(0x82);

    // lea rdi, [rbx + rax*1]             48 8D 3C 03                  (4)
    //   rdi = function body start.
    e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x03);

    // cmp dword [rdi], 0xB8D18B4C        81 3F 4C 8B D1 B8            (6)
    //   Validate unhooked prologue: `mov r10, rcx; mov eax, ...`.
    //   Little-endian, so 4C 8B D1 B8 becomes the imm32 literal.
    e.u8(0x81); e.u8(0x3F);
    e.u8(0x4C); e.u8(0x8B); e.u8(0xD1); e.u8(0xB8);

    // jne short .done                    75 rel8                      (2)
    //   Hooked or non-syscall export → bail with r13 = 0.
    e.u8(0x75);
    const size_t patch_jne_done = e.size();
    e.u8(0x00);

    if (return_address) {
        // mov r13, rdi                    49 89 FD                     (3)
        //   Return the full 64-bit function body address.
        e.u8(0x49); e.u8(0x89); e.u8(0xFD);
    } else {
        // mov r13d, [rdi + 4]             44 8B 6F 04                  (4)
        //   SSN is the imm32 right after the 4-byte prologue.
        e.u8(0x44); e.u8(0x8B); e.u8(0x6F); e.u8(0x04);
    }

    // jmp short .done                    EB rel8                      (2)
    e.u8(0xEB);
    const size_t patch_jmp_done = e.size();
    e.u8(0x00);

    // --- .next: ---
    const size_t label_next = e.size();
    patch_rel8(e, patch_jne_next, label_next);

    // inc r11                            49 FF C3                     (3)
    e.u8(0x49); e.u8(0xFF); e.u8(0xC3);

    // jmp short .scan                    EB rel8                      (2)
    e.u8(0xEB);
    {
        const size_t patch = e.size();
        e.u8(0x00);
        patch_rel8(e, patch, label_scan);
    }

    // --- .done: ---
    const size_t label_done = e.size();
    patch_rel8(e, patch_jae_done, label_done);
    patch_rel8(e, patch_jne_done, label_done);
    patch_rel8(e, patch_jmp_done, label_done);
}

} // anonymous namespace (emit_hells_gate_common)

} // namespace mx::anti_tamper
