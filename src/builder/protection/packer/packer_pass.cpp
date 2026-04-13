/**
 * @file packer_pass.cpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector implementation.
 *
 * Strategy:
 *   1. Strip base relocations (set IMAGE_FILE_RELOCS_STRIPPED, clear DYNAMIC_BASE,
 *      clear the IMAGE_DIRECTORY_ENTRY_BASERELOC directory). The loader will
 *      load at the preferred ImageBase without applying any fixups, so the
 *      encrypted bytes survive loader → stub unchanged.
 *   2. Generate a per-build random 256-byte XOR key.
 *   3. Encrypt .text in place: enc[i] = plain[i] ^ key[i % 256]. Mark .text
 *      writable so the stub can decrypt in place.
 *   4. Emit an x64 decryption stub into a new .mxpack section. The stub:
 *        - uses RIP-relative LEAs to locate .text and the embedded key,
 *        - masks the byte index against 0xFF so a single-byte counter drives
 *          the key stream,
 *        - jmps to the original entry point via rel32.
 *   5. Retarget the PE entry point to the stub.
 *
 * Limitations (MVP):
 *   - Only .text is encrypted.
 *   - .reloc is stripped — binaries must be loadable at ImageBase.
 *   - Stub does not restore the .text page protection after decrypting.
 */

#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <variant>

namespace mx {

namespace {

/// 256-byte XOR key stream. The stub counts bytes with `inc dl` so the key
/// wraps automatically at 256.
constexpr uint32_t kKeySize = 256;

/// Approximate size of the stub code (before the key). The actual size varies
/// a little across builds because the push/pop and setup order is randomised,
/// but the patch offsets are tracked dynamically so this is only a sanity
/// reference for documentation.
///
/// Layout (all sizes in bytes):
///   push rdi/rsi/rcx/rdx/rax          = 5
///   mov  rax, gs:[0x60]                = 9    — read PEB
///   movzx eax, byte [rax+2]            = 4    — BeingDebugged (0 or 1)
///   mov  edx, eax                       = 2    — edx = 0 normally, 1 under a dbg
///   lea  rdi, [rip + rel32]             = 7
///   lea  rsi, [rip + rel32]             = 7
///   mov  ecx, imm32                     = 5
///   .loop:
///     mov  al, [rdi]                    = 2
///     xor  al, [rsi + rdx]              = 3
///     mov  [rdi], al                    = 2
///     inc  rdi                          = 3
///     inc  dl                           = 2
///     dec  rcx                          = 3
///     jnz  .loop                        = 2
///   pop  rax/rdx/rcx/rsi/rdi            = 5
///   jmp  rel32                          = 5
///   -------------------------------------
///   total                               = 66
///
/// The anti-debug is woven *into* the decryption: if the process is being
/// debugged, edx starts at 1 instead of 0 and the entire key stream is
/// shifted by one byte, producing garbage on the first instruction executed.
/// A reverser cannot simply NOP the check — they must also un-shift the
/// byte counter, which would require detecting that the shift is present.
constexpr uint32_t kStubCodeSize = 66;

/// A single section the packer stub decrypts at runtime.
///
/// For each target section, the stub receives a (rva, size) pair and runs
/// a standalone XOR loop over that range. The key pointer (`rsi`) is set
/// once before the first loop; the key index (`dl`) wraps at 256 and is
/// simply carried from one section to the next, so each section uses a
/// unique slice of the key stream — good enough against known-plaintext
/// since one section won't reveal another's offset without guessing the
/// dl value at the section boundary.
struct DecryptSection {
    Rva      rva;            ///< RVA of the section to decrypt
    uint32_t size;           ///< Size in bytes
    uint32_t patch_lea_at;   ///< Stub-relative offset of the rel32 inside `lea rdi, [rip+rel]`
    uint32_t patch_size_at;  ///< Stub-relative offset of the `mov ecx, imm32` immediate
};

struct StubPatches {
    // Per-section patch sites (see DecryptSection above). Populated in
    // stub-emission order; the caller patches each one to its section RVA
    // and byte count.
    std::vector<DecryptSection> sections;

    uint32_t rel_to_key_at;        ///< patch offset (rel32 from end-of-lea to embedded key)
    uint32_t rel_to_oep_at;        ///< patch offset (rel32 from end-of-jmp to OEP + stolen_size)
    uint32_t stolen_bytes_offset;  ///< offset of the first byte of the embedded stolen payload
    uint32_t rel_to_impdir_at;     ///< patch offset (rel32 from end-of-lea to Import Directory)
    uint32_t impdir_size_at;       ///< patch offset of the import dir size imm32

    // --- Reprotect block patches ---
    // The reprotect block emits a Hell's Gate resolver + loop over an
    // embedded section table so the stub can revoke WRITE from every
    // decrypted section via `NtProtectVirtualMemory`. The table contains
    // `reprotect_entry_count` entries of {rva: u32, size: u32} and the
    // caller fills it with the actual RVAs/sizes right after stub assembly.
    //
    // `rel_to_reprotect_table_at` is the rel32 offset inside the
    // `lea r14, [rip + table]` that points at the table. Filled in by
    // the caller once the stub's section RVA is known.
    uint32_t rel_to_reprotect_table_at;
    uint32_t reprotect_table_offset;
    uint32_t reprotect_entry_count;
};

/// Minimum number of bytes we want to steal from the OEP. We walk whole
/// instructions so the actual stolen size may be larger.
constexpr uint32_t kMinStolenBytes = 10;
/// Upper bound on stolen bytes — prevents extracting so much code that the
/// stub grows unreasonably or the check for safe instructions becomes fragile.
constexpr uint32_t kMaxStolenBytes = 64;

/// One rel32 fix-up inside the stolen-bytes payload: the rel32 target was
/// originally `original_target_rva`; after the bytes move into the stub the
/// rel32 at `offset_in_stolen` (4 bytes) must be rewritten to keep pointing
/// at that RVA. Currently only CALL rel32 patches are produced.
struct StolenReloc {
    uint32_t offset_in_stolen;    ///< offset of rel32 within stolen_bytes
    uint32_t instr_end_in_stolen; ///< byte just after the full instruction
    Rva      original_target_rva; ///< absolute target RVA (stays constant)
};

struct StolenPlan {
    uint32_t                 size = 0;
    std::vector<StolenReloc> relocs;
};

/// Scan OEP for instructions that can be safely lifted into the stub.
/// Allows:
///   - plain GPR/ALU instructions
///   - CALL rel32 (will be rewritten after move)
/// Rejects:
///   - JMP/JCC (stubs don't loop — a taken branch would escape unresolved)
///   - RET (ends the OEP sequence)
///   - RIP-relative memory operands (cannot be fixed up generically)
[[nodiscard]] StolenPlan plan_stolen_bytes(ByteView text_bytes,
                                           uint32_t oep_offset_in_text,
                                           Rva oep_rva)
{
    StolenPlan result;
    if (oep_offset_in_text >= text_bytes.size()) return result;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    size_t pos = oep_offset_in_text;
    while (result.size < kMinStolenBytes) {
        if (pos >= text_bytes.size()) { result.size = 0; result.relocs.clear(); return result; }
        const size_t remain = text_bytes.size() - pos;

        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, text_bytes.data() + pos, remain, &insn, operands))) {
            return {};
        }

        // Reject branches/ret outright — they leave the stolen sequence.
        if (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_RET) {
            return {};
        }

        // RIP-relative memory references break when we move the bytes.
        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const auto& op = operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                op.mem.base == ZYDIS_REGISTER_RIP) {
                return {};
            }
        }

        // CALL rel32 — record a fix-up so the absolute target survives.
        if (insn.meta.category == ZYDIS_CATEGORY_CALL) {
            // Only the rel32 form (E8 rel32) is supported here. Indirect calls
            // (FF /2) would need a different encoding change.
            if (insn.length != 5 || text_bytes[pos] != 0xE8) return {};

            int32_t rel32 = 0;
            std::memcpy(&rel32, text_bytes.data() + pos + 1, 4);
            const Rva target_rva = static_cast<Rva>(
                static_cast<int64_t>(oep_rva) +
                static_cast<int64_t>(pos - oep_offset_in_text) +
                5 + rel32);

            StolenReloc r{};
            r.offset_in_stolen    = result.size + 1;
            r.instr_end_in_stolen = result.size + 5;
            r.original_target_rva = target_rva;
            result.relocs.push_back(r);
        }

        pos += insn.length;
        result.size += insn.length;
        if (result.size > kMaxStolenBytes) return {};
    }
    return result;
}

/// Build the stub code bytes (without patching rel32s yet) and report where
/// the placeholders need to be filled in. The stub protects N sections:
///
///   1. Save 5 registers (randomised push order).
///   2. Anti-debug: read PEB.BeingDebugged into dl (key-stream index). In a
///      non-debugged process this is 0; under a debugger it becomes 1, so
///      every byte of every decrypt loop is XOR'd with the wrong key byte
///      and the decrypted program is silently garbage — no explicit branch
///      that the reverser can NOP out.
///   3. Load the 256-byte key pointer into rsi (shared across all sections).
///   4. For each section to protect, emit:
///        lea rdi, [rip + section_rel32]
///        mov ecx, section_size
///       .loop:
///          mov al, [rdi]
///          xor al, [rsi + rdx*1]
///          mov [rdi], al
///          inc rdi
///          inc dl            ; key index wraps at 256
///          dec ecx
///          jnz .loop
///      The `dl` counter is carried across sections so each one uses a
///      different slice of the key stream — one section's recovered key
///      doesn't trivially reveal another's offset.
///   5. IAT destruction: zero the Import Directory region so dumped binaries
///      lose their resolved import table.
///   6. Restore registers (mirror of the push order).
///   7. Execute the stolen OEP bytes inline.
///   8. jmp rel32 → OEP + stolen_size.
[[nodiscard]] std::pair<ByteBuffer, StubPatches> build_stub_bytes(
    Randomizer& rng,
    ByteView stolen_bytes,
    uint32_t section_count)
{
    ByteBuffer buf;
    buf.reserve(128 + 32 * section_count + stolen_bytes.size() + kKeySize);

    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };

    // (1) Randomised push/pop register order. Same permutation used for
    //     pushes (top-down) and pops (reversed) so the stack is balanced.
    std::array<uint8_t, 5> save_order{0x50 /*rax*/, 0x51 /*rcx*/, 0x52 /*rdx*/,
                                       0x56 /*rsi*/, 0x57 /*rdi*/};
    std::shuffle(save_order.begin(), save_order.end(), rng.engine());
    for (uint8_t op : save_order) u8(op);

    StubPatches patches{};
    patches.sections.reserve(section_count);

    // (2) Anti-debug — polymorphic. Each variant reads a different Windows
    //     "debugger present" indicator and normalizes the result to `edx`
    //     ∈ {0, 1}. The downstream decrypt loop uses `edx` as the key-stream
    //     start index, so a non-zero value silently garbles the entire
    //     decrypted output. No explicit jump to patch: the check is baked
    //     into the cipher.
    //
    // All variants leave edx ∈ {0, 1} and clobber rax. Callers that need
    // a preserved rax must restore it after the stub.
    //
    // Variant 0: PEB.BeingDebugged (byte at PEB+0x02) — classic.
    //    mov rax, gs:[0x60]         ; PEB
    //    movzx eax, byte [rax+2]    ; 0 or 1
    //    mov edx, eax
    //
    // Variant 1: PEB.NtGlobalFlag (dword at PEB+0xBC). Under a debugger the
    //    loader sets FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK
    //    | FLG_HEAP_VALIDATE_PARAMETERS (mask 0x70). We reduce to {0, 1}
    //    via `(val & 0x70) ? 1 : 0`.
    //    mov rax, gs:[0x60]              ; PEB
    //    mov eax, [rax + 0xBC]           ; NtGlobalFlag
    //    and eax, 0x70                   ; mask heap flags
    //    xor edx, edx
    //    test eax, eax
    //    setnz dl                         ; edx = (masked != 0)
    //
    // Variant 2: KUSER_SHARED_DATA.KdDebuggerEnabled at 0x7FFE02D4.
    //    User-mode readable page mapped at fixed VA 0x7FFE0000. Byte at
    //    +0x2D4 has bit 0x01 set when a kernel debugger is present AND
    //    attached. bit 0x02 set when user-mode code runs under a debugger
    //    in many Windows versions, but less reliable — we use bit 0x01
    //    OR bit 0x02 for broader coverage.
    //    mov rax, 0x7FFE02D4
    //    movzx eax, byte [rax]
    //    and eax, 0x03
    //    xor edx, edx
    //    test eax, eax
    //    setnz dl
    const uint32_t adv = rng.next_range(0, 2);
    switch (adv) {
        case 0: {
            // PEB.BeingDebugged
            u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
            u8(0x60); u8(0x00); u8(0x00); u8(0x00);     // mov rax, gs:[0x60]
            u8(0x0F); u8(0xB6); u8(0x40); u8(0x02);     // movzx eax, byte [rax+2]
            u8(0x89); u8(0xC2);                          // mov edx, eax
            break;
        }
        case 1: {
            // PEB.NtGlobalFlag
            u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
            u8(0x60); u8(0x00); u8(0x00); u8(0x00);     // mov rax, gs:[0x60]
            u8(0x8B); u8(0x80); u8(0xBC); u8(0x00); u8(0x00); u8(0x00);
                                                          // mov eax, [rax + 0xBC]
            u8(0x83); u8(0xE0); u8(0x70);                // and eax, 0x70
            u8(0x31); u8(0xD2);                          // xor edx, edx
            u8(0x85); u8(0xC0);                          // test eax, eax
            u8(0x0F); u8(0x95); u8(0xC2);                // setnz dl
            break;
        }
        default: {
            // KUSER_SHARED_DATA.KdDebuggerEnabled at 0x7FFE02D4.
            // `mov rax, imm64` is 10 bytes; we need the full 64-bit addr.
            u8(0x48); u8(0xB8);                          // mov rax, imm64
            u8(0xD4); u8(0x02); u8(0xFE); u8(0x7F);
            u8(0x00); u8(0x00); u8(0x00); u8(0x00);      // 0x7FFE02D4
            u8(0x0F); u8(0xB6); u8(0x00);                // movzx eax, byte [rax]
            u8(0x83); u8(0xE0); u8(0x03);                // and eax, 0x03
            u8(0x31); u8(0xD2);                          // xor edx, edx
            u8(0x85); u8(0xC0);                          // test eax, eax
            u8(0x0F); u8(0x95); u8(0xC2);                // setnz dl
            break;
        }
    }

    // (3) lea rsi, [rip + key_rel32]   — load key pointer, shared by all loops.
    u8(0x48); u8(0x8D); u8(0x35);
    patches.rel_to_key_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // (4) Per-section decrypt loop. dl (key index) is carried across
    //     iterations. Two equivalent loop shapes are picked per-build:
    //
    //     V0 "load-xor-store":
    //         mov al, [rdi]            8A 07
    //         xor al, [rsi + rdx*1]    32 04 16
    //         mov [rdi], al            88 07
    //         inc rdi                  48 FF C7
    //         inc dl                   FE C2
    //         dec ecx                  FF C9
    //         jnz .loop                75 rel8
    //
    //     V1 "memory-xor":
    //         mov al, [rsi + rdx*1]    8A 04 16
    //         xor [rdi], al            30 07
    //         inc rdi                  48 FF C7
    //         inc dl                   FE C2
    //         dec ecx                  FF C9
    //         jnz .loop                75 rel8
    //
    //     The same variant is used for every section in a single build so
    //     the stream cipher stays consistent; sections are laid out back
    //     to back with the dl index carrying through.
    const uint32_t loop_variant = rng.next_range(0, 1);
    for (uint32_t s = 0; s < section_count; ++s) {
        DecryptSection ds{};

        //   lea rdi, [rip + section_rel32]    48 8D 3D rel32
        u8(0x48); u8(0x8D); u8(0x3D);
        ds.patch_lea_at = static_cast<uint32_t>(buf.size());
        u32(0);

        //   mov ecx, imm32                    B9 imm32
        u8(0xB9);
        ds.patch_size_at = static_cast<uint32_t>(buf.size());
        u32(0);

        patches.sections.push_back(ds);

        const uint32_t loop_body_start = static_cast<uint32_t>(buf.size());

        if (loop_variant == 0) {
            //   mov al, [rdi]           8A 07
            u8(0x8A); u8(0x07);
            //   xor al, [rsi + rdx*1]   32 04 16
            u8(0x32); u8(0x04); u8(0x16);
            //   mov [rdi], al           88 07
            u8(0x88); u8(0x07);
        } else {
            //   mov al, [rsi + rdx*1]   8A 04 16
            u8(0x8A); u8(0x04); u8(0x16);
            //   xor [rdi], al           30 07
            u8(0x30); u8(0x07);
        }
        //   inc rdi                 48 FF C7
        u8(0x48); u8(0xFF); u8(0xC7);
        //   inc dl                  FE C2
        u8(0xFE); u8(0xC2);
        //   dec ecx                 FF C9   (32-bit form)
        u8(0xFF); u8(0xC9);
        //   jnz .loop (rel8)
        const uint32_t jnz_end = static_cast<uint32_t>(buf.size()) + 2;
        const int32_t  rel8    = static_cast<int32_t>(loop_body_start) -
                                 static_cast<int32_t>(jnz_end);
        u8(0x75); u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    // (4.5) Reprotect decrypted sections to PAGE_EXECUTE_READ.
    //
    // The decrypt loop above wrote through each section, which means
    // those sections had IMAGE_SCN_MEM_WRITE in the loader's eyes and
    // were mapped PAGE_EXECUTE_READWRITE. Leaving them RWX at runtime
    // is a security hazard — it means (a) a reverser's in-memory
    // patch doesn't need to call VirtualProtect first (no detection
    // opportunity), and (b) the anti-tamper `page_protection_sweep`
    // check can't meaningfully probe our own VM blob section because
    // a legitimate state of RWX is indistinguishable from a tampered
    // one. Both problems disappear if we revoke WRITE after the
    // decrypt loop finishes.
    //
    // The reprotect block does:
    //
    //   1. Save rsp to r12 and allocate a 16-byte-aligned 0x50-byte
    //      scratch frame for the syscall args and output buffer.
    //
    //   2. Emit the Hell's Gate SSN resolver targeting
    //      `NtProtectVirtualMemory`. It walks
    //      `PEB.Ldr.InMemoryOrderModuleList` → ntdll (2nd entry) →
    //      PE export table → DJB2 scan → prologue validation → SSN
    //      into r13d. ~155 bytes of emitted code.
    //
    //   3. Skip the reprotect loop entirely if r13 came back 0
    //      (resolver failure). The decrypted sections stay RWX,
    //      which is the pre-fix state — safe, just not hardened.
    //
    //   4. Load one-time constants that survive across syscalls:
    //      rbx = PEB.ImageBase, rdx = &base_var, r8 = &size_var,
    //      r9d = PAGE_EXECUTE_READ, [rsp+0x28] = &old_protect_var,
    //      r14 = section table pointer, r15 = N section count.
    //
    //   5. Loop over each {rva, size} entry in the table:
    //        compute base = ImageBase + rva
    //        write base into base_var
    //        write size into size_var
    //        mov rcx, -1 (NtCurrentProcess)
    //        mov r10, rcx (syscall ABI)
    //        mov eax, r13d (SSN)
    //        syscall
    //
    //   6. Restore rsp from r12.
    //
    // All clobbered registers (rax, rbx, rcx, rdx, rdi, rsi, r8–r15)
    // are either already dirty from the decrypt loop, or are loader-
    // initialised values that the original OEP code doesn't depend
    // on. r12 is new state we introduce specifically for the rsp
    // save, and we restore it before returning control.

    const uint32_t reprotect_entry_count = section_count;
    patches.reprotect_entry_count = reprotect_entry_count;

    // mov r12, rsp                           49 89 E4
    u8(0x49); u8(0x89); u8(0xE4);

    // sub rsp, 0x50                          48 81 EC 50 00 00 00
    u8(0x48); u8(0x81); u8(0xEC);
    u32(0x00000050u);

    // and rsp, -16                           48 83 E4 F0
    u8(0x48); u8(0x83); u8(0xE4); u8(0xF0);

    // Hell's Gate SSN resolver → r13d = NtProtectVirtualMemory SSN.
    // The target hash is computed at build time; the literal ASCII
    // name never appears in the stub.
    {
        mx::RawEmitter tmp{};
        constexpr uint32_t kNtProtectHash =
            anti_tamper::djb2_ascii_hash("NtProtectVirtualMemory");
        anti_tamper::emit_hells_gate_resolver(tmp, kNtProtectHash);
        for (uint8_t b : tmp.buf) u8(b);
    }

    // test r13, r13                          4D 85 ED
    u8(0x4D); u8(0x85); u8(0xED);
    // jz short .reprotect_done               74 rel8 (patched below)
    u8(0x74);
    const uint32_t patch_jz_reprotect_done = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // --- One-time setup: pointers, constants, ImageBase cache ---

    // mov rax, gs:[0x60]                     65 48 8B 04 25 60 00 00 00
    u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
    u8(0x60); u8(0x00); u8(0x00); u8(0x00);
    // mov rbx, [rax + 0x10]                  48 8B 58 10
    //   rbx = PEB.ImageBase — preserved across syscall, reused by loop.
    u8(0x48); u8(0x8B); u8(0x58); u8(0x10);

    // lea rdx, [rsp + 0x20]                  48 8D 54 24 20
    //   arg2: &base_var — same slot every iteration.
    u8(0x48); u8(0x8D); u8(0x54); u8(0x24); u8(0x20);

    // lea r8, [rsp + 0x30]                   4C 8D 44 24 30
    //   arg3: &size_var
    u8(0x4C); u8(0x8D); u8(0x44); u8(0x24); u8(0x30);

    // mov r9d, 0x20                          41 B9 20 00 00 00
    //   arg4: PAGE_EXECUTE_READ
    u8(0x41); u8(0xB9);
    u32(0x00000020u);

    // lea rax, [rsp + 0x38]                  48 8D 44 24 38
    // mov [rsp + 0x28], rax                  48 89 44 24 28
    //   arg5: &old_protect_var (stored at [rsp+0x28], kernel reads it
    //   from there as the 5th syscall arg).
    u8(0x48); u8(0x8D); u8(0x44); u8(0x24); u8(0x38);
    u8(0x48); u8(0x89); u8(0x44); u8(0x24); u8(0x28);

    // lea r14, [rip + reprotect_table_rel32]  4C 8D 35 rel32
    //   r14 = pointer to the embedded section table. The rel32 is
    //   patched at the end of build_stub_bytes once the table's
    //   position in the stub is known.
    u8(0x4C); u8(0x8D); u8(0x35);
    patches.rel_to_reprotect_table_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // mov r15d, <reprotect_entry_count>      41 BF imm32
    u8(0x41); u8(0xBF);
    u32(reprotect_entry_count);

    // --- Loop body ---

    const uint32_t loop_start = static_cast<uint32_t>(buf.size());

    // test r15, r15                          4D 85 FF
    u8(0x4D); u8(0x85); u8(0xFF);
    // jz short .reprotect_done               74 rel8 (patched below)
    u8(0x74);
    const uint32_t patch_jz_loop_done = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // mov eax, [r14]                         41 8B 06
    //   rva (zero-extends to 64-bit in rax)
    u8(0x41); u8(0x8B); u8(0x06);
    // lea rax, [rbx + rax*1]                 48 8D 04 03
    //   rax = ImageBase + rva
    u8(0x48); u8(0x8D); u8(0x04); u8(0x03);
    // mov [rsp + 0x20], rax                  48 89 44 24 20
    u8(0x48); u8(0x89); u8(0x44); u8(0x24); u8(0x20);

    // mov eax, [r14 + 4]                     41 8B 46 04
    //   size (zero-extends)
    u8(0x41); u8(0x8B); u8(0x46); u8(0x04);
    // mov [rsp + 0x30], rax                  48 89 44 24 30
    u8(0x48); u8(0x89); u8(0x44); u8(0x24); u8(0x30);

    // mov rcx, -1                            48 C7 C1 FF FF FF FF
    //   arg1: NtCurrentProcess pseudo-handle (re-set each iteration
    //   because syscall clobbered rcx with the saved RIP).
    u8(0x48); u8(0xC7); u8(0xC1);
    u32(0xFFFFFFFFu);
    // mov r10, rcx                           49 89 CA
    u8(0x49); u8(0x89); u8(0xCA);
    // mov eax, r13d                          44 89 E8
    u8(0x44); u8(0x89); u8(0xE8);
    // syscall                                0F 05
    u8(0x0F); u8(0x05);

    // add r14, 8                             49 83 C6 08
    u8(0x49); u8(0x83); u8(0xC6); u8(0x08);
    // dec r15                                49 FF CF
    u8(0x49); u8(0xFF); u8(0xCF);
    // jmp short .loop_start                  EB rel8
    u8(0xEB);
    {
        const uint32_t jmp_end = static_cast<uint32_t>(buf.size()) + 1;
        const int32_t rel8 = static_cast<int32_t>(loop_start) -
                             static_cast<int32_t>(jmp_end);
        u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    // .reprotect_done:
    {
        const uint32_t done_at = static_cast<uint32_t>(buf.size());
        // Patch the two forward rel8 jumps that both target this
        // label: the "resolver failed" bail and the "loop counter
        // reached 0" exit.
        buf[patch_jz_reprotect_done] = static_cast<uint8_t>(
            static_cast<int8_t>(static_cast<int32_t>(done_at) -
                                static_cast<int32_t>(patch_jz_reprotect_done + 1)));
        buf[patch_jz_loop_done] = static_cast<uint8_t>(
            static_cast<int8_t>(static_cast<int32_t>(done_at) -
                                static_cast<int32_t>(patch_jz_loop_done + 1)));
    }

    // Restore rsp from r12.
    // mov rsp, r12                           4C 89 E4
    u8(0x4C); u8(0x89); u8(0xE4);

    // (5) IAT destruction: zero the Import Directory region in memory.
    // After decryption, the loader has already resolved all imports into the
    // IAT. Zeroing the Import Directory + ILT makes the resolved addresses
    // un-labelable by dump/reconstruction tools (Scylla, IDA imports tab).
    //
    //   lea rdi, [rip + import_dir_rel32]
    //   xor eax, eax
    //   mov ecx, import_dir_size / 4
    //   rep stosd
    u8(0x48); u8(0x8D); u8(0x3D);            // lea rdi, [rip + rel32]
    patches.rel_to_impdir_at = static_cast<uint32_t>(buf.size());
    u32(0);                                   // placeholder rel32
    u8(0x31); u8(0xC0);                       // xor eax, eax
    u8(0xB9);                                  // mov ecx, imm32
    patches.impdir_size_at = static_cast<uint32_t>(buf.size());
    u32(0);                                   // placeholder size/4
    u8(0xF3); u8(0xAB);                       // rep stosd

    // (6) Restore registers in reverse of the saved order (LIFO).
    for (auto it = save_order.rbegin(); it != save_order.rend(); ++it) {
        u8(static_cast<uint8_t>(*it + 0x08));
    }

    // (7) Stolen OEP bytes run inline — rsp is now back to what the OEP
    //     would have seen at entry. If none were stolen this is empty.
    patches.stolen_bytes_offset = static_cast<uint32_t>(buf.size());
    for (auto b : stolen_bytes) u8(b);

    // (8) jmp rel32 → OEP + stolen_size
    u8(0xE9);
    patches.rel_to_oep_at = static_cast<uint32_t>(buf.size());
    u32(0);

    return {std::move(buf), patches};
}

/// Write an int32 little-endian into a buffer at `offset`.
void write_i32(ByteBuffer& buf, uint32_t offset, int32_t value) {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// Strip base relocations: clear the directory entry, set the file header's
/// IMAGE_FILE_RELOCS_STRIPPED bit, clear DYNAMIC_BASE in DllCharacteristics,
/// and blank out in-memory .reloc contents so PeBuilder doesn't re-emit them.
void disable_relocations(PeImage& image) {
    std::visit([&](auto& nt) {
        using NT = std::decay_t<decltype(nt)>;

        nt.FileHeader.Characteristics |= pe::IMAGE_FILE_RELOCS_STRIPPED;
        nt.OptionalHeader.DllCharacteristics &=
            static_cast<uint16_t>(~pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS32> ||
                      std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC < nt.OptionalHeader.NumberOfRvaAndSizes) {
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            }
        }
    }, image.nt_headers());

    image.set_relocations({});

    for (auto& sec : image.sections()) {
        if (sec.name == ".reloc") {
            std::fill(sec.data.begin(), sec.data.end(), static_cast<uint8_t>(0));
        }
    }
}

/// Find the primary code section to encrypt. For MSVC-built PEs this is
/// ".text". If a CFF trampoline section (`ctx.section_names().cff`) or a VM
/// blob (`ctx.section_names().vm`) was added earlier, they are also encrypted
/// so neither is left in the clear.
std::vector<size_t> collect_target_sections(const PeImage& image,
                                             const SectionNameMap& names) {
    std::vector<size_t> indices;
    for (size_t i = 0; i < image.sections().size(); ++i) {
        const auto& sec = image.sections()[i];
        if (sec.data.empty()) continue;
        if (sec.name == ".text" || sec.name == names.cff || sec.name == names.vm) {
            indices.push_back(i);
        }
    }
    return indices;
}

} // anonymous namespace

bool PackerPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    // The self-unpacking stub is assembled in x64 PE form; other targets
    // need their own packer implementations.
    return ctx.config().enable_packer && ctx.target().is_windows_pe_x64();
}

MxStatus PackerPass::execute(ProtectionContext& ctx) {
    ctx.log("PackerPass: начало самораспаковывающейся защиты");

    auto target_indices = collect_target_sections(ctx.pe_image(),
                                                   ctx.section_names());
    if (target_indices.empty()) {
        ctx.log("PackerPass: нет подходящих секций, пропуск");
        return {};
    }

    // The first target must be the one holding the OEP (only .text qualifies
    // under current policy). plan_stolen_bytes and the OEP retargeting both
    // reference it below.
    const size_t oep_target_idx = target_indices.front();
    auto& oep_target = ctx.pe_image().sections()[oep_target_idx];

    // (1) Kill base relocations so the encrypted bytes survive to runtime
    //     without the Windows loader touching them.
    disable_relocations(ctx.pe_image());
    ctx.log("PackerPass: релокации отключены (IMAGE_FILE_RELOCS_STRIPPED)");

    // (2) Plan stolen bytes: move the first instructions of OEP into the
    //     stub (before encryption) so a memory dump of the decrypted .text
    //     is missing its front. plan_stolen_bytes refuses unsafe sequences;
    //     in that case we skip stealing and keep the packer semantically
    //     identical. CALL rel32 sites are carried as relocs and fixed up
    //     once the stub section gets placed.
    const Rva oep_rva_initial = ctx.pe_image().entry_point_rva();
    StolenPlan stolen_plan;
    ByteBuffer stolen_bytes;
    if (oep_rva_initial >= oep_target.virtual_address &&
        oep_rva_initial < oep_target.virtual_address + oep_target.virtual_size) {
        const uint32_t oep_off = oep_rva_initial - oep_target.virtual_address;
        stolen_plan = plan_stolen_bytes(
            ByteView{oep_target.data.data(), oep_target.data.size()},
            oep_off, oep_rva_initial);
        if (stolen_plan.size > 0) {
            stolen_bytes.assign(
                oep_target.data.begin() + oep_off,
                oep_target.data.begin() + oep_off + stolen_plan.size);
            std::fill(oep_target.data.begin() + oep_off,
                      oep_target.data.begin() + oep_off + stolen_plan.size,
                      static_cast<uint8_t>(0xCC));
            ctx.log_fmt("PackerPass: украдено {} байт OEP (0x{:08X}), {} CALL-fixup",
                stolen_plan.size, oep_rva_initial,
                static_cast<uint32_t>(stolen_plan.relocs.size()));
        } else {
            ctx.log("PackerPass: OEP небезопасен для stolen bytes — пропуск");
        }
    }
    const uint32_t stolen_size = stolen_plan.size;

    // Make .rdata writable so the stub can zero the Import Directory at runtime.
    for (auto& sec : ctx.pe_image().sections()) {
        if (sec.name == ".rdata") {
            sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;
        }
    }

    // (3) Generate the per-build random 256-byte key.
    Randomizer rng;
    ByteBuffer key(kKeySize);
    for (auto& b : key) b = rng.next_u8();

    // (4) Encrypt every target section in place. The key index `dl` wraps
    //     at 256 and is carried across sections — mirrored exactly by the
    //     stub's decrypt loop. We start at dl=0 (builder isn't debugged);
    //     at runtime the stub's anti-debug step shifts dl by 1 if PEB
    //     reports a debugger.
    struct EncryptedTarget {
        size_t   image_index;
        Rva      rva;
        uint32_t size;
    };
    std::vector<EncryptedTarget> encrypted;
    encrypted.reserve(target_indices.size());

    uint8_t key_index = 0;
    for (const size_t idx : target_indices) {
        auto& sec = ctx.pe_image().sections()[idx];
        const uint32_t sec_size = static_cast<uint32_t>(sec.data.size());
        if (sec_size == 0) continue;

        for (uint32_t i = 0; i < sec_size; ++i) {
            sec.data[i] ^= key[key_index];
            key_index = static_cast<uint8_t>(key_index + 1); // wraps at 256
        }

        // Allow the stub to decrypt in place.
        sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

        encrypted.push_back({idx, sec.virtual_address, sec_size});
        ctx.log_fmt("PackerPass: зашифрована '{}' (RVA=0x{:08X}, {} байт)",
            sec.name, sec.virtual_address, sec_size);
    }

    if (encrypted.empty()) {
        ctx.log("PackerPass: все кандидаты пусты, пропуск");
        return {};
    }

    // (5) Build the stub code (includes stolen OEP bytes) + append the
    //     256-byte key. Size is not fixed because the stub is polymorphic.
    auto [stub_buf, patches] = build_stub_bytes(
        rng, ByteView{stolen_bytes.data(), stolen_bytes.size()},
        static_cast<uint32_t>(encrypted.size()));
    const uint32_t key_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), key.begin(), key.end());

    // Embed the reprotect section table right after the key: one
    // {rva: u32, size: u32} entry per encrypted section. The content
    // is zero-filled here and patched in step (7) once section RVAs
    // are final.
    const uint32_t reprotect_table_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), encrypted.size() * 8, uint8_t{0});

    // The jmp rel32 lands AFTER the stolen bytes: OEP + stolen_size.
    const Rva oep_rva = oep_rva_initial + stolen_size;

    // (6) Add the .mxpack section and figure out its RVA.
    constexpr uint32_t pack_characteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ;

    SectionManager sec_mgr(ctx.pe_image());
    const std::string& packer_section_name = ctx.section_names().packer;
    auto add_res = sec_mgr.add_section(
        packer_section_name,
        ByteView{stub_buf.data(), stub_buf.size()},
        pack_characteristics);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const uint32_t pack_idx = *add_res;
    auto& pack_sec = ctx.pe_image().sections()[pack_idx];
    const Rva stub_rva = pack_sec.virtual_address;

    ctx.log_fmt("PackerPass: секция '{}' добавлена: RVA=0x{:08X}, размер={} байт",
        packer_section_name, stub_rva, static_cast<uint32_t>(pack_sec.data.size()));

    // (7) Patch all rel32 placeholders. For each `lea reg, [rip + rel32]`
    //     and each `jmp rel32`, rel32 is computed from the instruction's
    //     END (= patch_offset + 4) to the target RVA.

    // Per-section: lea rdi → section base, mov ecx → section size
    for (size_t i = 0; i < encrypted.size(); ++i) {
        const auto& ds  = patches.sections[i];
        const auto& tgt = encrypted[i];

        const Rva lea_end_rva = stub_rva + ds.patch_lea_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(tgt.rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, ds.patch_lea_at, rel);
        write_i32(pack_sec.data, ds.patch_size_at, static_cast<int32_t>(tgt.size));
    }

    // lea rsi, [rip + rel] → embedded 256-byte key
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_key_at + 4;
        const Rva key_rva     = stub_rva + key_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_key_at, rel);
    }

    // lea r14, [rip + rel] → reprotect section table (one {rva,size} per
    // encrypted section). The table itself lives right after the key in
    // the stub buffer; each entry is filled with the final section RVA
    // and byte count.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_reprotect_table_at + 4;
        const Rva table_rva   = stub_rva + reprotect_table_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(table_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_reprotect_table_at, rel);

        for (size_t i = 0; i < encrypted.size(); ++i) {
            const uint32_t entry_off =
                reprotect_table_offset_in_stub + static_cast<uint32_t>(i * 8);
            write_i32(pack_sec.data, entry_off + 0,
                      static_cast<int32_t>(encrypted[i].rva));
            write_i32(pack_sec.data, entry_off + 4,
                      static_cast<int32_t>(encrypted[i].size));
        }
    }

    // jmp rel32 → OEP + stolen_size
    {
        const Rva jmp_end_rva = stub_rva + patches.rel_to_oep_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(oep_rva) - static_cast<int64_t>(jmp_end_rva));
        write_i32(pack_sec.data, patches.rel_to_oep_at, rel);
    }

    // IAT destruction: patch the lea rdi → Import Directory and size.
    // Read Import Directory RVA/size from the NT headers.
    {
        Rva impdir_rva = 0;
        uint32_t impdir_size = 0;
        std::visit([&](const auto& nt) {
            if (pe::IMAGE_DIRECTORY_ENTRY_IMPORT < nt.OptionalHeader.NumberOfRvaAndSizes) {
                impdir_rva  = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                impdir_size = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
        }, ctx.pe_image().nt_headers());

        if (impdir_rva != 0 && impdir_size >= 4) {
            // lea rdi → Import Directory
            const Rva lea_end_rva = stub_rva + patches.rel_to_impdir_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(impdir_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, patches.rel_to_impdir_at, rel);
            // mov ecx, size / 4 (dword count for rep stosd)
            write_i32(pack_sec.data, patches.impdir_size_at,
                      static_cast<int32_t>(impdir_size / 4));

            ctx.log_fmt("PackerPass: IAT destruction — Import Directory 0x{:08X} ({} байт) "
                        "будет обнулён при запуске",
                impdir_rva, impdir_size);
        } else {
            // No imports — zero the size so rep stosd is a no-op
            write_i32(pack_sec.data, patches.impdir_size_at, 0);
        }
    }

    // Fix up CALL rel32 inside the stolen bytes so each CALL still targets
    // its original .text function after the move into .mxpack.
    for (const auto& r : stolen_plan.relocs) {
        const uint32_t rel_abs_offset = patches.stolen_bytes_offset + r.offset_in_stolen;
        const uint32_t instr_end_abs  = patches.stolen_bytes_offset + r.instr_end_in_stolen;
        const Rva new_instr_end_rva   = stub_rva + instr_end_abs;
        const int32_t new_rel = static_cast<int32_t>(
            static_cast<int64_t>(r.original_target_rva) -
            static_cast<int64_t>(new_instr_end_rva));
        write_i32(pack_sec.data, rel_abs_offset, new_rel);
    }

    // 7. Point the PE entry at the stub. Update both the cached value and
    //    the NT header field so PeBuilder emits the redirected OEP.
    ctx.pe_image().set_entry_point_rva(stub_rva);
    std::visit([&](auto& nt) {
        nt.OptionalHeader.AddressOfEntryPoint = stub_rva;
    }, ctx.pe_image().nt_headers());

    ctx.log_fmt("PackerPass: OEP перенаправлен 0x{:08X} -> 0x{:08X}",
        oep_rva, stub_rva);
    ctx.log("PackerPass: упаковка завершена");
    return {};
}

} // namespace mx
