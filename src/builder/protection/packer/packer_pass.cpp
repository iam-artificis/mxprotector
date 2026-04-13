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
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <variant>

namespace mx {

namespace {

/// RC4 key size in bytes. 32 bytes = 256 bits — matches the roadmap's
/// P1 target ("key 256 бит") and is the length the KSA modular index
/// `i mod kKeySize` is hard-coded to in the emitted stub.
///
/// Historically this was 256 bytes for the vanilla-XOR stream cipher;
/// the number and the name have been kept so the existing patch-site
/// plumbing ("embedded key" → "lea rsi, key") reads the same, but the
/// semantics are now "KSA input key" rather than "XOR key stream".
constexpr uint32_t kKeySize = 32;

/// S-box size for RC4 (fixed by the algorithm).
constexpr uint32_t kSboxSize = 256;

// ---------------------------------------------------------------------------
// Build-time RC4 stream cipher — mirrors the runtime stub byte-for-byte.
//
// The decryptor emitted by `build_stub_bytes` below implements standard
// RC4 (KSA + PRGA). This helper runs the same algorithm at build time
// so the encrypted output matches what the stub will decrypt.
//
// The state deliberately starts with `j = anti_debug_bias`, which is
// the build's prediction of what `edx` will hold at stub entry —
// normally 0 (no debugger). At runtime, if a debugger is present and
// the anti-debug probe flips `edx` to 1, the KSA starts with a
// different `j`, produces an entirely different S-box, and the PRGA
// stream decrypts the sections into garbage. There is no explicit
// "if debugger then die" branch; the cipher itself silently fails.
// ---------------------------------------------------------------------------

struct Rc4State {
    std::array<uint8_t, kSboxSize> sbox{};
    uint8_t i = 0;
    uint8_t j = 0;
};

void rc4_init(Rc4State& s, ByteView key, uint8_t anti_debug_bias) noexcept {
    for (uint32_t k = 0; k < kSboxSize; ++k) {
        s.sbox[k] = static_cast<uint8_t>(k);
    }
    uint8_t j = anti_debug_bias;
    for (uint32_t k = 0; k < kSboxSize; ++k) {
        j = static_cast<uint8_t>(
            j + s.sbox[k] + key[k % key.size()]);
        std::swap(s.sbox[k], s.sbox[j]);
    }
    s.i = 0;
    s.j = 0;
}

/// Encrypt (or decrypt — RC4 is self-inverse through XOR) `data` in
/// place. State carries over across calls so the cipher can stream
/// through several sections with one KSA.
void rc4_process(Rc4State& s, MutableByteView data) noexcept {
    for (auto& b : data) {
        s.i = static_cast<uint8_t>(s.i + 1);
        s.j = static_cast<uint8_t>(s.j + s.sbox[s.i]);
        std::swap(s.sbox[s.i], s.sbox[s.j]);
        const uint8_t k = s.sbox[
            static_cast<uint8_t>(s.sbox[s.i] + s.sbox[s.j])];
        b = static_cast<uint8_t>(b ^ k);
    }
}

/// Approximate size of the stub code (before the key). The actual size varies
/// a little across builds because the push/pop and setup order is randomised,
/// but the patch offsets are tracked dynamically so this is only a sanity
/// reference for documentation.
///
/// Layout (approximate — the stub is polymorphic and grew in P1 from
/// a 256-byte XOR keystream to full RC4 KSA + PRGA):
///   push rdi/rsi/rcx/rdx/rax          = 5
///   anti-debug probe (variant 0/1/2) = 10..20
///   lea  rsi, [rip + rel32]           = 7    — 32-byte RC4 key
///   lea  r8,  [rip + rel32]           = 7    — 256-byte S-box scratch
///   KSA phase 1 (init S[k]=k loop)   ~10
///   KSA phase 2 (mix with key loop)  ~34
///   PRGA state reset (xor r9/r10)     = 6
///   per section:
///     lea  rdi, [rip + rel32]         = 7
///     mov  ecx, imm32                 = 5
///     PRGA loop body                 ~42
///   reprotect block                 ~250
///   pop rax/rdx/rcx/rsi/rdi           = 5
///   jmp  rel32                        = 5
///
/// The anti-debug is woven *into* the cipher: the probe writes `edx`
/// ∈ {0, 1}, the KSA seeds its `j` register from `edx`. On a clean
/// run both build-time and runtime KSAs see j=0 and produce the same
/// S-box. Under a debugger the runtime j starts at 1 — the very first
/// KSA iteration swaps different entries than the build, the S-box
/// diverges, and the PRGA keystream is unrelated to the build-time
/// one. Every protected section decrypts to garbage before the stub
/// even reaches its reprotect block, and the process crashes before
/// the debugger can inspect anything meaningful.
constexpr uint32_t kStubCodeSize = 0; // polymorphic; see comment above

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

    uint32_t rel_to_key_at;        ///< patch offset (rel32 from end-of-lea to embedded 32-byte RC4 key)
    uint32_t rel_to_sbox_at;       ///< patch offset (rel32 from end-of-lea to 256-byte scratch S-box)
    uint32_t rel_to_oep_at;        ///< patch offset (rel32 from end-of-jmp to OEP + stolen_size)

    // P3 — VM-protected entry stub. The range
    // `[ksa_block_start_offset, ksa_block_end_offset)` inside the emitted
    // stub holds the RC4 KSA (init loop + mix loop + PRGA state reset).
    // If the caller succeeds in lifting those bytes through the VM engine
    // they overwrite the range with `call rel32 <vm_entry>` + NOP padding
    // and append the runtime blob elsewhere in the stub buffer. On lift
    // failure the range stays as plaintext — the packer still runs
    // correctly, it just isn't VM-wrapped.
    uint32_t ksa_block_start_offset = 0;
    uint32_t ksa_block_end_offset   = 0;
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

    // (3) RC4 setup — load the key and scratch S-box pointers.
    //
    // `rsi` holds the 32-byte key. `r8` holds the 256-byte S-box
    // scratch area. Both are `lea rip+disp32` loads whose disp32
    // slots the caller patches after the stub section RVA is known.
    //
    //   lea rsi, [rip + key_rel32]   48 8D 35 rel32
    u8(0x48); u8(0x8D); u8(0x35);
    patches.rel_to_key_at = static_cast<uint32_t>(buf.size());
    u32(0);
    //   lea r8,  [rip + sbox_rel32]  4C 8D 05 rel32
    u8(0x4C); u8(0x8D); u8(0x05);
    patches.rel_to_sbox_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // (3a) RC4 Key Scheduling Algorithm (KSA).
    //
    //   Phase 1 — initialise S[k] = k for k ∈ [0, 256):
    //     xor  ecx, ecx               ; k = 0
    //   .init:
    //     mov  [r8 + rcx], cl         ; S[k] = k (low byte)
    //     inc  cl                     ; k++
    //     jnz  .init                  ; wraps at 256 → exit
    //
    //   Phase 2 — mix with the key, seeded by the anti-debug bias:
    //     xor  ecx, ecx               ; k = 0
    //     mov  ebx, edx               ; j  = edx (0 normally, 1 under a debugger)
    //   .ksa:
    //     movzx eax, byte [r8 + rcx]  ; al = S[k]
    //     mov  dl, cl                 ; dl = k
    //     and  dl, 0x1F               ; dl = k mod 32 (key length)
    //     add  bl, al                 ; j += S[k]
    //     add  bl, [rsi + rdx]        ; j += key[k mod 32]
    //     movzx edx, byte [r8 + rbx]  ; dl = S[j]
    //     mov  [r8 + rbx], al         ; S[j] = S[k]
    //     mov  [r8 + rcx], dl         ; S[k] = S[j]   (old S[j])
    //     inc  cl                     ; k++
    //     jnz  .ksa                   ; wraps at 256
    //
    //   Phase 3 — reset PRGA state:
    //     xor  r9,  r9                ; i = 0
    //     xor  r10, r10               ; j = 0

    // Mark the start of the VM-liftable KSA block. Everything from
    // here through `xor r10, r10` (PRGA state reset) is pure
    // register / r8-or-rsi-relative code — no rip-relative memory
    // operands, no syscalls, no external branches. Safe for the
    // VmLifter.
    patches.ksa_block_start_offset = static_cast<uint32_t>(buf.size());

    // Phase 1: init S[k] = k.
    u8(0x31); u8(0xC9);                          // xor ecx, ecx
    const uint32_t init_loop_start = static_cast<uint32_t>(buf.size());
    u8(0x41); u8(0x88); u8(0x0C); u8(0x08);      // mov [r8+rcx], cl
    u8(0xFE); u8(0xC1);                          // inc cl
    {
        const uint32_t jnz_end = static_cast<uint32_t>(buf.size()) + 2;
        const int32_t  rel8    = static_cast<int32_t>(init_loop_start) -
                                 static_cast<int32_t>(jnz_end);
        u8(0x75); u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    // Phase 2: KSA mix.
    u8(0x31); u8(0xC9);                          // xor ecx, ecx    (k = 0)
    u8(0x89); u8(0xD3);                          // mov ebx, edx    (j = anti-debug bias)
    const uint32_t ksa_loop_start = static_cast<uint32_t>(buf.size());
    u8(0x41); u8(0x0F); u8(0xB6); u8(0x04); u8(0x08); // movzx eax, byte [r8+rcx]
    u8(0x88); u8(0xCA);                          // mov dl, cl
    u8(0x80); u8(0xE2); u8(0x1F);                // and dl, 0x1F
    u8(0x00); u8(0xC3);                          // add bl, al        (j += S[k])
    u8(0x02); u8(0x1C); u8(0x16);                // add bl, [rsi+rdx] (j += key[k mod 32])
    u8(0x41); u8(0x0F); u8(0xB6); u8(0x14); u8(0x18); // movzx edx, byte [r8+rbx] (dl = S[j])
    u8(0x41); u8(0x88); u8(0x04); u8(0x18);      // mov [r8+rbx], al  (S[j] = S[k])
    u8(0x41); u8(0x88); u8(0x14); u8(0x08);      // mov [r8+rcx], dl  (S[k] = old S[j])
    u8(0xFE); u8(0xC1);                          // inc cl
    {
        const uint32_t jnz_end = static_cast<uint32_t>(buf.size()) + 2;
        const int32_t  rel8    = static_cast<int32_t>(ksa_loop_start) -
                                 static_cast<int32_t>(jnz_end);
        u8(0x75); u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    // Phase 3: zero the PRGA (i, j) state. These are carried across all
    // per-section decrypt loops so the cipher streams through every
    // protected section end-to-end — the same way the old XOR carried
    // `dl` across sections.
    u8(0x4D); u8(0x31); u8(0xC9);                // xor r9, r9     (i  = 0)
    u8(0x4D); u8(0x31); u8(0xD2);                // xor r10, r10   (j  = 0)

    // End of the VM-liftable KSA block. The caller may replace the
    // range `[ksa_block_start_offset, ksa_block_end_offset)` with a
    // `call rel32 <vm_entry>` + NOP pad, hiding the RC4 setup inside
    // a VM region.
    patches.ksa_block_end_offset = static_cast<uint32_t>(buf.size());

    // (4) Per-section decrypt loop — RC4 PRGA.
    //
    // State at entry: r8 = S-box ptr, r9b = PRGA i, r10b = PRGA j,
    //                 rdi/ecx = per-section dest ptr and length.
    //
    //   .loop:
    //     inc   r9b                           ; i++
    //     movzx eax, byte [r8 + r9]           ; al = S[i]
    //     add   r10b, al                      ; j += S[i]
    //     movzx edx, byte [r8 + r10]          ; dl = S[j]
    //     mov   [r8 + r10], al                ; S[j] = S[i]
    //     mov   [r8 + r9],  dl                ; S[i] = S[j] (swap)
    //     add   al, dl                        ; al = (S[i]+S[j]) mod 256
    //     movzx eax, al                       ; zero-extend sum
    //     mov   al, [r8 + rax]                ; K = S[sum]
    //     xor   [rdi], al                     ; decrypt one byte
    //     inc   rdi                           ; advance dst
    //     dec   ecx                           ; length--
    //     jnz   .loop
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

        u8(0x41); u8(0xFE); u8(0xC1);                      // inc r9b
        u8(0x43); u8(0x0F); u8(0xB6); u8(0x04); u8(0x08);  // movzx eax, [r8+r9]
        u8(0x41); u8(0x00); u8(0xC2);                      // add r10b, al
        u8(0x43); u8(0x0F); u8(0xB6); u8(0x14); u8(0x10);  // movzx edx, [r8+r10]
        u8(0x43); u8(0x88); u8(0x04); u8(0x10);            // mov [r8+r10], al
        u8(0x43); u8(0x88); u8(0x14); u8(0x08);            // mov [r8+r9],  dl
        u8(0x00); u8(0xD0);                                // add al, dl
        u8(0x0F); u8(0xB6); u8(0xC0);                      // movzx eax, al
        u8(0x41); u8(0x8A); u8(0x04); u8(0x00);            // mov al, [r8+rax]
        u8(0x30); u8(0x07);                                // xor [rdi], al
        u8(0x48); u8(0xFF); u8(0xC7);                      // inc rdi
        u8(0xFF); u8(0xC9);                                // dec ecx
        {
            const uint32_t jnz_end = static_cast<uint32_t>(buf.size()) + 2;
            const int32_t  rel8    = static_cast<int32_t>(loop_body_start) -
                                     static_cast<int32_t>(jnz_end);
            u8(0x75); u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
        }
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

    // Save rsp, align, and allocate our scratch+call frame.
    //
    //   mov r12, rsp                 49 89 E4
    //   and rsp, -16                 48 83 E4 F0
    //   sub rsp, 0x50                48 81 EC 50 00 00 00
    //
    // After sub the frame looks like:
    //   [rsp+0x00..0x1F]  shadow space for the callee's arg1..4 homes
    //   [rsp+0x20]        arg5 slot = &old_protect_var (set once)
    //   [rsp+0x28]        pad / unused
    //   [rsp+0x30]        base_var  (rdx target, rewritten per iter)
    //   [rsp+0x38]        size_var  (r8 target, rewritten per iter)
    //   [rsp+0x40]        old_protect_var (PULONG output)
    //   [rsp+0x48..0x4F]  pad
    //
    // `and rsp, -16` ensures rsp is 16-aligned BEFORE the `call r13`
    // below — the CALL push will then leave rsp at mod16==8 inside
    // ntdll's stub, which is what the Windows x64 ABI expects.
    u8(0x49); u8(0x89); u8(0xE4);
    u8(0x48); u8(0x83); u8(0xE4); u8(0xF0);
    u8(0x48); u8(0x81); u8(0xEC);
    u32(0x00000050u);

    // Hell's Gate address resolver → r13 = NtProtectVirtualMemory
    // function body address. The resolver walks the PEB, finds
    // ntdll, and looks up the export by DJB2 hash. On failure r13
    // is left at 0 and we skip the reprotect loop entirely —
    // pre-fix behaviour.
    {
        mx::RawEmitter tmp{};
        constexpr uint32_t kNtProtectHash =
            anti_tamper::djb2_ascii_hash("NtProtectVirtualMemory");
        anti_tamper::emit_hells_gate_address_resolver(tmp, kNtProtectHash);
        for (uint8_t b : tmp.buf) u8(b);
    }

    // test r13, r13                          4D 85 ED
    u8(0x4D); u8(0x85); u8(0xED);
    // jz short .reprotect_done               74 rel8 (patched below)
    u8(0x74);
    const uint32_t patch_jz_reprotect_done = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // --- One-time setup outside the loop: ImageBase, arg5, table ---

    // mov rax, gs:[0x60]                     65 48 8B 04 25 60 00 00 00
    u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
    u8(0x60); u8(0x00); u8(0x00); u8(0x00);
    // mov rbx, [rax + 0x10]                  48 8B 58 10
    //   rbx = PEB.ImageBase. rbx is nonvolatile across the CALL, so
    //   we cache it once and reuse it for every iteration's base
    //   computation.
    u8(0x48); u8(0x8B); u8(0x58); u8(0x10);

    // lea rax, [rsp + 0x40]                  48 8D 44 24 40
    // mov [rsp + 0x20], rax                  48 89 44 24 20
    //   arg5 slot (pointer to old_protect_var) — constant, set once.
    u8(0x48); u8(0x8D); u8(0x44); u8(0x24); u8(0x40);
    u8(0x48); u8(0x89); u8(0x44); u8(0x24); u8(0x20);

    // lea r14, [rip + reprotect_table_rel32]  4C 8D 35 rel32
    //   r14 = pointer to the embedded section table. The rel32 is
    //   patched in `execute()` once the stub's section RVA and the
    //   table's offset inside the stub are final. r14 is also
    //   nonvolatile so it survives the CALL.
    u8(0x4C); u8(0x8D); u8(0x35);
    patches.rel_to_reprotect_table_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // mov r15d, <reprotect_entry_count>      41 BF imm32
    //   r15 = loop countdown. Nonvolatile, so the CALL won't stomp it.
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
    // mov [rsp + 0x30], rax                  48 89 44 24 30
    //   store base_var
    u8(0x48); u8(0x89); u8(0x44); u8(0x24); u8(0x30);

    // mov eax, [r14 + 4]                     41 8B 46 04
    //   size (zero-extends)
    u8(0x41); u8(0x8B); u8(0x46); u8(0x04);
    // mov [rsp + 0x38], rax                  48 89 44 24 38
    //   store size_var
    u8(0x48); u8(0x89); u8(0x44); u8(0x24); u8(0x38);

    // Prepare call registers (volatile — re-set every iteration
    // because the previous CALL clobbered them).
    //
    //   rcx = -1              (NtCurrentProcess pseudo-handle)
    //   rdx = &base_var       ([rsp + 0x30])
    //   r8  = &size_var       ([rsp + 0x38])
    //   r9d = PAGE_EXECUTE_READ (0x20)

    // mov rcx, -1                            48 C7 C1 FF FF FF FF
    u8(0x48); u8(0xC7); u8(0xC1);
    u32(0xFFFFFFFFu);
    // lea rdx, [rsp + 0x30]                  48 8D 54 24 30
    u8(0x48); u8(0x8D); u8(0x54); u8(0x24); u8(0x30);
    // lea r8, [rsp + 0x38]                   4C 8D 44 24 38
    u8(0x4C); u8(0x8D); u8(0x44); u8(0x24); u8(0x38);
    // mov r9d, 0x20                          41 B9 20 00 00 00
    u8(0x41); u8(0xB9);
    u32(0x00000020u);

    // call r13                               41 FF D5
    //   Invoke ntdll!NtProtectVirtualMemory. Going through the real
    //   stub means ntdll handles the Windows x64 ABI for the stack
    //   argument at [rsp+0x20] → [rsp+0x28] inside the stub, which
    //   a hand-rolled direct `syscall` from a 16-aligned rsp does
    //   not replicate correctly on Win11 with CET / shadow stack.
    u8(0x41); u8(0xFF); u8(0xD5);

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
///
/// The S2 string-protection section (`ctx.section_names().str`) is NOT
/// included: the packer's post-decrypt `NtProtectVirtualMemory` loop
/// revokes the write bit on every encrypted section, but `mx_str_get`
/// does an in-place XOR over the `.mxstr` data pool on the first call
/// to each string and flips a sticky flag inside the descriptor. Both
/// operations require the section to stay writable, so `.mxstr` is left
/// out of the packer target list. Its data pool is still ciphertext at
/// rest thanks to the per-string XOR encryption built into the pass,
/// and strong packer protection for the decryptor itself is a job for
/// S2c (`--strings=vm`) which lifts `mx_str_get` into a VM region.
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
    if (!ctx.config().enable_packer)      return false;
    if (!ctx.target().is_windows_pe_x64()) return false;

    // The stub assumes executable entry-point semantics: a single
    // thread enters at OEP with no arguments and runs the unpack
    // loop before jumping to the real OEP. DLLs enter via DllMain
    // with a (HINSTANCE, DWORD reason, LPVOID) ABI; kernel drivers
    // via DriverEntry with (PDRIVER_OBJECT, PUNICODE_STRING).
    // Dropping the exe-shaped stub on either of those produces a
    // binary that crashes on load. Auto-skip until the packer grows
    // a DLL/SYS-aware variant.
    const auto pe_type = ctx.pe_image().pe_type();
    if (pe_type != PeType::executable) return false;

    return true;
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

    // (3) Generate the per-build random 32-byte RC4 key.
    Randomizer rng;
    ByteBuffer key(kKeySize);
    for (auto& b : key) b = rng.next_u8();

    // (4) Encrypt every target section with RC4. The S-box and
    //     (i, j) state are carried across sections so the cipher
    //     streams through every protected section end-to-end — the
    //     runtime stub rebuilds the same stream once via KSA and
    //     consumes it in the same order.
    //
    //     We seed the KSA with `j = 0` at build time because the
    //     builder is not running under a debugger. The stub starts
    //     its KSA with `j = edx`, where edx is 0 under normal
    //     execution and 1 if the anti-debug probe fires. If a
    //     debugger is present the stub's S-box diverges on the very
    //     first KSA iteration and the PRGA keystream is incompatible
    //     with the build-time one — every protected section decrypts
    //     to garbage and the process crashes before the reverser
    //     reaches the real OEP.
    Rc4State rc4{};
    rc4_init(rc4, ByteView{key.data(), key.size()}, /*anti_debug_bias=*/0);

    struct EncryptedTarget {
        size_t   image_index;
        Rva      rva;
        uint32_t size;
    };
    std::vector<EncryptedTarget> encrypted;
    encrypted.reserve(target_indices.size());

    for (const size_t idx : target_indices) {
        auto& sec = ctx.pe_image().sections()[idx];
        const uint32_t sec_size = static_cast<uint32_t>(sec.data.size());
        if (sec_size == 0) continue;

        rc4_process(rc4, MutableByteView{sec.data.data(), sec.data.size()});

        // Allow the stub to decrypt in place.
        sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

        encrypted.push_back({idx, sec.virtual_address, sec_size});
        ctx.log_fmt("PackerPass: зашифрована (RC4) '{}' (RVA=0x{:08X}, {} байт)",
            sec.name, sec.virtual_address, sec_size);
    }

    if (encrypted.empty()) {
        ctx.log("PackerPass: все кандидаты пусты, пропуск");
        return {};
    }

    // (5) Build the stub code (includes stolen OEP bytes) + append the
    //     32-byte RC4 key, the 256-byte S-box scratch area, and the
    //     reprotect section table. Size is not fixed because the stub
    //     is polymorphic.
    auto [stub_buf, patches] = build_stub_bytes(
        rng, ByteView{stolen_bytes.data(), stolen_bytes.size()},
        static_cast<uint32_t>(encrypted.size()));
    const uint32_t key_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), key.begin(), key.end());

    // S-box scratch: 256 bytes of zeros. At runtime the KSA overwrites
    // the whole region — the build-time content doesn't matter, we
    // just need the space inside the section so `lea r8, sbox` points
    // at valid memory. Putting the scratch inside `.mxpack` keeps
    // everything rip-relative and avoids per-process stack frames.
    const uint32_t sbox_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), kSboxSize, uint8_t{0});

    // (5a) P3 — VM-protected entry stub.
    //
    // If a disassembler is available, lift the RC4 KSA block (init
    // loop + mix loop + PRGA state reset — see `ksa_block_*_offset`
    // recorded by `build_stub_bytes`) through the existing VM engine
    // and append the runtime blob to the stub buffer. The original
    // KSA bytes inside the stub are later overwritten with
    // `call rel32 <vm_entry>` + NOP padding (step 7a below) so the
    // entry stub dispatches the key derivation through a VM region
    // instead of executing it as plaintext x64.
    //
    // Two things the lifted block deliberately includes:
    //   * The `xor r9, r9; xor r10, r10` PRGA state reset, so the
    //     PRGA loops that run AFTER the VM exits see a consistent
    //     initial (i=0, j=0). The VM's exit writes these back to
    //     the real registers.
    //   * No rip-relative operands. `r8` and `rsi` are loaded BEFORE
    //     the KSA block via plaintext `lea` pairs; the VM just uses
    //     the values the caller handed it.
    //
    // Anti-tamper checks are skipped for this VM: `.mxpack` is
    // R+W+X on purpose (the KSA writes the S-box in place) and the
    // page-protection probe would trip on that.
    size_t   packer_vm_blob_offset       = 0;
    uint32_t packer_vm_entry_offset      = 0;
    bool     packer_vm_lift_succeeded    = false;
    if (ctx.disassembler() != nullptr &&
        patches.ksa_block_end_offset > patches.ksa_block_start_offset)
    {
        const size_t ksa_size =
            patches.ksa_block_end_offset - patches.ksa_block_start_offset;
        ByteView ksa_view{
            stub_buf.data() + patches.ksa_block_start_offset,
            ksa_size};

        vm::VmLifter lifter(*ctx.disassembler());
        // Fake base VA — the lift only uses it for intra-region
        // branch resolution, and the KSA block has no external
        // branches.
        constexpr Va kFakeKsaBase = 0x0000000140000000ULL;
        auto lift_result = lifter.lift(ksa_view, kFakeKsaBase);
        if (!lift_result) {
            ctx.log_fmt("PackerPass: P3 VM-lift KSA failed ({}), keeping plaintext",
                lift_result.error().message());
        } else {
            auto [vm_insns, report] = *lift_result;
            ctx.log_fmt("PackerPass: P3 VM-lift OK — total={}, generic={}, native={}",
                report.total_insns, report.generic_ops, report.native_ops);

            vm::VmRuntimeGenerator gen;
            const vm::VmGenOptions opts{
                .emit_exit_as_jmp        = false,
                // Packer strips ASLR so runtime ImageBase matches
                // preferred — same condition VirtualizationPass uses.
                .use_imagebase_key       = true,
                .preferred_image_base    =
                    static_cast<uint64_t>(ctx.pe_image().image_base()),
                // `.mxpack` stays R+W+X for the S-box — the
                // page-protection probe would misfire.
                .skip_anti_tamper_checks = true,
            };
            auto runtime = gen.generate(vm_insns, rng, opts);
            if (!runtime) {
                ctx.log_fmt("PackerPass: P3 VM-lift generate failed ({}), keeping plaintext",
                    runtime.error().message());
            } else {
                // Align the blob to 16 bytes so handler loads land
                // on naturally aligned addresses.
                while (stub_buf.size() % 16 != 0) {
                    stub_buf.push_back(0xCC);
                }
                packer_vm_blob_offset   = stub_buf.size();
                packer_vm_entry_offset  = runtime->entry_offset;
                stub_buf.insert(stub_buf.end(),
                                runtime->blob.begin(),
                                runtime->blob.end());
                packer_vm_lift_succeeded = true;
                ctx.log_fmt("PackerPass: P3 VM blob {} байт, entry @ stub+0x{:X}",
                    runtime->blob.size(),
                    packer_vm_blob_offset + packer_vm_entry_offset);
            }
        }
    }

    // Embed the reprotect section table right after the VM blob (or
    // right after the S-box if no blob was appended): one
    // {rva: u32, size: u32} entry per encrypted section. The content
    // is zero-filled here and patched in step (7) once section RVAs
    // are final.
    const uint32_t reprotect_table_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), encrypted.size() * 8, uint8_t{0});

    // The jmp rel32 lands AFTER the stolen bytes: OEP + stolen_size.
    const Rva oep_rva = oep_rva_initial + stolen_size;

    // (6) Add the .mxpack section and figure out its RVA.
    //
    // Characteristics include MEM_WRITE because the RC4 KSA rebuilds
    // the S-box scratch area at runtime (and the scratch lives inside
    // the stub section itself). The reprotect loop at the tail of
    // the stub only revokes WRITE from sections in `encrypted` — it
    // never touches `.mxpack` — so the section stays R+W+X for the
    // lifetime of the process. That's tolerable here because the
    // stub is only used once at startup and the page is a single
    // 4KB region no anti-tamper probe targets.
    constexpr uint32_t pack_characteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ |
        pe::IMAGE_SCN_MEM_WRITE;

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

    // lea rsi, [rip + rel] → embedded 32-byte RC4 key
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_key_at + 4;
        const Rva key_rva     = stub_rva + key_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_key_at, rel);
    }

    // lea r8, [rip + rel] → 256-byte S-box scratch area
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_sbox_at + 4;
        const Rva sbox_rva    = stub_rva + sbox_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(sbox_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_sbox_at, rel);
    }

    // P3 — if the KSA block was successfully lifted, overwrite the
    // plaintext KSA bytes with `call rel32 <vm_entry>` + NOP pad.
    // Runtime flow becomes:
    //
    //   save regs
    //   anti-debug → edx
    //   lea rsi, key; lea r8, sbox
    //   call vm_entry                   ; [NEW] KSA dispatched through VM
    //   <NOPs filling the rest of the old KSA range>
    //   per-section PRGA loop           ; unchanged, reads r8/r9/r10 state
    //   reprotect block
    //   ...
    //
    // When the VM exits, guest r8 / rsi are still the same pointers
    // (the KSA only writes the S-box through r8, doesn't overwrite
    // the pointer itself), and guest r9 / r10 are zero (the PRGA
    // state reset at the end of the lifted block). The PRGA loops
    // read those values unchanged, so the post-VM state is
    // bit-for-bit identical to the old plaintext path.
    if (packer_vm_lift_succeeded) {
        const Rva vm_entry_rva =
            stub_rva +
            static_cast<Rva>(packer_vm_blob_offset) +
            static_cast<Rva>(packer_vm_entry_offset);
        const uint32_t ksa_off = patches.ksa_block_start_offset;
        const Rva    call_rva   = stub_rva + ksa_off;
        const Rva    call_end_rva = call_rva + 5;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(vm_entry_rva) -
            static_cast<int64_t>(call_end_rva));

        pack_sec.data[ksa_off + 0] = 0xE8;  // call rel32
        pack_sec.data[ksa_off + 1] = static_cast<uint8_t>(rel        & 0xFF);
        pack_sec.data[ksa_off + 2] = static_cast<uint8_t>((rel >> 8)  & 0xFF);
        pack_sec.data[ksa_off + 3] = static_cast<uint8_t>((rel >> 16) & 0xFF);
        pack_sec.data[ksa_off + 4] = static_cast<uint8_t>((rel >> 24) & 0xFF);
        for (uint32_t i = ksa_off + 5; i < patches.ksa_block_end_offset; ++i) {
            pack_sec.data[i] = 0x90;
        }
        ctx.log_fmt("PackerPass: P3 KSA replaced with call vm_entry @ RVA=0x{:08X}",
            vm_entry_rva);
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
