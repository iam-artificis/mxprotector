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
#include <concepts>
#include <cstring>
#include <format>
#include <optional>
#include <utility>
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

/// Patch offsets every stub emitter is required to produce, regardless of
/// shape. The shared packer runtime (`finalize_packer_stub`) consumes these
/// without caring what else the emitter wrote around them.
///
/// Both fields are stub-relative byte offsets:
///   * `stolen_bytes_offset` — first byte of the embedded stolen payload
///     inside the stub buffer. Used to fix up CALL rel32 sites inside the
///     stolen range once the stub's final RVA is known.
///   * `rel_to_oep_at`       — offset of the rel32 slot of the final
///     `jmp rel32` that branches back into the real entry (OEP for exe,
///     DllMain for dll) at `real_entry + stolen_size`.
struct CommonStubPatches {
    uint32_t stolen_bytes_offset = 0;
    uint32_t rel_to_oep_at       = 0;
};

/// Patch offsets produced by the shared decrypt-body emitter
/// (`emit_decrypt_body`). Every stub that embeds the cipher pipeline —
/// EXE today, full DLL next — exposes these through multi-inheritance
/// so the caller code that patches them stays emitter-agnostic.
struct CipherBodyPatches {
    // Per-section patch sites (see DecryptSection above). Populated in
    // stub-emission order; the caller patches each one to its section RVA
    // and byte count.
    std::vector<DecryptSection> sections;

    uint32_t rel_to_key_at       = 0;  ///< rel32 from end-of-lea to embedded 32-byte RC4 key
    uint32_t rel_to_sbox_at      = 0;  ///< rel32 from end-of-lea to 256-byte scratch S-box

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

    uint32_t rel_to_impdir_at    = 0;  ///< rel32 from end-of-lea to Import Directory
    uint32_t impdir_size_at      = 0;  ///< offset of the import dir size imm32

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
    uint32_t rel_to_reprotect_table_at = 0;
    uint32_t reprotect_table_offset    = 0;
    uint32_t reprotect_entry_count     = 0;

    // --- ImageBase rip-relative computation ---
    // The reprotect block needs to know the runtime image base of
    // **our own module** so it can compute `base = ImageBase + rva`
    // for each section entry. Reading `PEB.ImageBaseAddress` gives
    // the host EXE's base — correct for executables (where the host
    // IS the packed module) but wrong for DLLs (the stub would
    // reprotect pages inside the host EXE's image instead of our
    // own, intermittently crashing the host depending on ASLR).
    //
    // Instead the stub computes the base rip-relative:
    //
    //   lea rbx, [rip + 0]          ; rbx = runtime address of next insn
    //   sub rbx, <imm32>            ; imm32 = stub_section_rva +
    //                                         imagebase_lea_anchor_offset
    //                                 → rbx = our own image base
    //
    // `imagebase_lea_anchor_offset` is the stub-relative offset of
    // the byte right after the lea (also the "rip" value the lea
    // produces, because the lea is `[rip + 0]`). The caller fills
    // `imagebase_sub_imm32_at` after the stub section is injected.
    uint32_t imagebase_lea_anchor_offset = 0;
    uint32_t imagebase_sub_imm32_at      = 0;
};

struct ExeStubPatches : CommonStubPatches, CipherBodyPatches {};

/// Patches produced by the full DLL stub — same cipher body as the EXE
/// shape, just wrapped in a DllMain-ABI save/restore shell and a
/// `reason == DLL_PROCESS_ATTACH` gate (the gate's rel32 is back-patched
/// inside the emitter itself, so the caller sees nothing new).
struct DllFullStubPatches : CommonStubPatches, CipherBodyPatches {};

/// A StubEmitter is a stateless (or cheaply copyable) policy type that
/// turns `(rng, stolen_bytes_view)` into a concrete stub buffer + an
/// emitter-specific patch descriptor. The patch descriptor must derive
/// from `CommonStubPatches` so the shared runtime can patch the rel32
/// slots (jmp-to-OEP, stolen CALL fixups) uniformly.
template <class T>
concept StubEmitter = requires(T& t, Randomizer& rng, ByteView stolen) {
    typename T::patches_type;
    requires std::derived_from<typename T::patches_type, CommonStubPatches>;
    { t.emit(rng, stolen) } ->
        std::same_as<std::pair<ByteBuffer, typename T::patches_type>>;
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

/// Append the shared decrypt body to `buf`:
///   anti-debug probe → edx ∈ {0, 1}
///   lea rsi = key; lea r8 = sbox
///   RC4 KSA (init + mix + PRGA state reset, VM-liftable range)
///   per-section RC4 PRGA decrypt loop (state carried across sections)
///   reprotect loop (Hell's Gate → NtProtectVirtualMemory per section)
///   Import Directory wipe
///
/// This body is emitter-agnostic: EXE and full-DLL stubs both wrap it in
/// their own register save/restore (and, for DLL, a `reason != ATTACH`
/// gate) and inherit `CipherBodyPatches` so their patch descriptors are
/// fillable by the same post-emit patching code.
///
/// Registers clobbered by the body: rax, rbx, rcx, rdx, rsi, rdi,
/// r8, r9, r10, r12, r13, r14, r15. (r11 is the only volatile GPR
/// left untouched.) Callers must save any of these that they need
/// preserved across the body.
///
/// On entry, the body assumes it owns rsp and can freely add a
/// 16-aligned scratch frame for the reprotect block's syscall args.
/// rsp at entry must be 16-aligned after any caller-side saves so the
/// reprotect block's `and rsp, -16` is a no-op.
void emit_decrypt_body(ByteBuffer& buf,
                       CipherBodyPatches& patches,
                       Randomizer& rng,
                       uint32_t section_count)
{
    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };

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
    // ntdll, and looks up the export by salted DJB2 hash. On
    // failure r13 is left at 0 and we skip the reprotect loop
    // entirely — pre-fix behaviour.
    //
    // The per-build random salt is what kills the "djb2_hash →
    // ntdll API" reverse-lookup dictionary: every build folds a
    // different 32-bit constant into the hash seed, so both the
    // `cmp eax, target_hash` slot and the scan-loop initial seed
    // slot change from build to build even though the target API
    // name is the same. Reversers reading the stub can still
    // extract both constants, but no longer via a static table.
    {
        mx::RawEmitter tmp{};
        const uint32_t salt = rng.next_u32();
        const uint32_t ntprotect_hash =
            anti_tamper::djb2_ascii_hash_salted(
                "NtProtectVirtualMemory", salt);
        anti_tamper::emit_hells_gate_address_resolver(
            tmp, ntprotect_hash, salt);
        for (uint8_t b : tmp.buf) u8(b);
    }

    // test r13, r13                          4D 85 ED
    u8(0x4D); u8(0x85); u8(0xED);
    // jz short .reprotect_done               74 rel8 (patched below)
    u8(0x74);
    const uint32_t patch_jz_reprotect_done = static_cast<uint32_t>(buf.size());
    u8(0x00);

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
    u8(0x48); u8(0x8D); u8(0x1D);
    u8(0x00); u8(0x00); u8(0x00); u8(0x00);
    patches.imagebase_lea_anchor_offset = static_cast<uint32_t>(buf.size());
    u8(0x48); u8(0x81); u8(0xEB);
    patches.imagebase_sub_imm32_at = static_cast<uint32_t>(buf.size());
    u32(0);

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
}

/// Build the EXE stub code bytes (without patching rel32s yet) and
/// report where the placeholders need to be filled in. The stub layout:
///
///   1. Save 5 registers (randomised push order — rax/rcx/rdx/rsi/rdi).
///   2. Emit the shared decrypt body via `emit_decrypt_body`
///      (anti-debug → KSA → PRGA → reprotect → IAT wipe).
///   3. Restore registers in reverse of the saved order (LIFO pop).
///   4. Execute the stolen OEP bytes inline.
///   5. jmp rel32 → OEP + stolen_size.
///
/// EXE semantics: at stub entry the Windows loader has just `call`ed
/// the entry point, there is no caller to return to that expects
/// nonvolatile-register preservation (OEP is the initial thread
/// entry), so we only save the volatile-but-clobbered set.
[[nodiscard]] std::pair<ByteBuffer, ExeStubPatches> build_exe_stub_bytes(
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

    ExeStubPatches patches{};

    // (1) Randomised push/pop register order. Same permutation used for
    //     pushes (top-down) and pops (reversed) so the stack is balanced.
    std::array<uint8_t, 5> save_order{0x50 /*rax*/, 0x51 /*rcx*/, 0x52 /*rdx*/,
                                       0x56 /*rsi*/, 0x57 /*rdi*/};
    std::shuffle(save_order.begin(), save_order.end(), rng.engine());
    for (uint8_t op : save_order) u8(op);

    // (2) Shared decrypt body — anti-debug, KSA, PRGA per section,
    //     reprotect, IAT wipe. Populates the CipherBodyPatches slots
    //     of `patches` via the multi-inheritance base.
    emit_decrypt_body(buf, patches, rng, section_count);

    // (3) Restore registers in reverse of the saved order (LIFO).
    for (auto it = save_order.rbegin(); it != save_order.rend(); ++it) {
        u8(static_cast<uint8_t>(*it + 0x08));
    }

    // (4) Stolen OEP bytes run inline — rsp is now back to what the OEP
    //     would have seen at entry. If none were stolen this is empty.
    patches.stolen_bytes_offset = static_cast<uint32_t>(buf.size());
    for (auto b : stolen_bytes) u8(b);

    // (5) jmp rel32 → OEP + stolen_size
    u8(0xE9);
    patches.rel_to_oep_at = static_cast<uint32_t>(buf.size());
    u32(0);

    return {std::move(buf), patches};
}

/// Write an int32 little-endian into a buffer at `offset`.
void write_i32(ByteBuffer& buf, uint32_t offset, int32_t value) {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// Build the full DLL stub code bytes (without patching rel32s yet).
///
/// Layout:
///   1. Save all nonvolatile GPRs the cipher body can clobber
///      (rbx, rbp, rsi, rdi, r12-r15) plus the three DllMain arg
///      registers (rcx = HINSTANCE, rdx = reason, r8 = lpReserved).
///      That is 11 pushes total — odd count, so rsp moves from the
///      call-site mod16 == 8 to mod16 == 0, which is what the
///      reprotect block inside `emit_decrypt_body` expects before
///      its own `and rsp, -16; sub rsp, 0x50` frame.
///   2. `cmp edx, 1; jne .forward` — only run the decrypt pipeline
///      on `DLL_PROCESS_ATTACH`. THREAD_ATTACH (2), THREAD_DETACH (3)
///      and PROCESS_DETACH (0) fall straight through to the forward
///      block so the real DllMain sees them untouched.
///   3. Shared decrypt body — anti-debug, KSA, PRGA per section,
///      reprotect, IAT wipe — via `emit_decrypt_body`.
///   4. `.forward:` — back-patch site for the `jne` above.
///   5. Pop everything in reverse LIFO order. Nonvolatiles restored
///      so the loader's caller state is intact; DllMain args
///      restored so the real entry sees its ABI unchanged.
///   6. Stolen DllMain prologue bytes inline.
///   7. `jmp rel32` → DllMain + stolen_size. The real DllMain's `ret`
///      then returns to the loader with the BOOL in eax.
///
/// Note on r12: the reprotect block inside the cipher body uses r12
/// as scratch for its own rsp save/restore. That clobbers the value
/// we pushed in step 1, but the push-to-stack copy is what counts —
/// the `pop r12` in step 5 reloads the caller's original r12 from
/// the stack, untouched.
[[nodiscard]] std::pair<ByteBuffer, DllFullStubPatches> build_dll_full_stub_bytes(
    Randomizer& rng,
    ByteView stolen_bytes,
    uint32_t section_count)
{
    ByteBuffer buf;
    buf.reserve(192 + 32 * section_count + stolen_bytes.size() + kKeySize);

    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };

    DllFullStubPatches patches{};

    // (1) Save nonvolatiles + DllMain args. Fixed order — polymorphism
    //     comes from the anti-debug probe and KSA variance. 11 pushes
    //     → rsp mod 16 = 0 before the cipher body starts.
    u8(0x53);                    // push rbx
    u8(0x55);                    // push rbp
    u8(0x56);                    // push rsi
    u8(0x57);                    // push rdi
    u8(0x41); u8(0x54);          // push r12
    u8(0x41); u8(0x55);          // push r13
    u8(0x41); u8(0x56);          // push r14
    u8(0x41); u8(0x57);          // push r15
    u8(0x51);                    // push rcx  (HINSTANCE)
    u8(0x52);                    // push rdx  (reason — also consumed by KSA bias seed)
    u8(0x41); u8(0x50);          // push r8   (lpReserved)

    // (2) Gate on reason == DLL_PROCESS_ATTACH (1). rdx still holds
    //     the original reason at this point (the cmp is 32-bit safe
    //     because the reason argument is a DWORD).
    //
    //   cmp edx, 1                        83 FA 01
    u8(0x83); u8(0xFA); u8(0x01);
    //   jne .forward (rel32, back-patched below)  0F 85 rel32
    u8(0x0F); u8(0x85);
    const uint32_t reason_jne_rel32_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // (3) Shared decrypt body.
    emit_decrypt_body(buf, patches, rng, section_count);

    // (4) .forward: — back-patch the jne target.
    {
        const uint32_t forward_label = static_cast<uint32_t>(buf.size());
        const int32_t rel32 = static_cast<int32_t>(forward_label) -
            static_cast<int32_t>(reason_jne_rel32_at + 4);
        std::memcpy(buf.data() + reason_jne_rel32_at, &rel32, sizeof(rel32));
    }

    // (5) Pop nonvolatiles + DllMain args in reverse push order.
    u8(0x41); u8(0x58);          // pop r8
    u8(0x5A);                    // pop rdx
    u8(0x59);                    // pop rcx
    u8(0x41); u8(0x5F);          // pop r15
    u8(0x41); u8(0x5E);          // pop r14
    u8(0x41); u8(0x5D);          // pop r13
    u8(0x41); u8(0x5C);          // pop r12
    u8(0x5F);                    // pop rdi
    u8(0x5E);                    // pop rsi
    u8(0x5D);                    // pop rbp
    u8(0x5B);                    // pop rbx

    // (6) Stolen DllMain prologue bytes inline (may be empty).
    patches.stolen_bytes_offset = static_cast<uint32_t>(buf.size());
    for (auto b : stolen_bytes) u8(b);

    // (7) jmp rel32 → DllMain + stolen_size
    u8(0xE9);
    patches.rel_to_oep_at = static_cast<uint32_t>(buf.size());
    u32(0);

    return {std::move(buf), patches};
}

// ---------------------------------------------------------------------------
// Emitter policy types. Each wraps one of the `build_*_stub_bytes` helpers
// and exposes it through the `StubEmitter` concept so the shared packer
// runtime can patch the common rel32 slots uniformly.
// ---------------------------------------------------------------------------

class ExeStubEmitter {
public:
    using patches_type = ExeStubPatches;

    /// `section_count` is the number of encrypted sections the stub will
    /// iterate over. The decrypt loops are unrolled at build time —
    /// `ExeStubPatches::sections` ends up with one entry per loop the
    /// caller needs to patch with (rva, size).
    explicit ExeStubEmitter(uint32_t section_count) noexcept
        : section_count_(section_count) {}

    [[nodiscard]] std::pair<ByteBuffer, ExeStubPatches> emit(
        Randomizer& rng, ByteView stolen_bytes) {
        return build_exe_stub_bytes(rng, stolen_bytes, section_count_);
    }

private:
    uint32_t section_count_;
};

class DllFullStubEmitter {
public:
    using patches_type = DllFullStubPatches;

    explicit DllFullStubEmitter(uint32_t section_count) noexcept
        : section_count_(section_count) {}

    [[nodiscard]] std::pair<ByteBuffer, DllFullStubPatches> emit(
        Randomizer& rng, ByteView stolen_bytes) {
        return build_dll_full_stub_bytes(rng, stolen_bytes, section_count_);
    }

private:
    uint32_t section_count_;
};

static_assert(StubEmitter<ExeStubEmitter>,
    "ExeStubEmitter must satisfy the StubEmitter concept");
static_assert(StubEmitter<DllFullStubEmitter>,
    "DllFullStubEmitter must satisfy the StubEmitter concept");

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

/// Result of `prepare_oep_steal`: the section the real entry point lives
/// in, the entry RVA, the safe stolen-byte plan, and the bytes themselves
/// (empty if no safe prologue could be stolen, in which case the stub is
/// entered, runs its payload, and jumps straight back to the unchanged
/// entry RVA).
struct OepStealResult {
    size_t     section_index;
    Rva        oep_rva;
    StolenPlan plan;
    ByteBuffer stolen_bytes;
};

/// Shared packer pre-stub preparation.
///
/// Strips base relocations, locates the section that holds the real
/// entry point, tries to steal a safe prologue range, and overwrites
/// the stolen range in the source section with 0xCC so memory dumps
/// are missing the real prologue.
///
/// Returns std::nullopt if the entry RVA is zero (no entry at all —
/// nothing to protect) or falls outside every section; callers
/// treat that as "skip the packer for this image".
[[nodiscard]] std::optional<OepStealResult>
prepare_oep_steal(ProtectionContext& ctx, std::string_view steal_label) {
    disable_relocations(ctx.pe_image());
    ctx.log("PackerPass: релокации отключены (IMAGE_FILE_RELOCS_STRIPPED)");

    const Rva oep_rva = ctx.pe_image().entry_point_rva();
    if (oep_rva == 0) {
        ctx.log("PackerPass: entry point == 0, пропуск");
        return std::nullopt;
    }

    auto& sections = ctx.pe_image().sections();
    size_t section_index = sections.size();
    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i];
        if (oep_rva >= s.virtual_address &&
            oep_rva < s.virtual_address + s.virtual_size) {
            section_index = i;
            break;
        }
    }
    if (section_index == sections.size()) {
        ctx.log("PackerPass: entry RVA вне секций, пропуск");
        return std::nullopt;
    }

    OepStealResult result{};
    result.section_index = section_index;
    result.oep_rva       = oep_rva;

    auto& oep_target = sections[section_index];
    const uint32_t oep_off = oep_rva - oep_target.virtual_address;
    result.plan = plan_stolen_bytes(
        ByteView{oep_target.data.data(), oep_target.data.size()},
        oep_off, oep_rva);

    if (result.plan.size > 0) {
        result.stolen_bytes.assign(
            oep_target.data.begin() + oep_off,
            oep_target.data.begin() + oep_off + result.plan.size);
        std::fill(oep_target.data.begin() + oep_off,
                  oep_target.data.begin() + oep_off + result.plan.size,
                  static_cast<uint8_t>(0xCC));
        ctx.log_fmt("PackerPass: украдено {} байт {} (0x{:08X}), {} CALL-fixup",
            result.plan.size, steal_label, oep_rva,
            static_cast<uint32_t>(result.plan.relocs.size()));
    } else {
        ctx.log_fmt("PackerPass: {} небезопасен для stolen bytes — пропуск",
            steal_label);
    }
    return result;
}

/// Result of `finalize_packer_stub`.
struct PackerStubInjection {
    size_t  pack_section_index;  ///< index into ctx.pe_image().sections()
    Rva     stub_rva;            ///< RVA where the injected stub was placed
};

/// Shared packer post-stub finalisation.
///
/// Injects a `.mxpack` (or equivalently-named) section carrying the
/// assembled stub buffer, patches the two rel32 slots every stub
/// emitter must produce (`rel_to_oep_at` → real entry + stolen_size,
/// and any CALL rel32 fix-ups inside the embedded stolen payload),
/// and retargets `AddressOfEntryPoint` at the stub.
///
/// Returns {section_index, stub_rva} so the caller can apply any
/// emitter-specific patches (per-section LEA/ECX slots, key/sbox
/// rel32, reprotect table, IAT wipe — all EXE-only for now).
[[nodiscard]] MxResult<PackerStubInjection> finalize_packer_stub(
    ProtectionContext& ctx,
    ByteBuffer&&       stub_buf,
    uint32_t           section_characteristics,
    const OepStealResult& steal,
    const CommonStubPatches& common)
{
    SectionManager sec_mgr(ctx.pe_image());
    const std::string& packer_section_name = ctx.section_names().packer;
    auto add_res = sec_mgr.add_section(
        packer_section_name,
        ByteView{stub_buf.data(), stub_buf.size()},
        section_characteristics);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const uint32_t pack_idx = *add_res;
    auto& pack_sec = ctx.pe_image().sections()[pack_idx];
    const Rva stub_rva = pack_sec.virtual_address;

    ctx.log_fmt("PackerPass: секция '{}' добавлена: RVA=0x{:08X}, размер={} байт",
        packer_section_name, stub_rva,
        static_cast<uint32_t>(pack_sec.data.size()));

    // jmp rel32 → real entry + stolen_size
    {
        const Rva resume_rva  = steal.oep_rva + steal.plan.size;
        const Rva jmp_end_rva = stub_rva + common.rel_to_oep_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(resume_rva) -
            static_cast<int64_t>(jmp_end_rva));
        write_i32(pack_sec.data, common.rel_to_oep_at, rel);
    }

    // Fix up CALL rel32 inside the stolen payload so each target RVA
    // stays identical after the move into the stub section.
    for (const auto& r : steal.plan.relocs) {
        const uint32_t rel_abs_offset = common.stolen_bytes_offset + r.offset_in_stolen;
        const uint32_t instr_end_abs  = common.stolen_bytes_offset + r.instr_end_in_stolen;
        const Rva new_instr_end_rva   = stub_rva + instr_end_abs;
        const int32_t new_rel = static_cast<int32_t>(
            static_cast<int64_t>(r.original_target_rva) -
            static_cast<int64_t>(new_instr_end_rva));
        write_i32(pack_sec.data, rel_abs_offset, new_rel);
    }

    ctx.pe_image().set_entry_point_rva(stub_rva);
    std::visit([&](auto& nt) {
        nt.OptionalHeader.AddressOfEntryPoint = stub_rva;
    }, ctx.pe_image().nt_headers());

    ctx.log_fmt("PackerPass: entry перенаправлен 0x{:08X} -> 0x{:08X}",
        steal.oep_rva, stub_rva);

    return PackerStubInjection{pack_idx, stub_rva};
}

/// Shared encrypted-packer pipeline. Parameterised on `Emitter` so EXE
/// and DLL both flow through the same steps, differing only in the
/// policy type's save/restore shell (and, for DLL, its PROCESS_ATTACH
/// gate). The emitter's `patches_type` must inherit from both
/// `CommonStubPatches` and `CipherBodyPatches`, which the concept +
/// multi-inheritance of the concrete patch types statically guarantee.
///
/// Pipeline:
///   1. Collect target sections (`.text`, vm blob, cff blob).
///   2. `prepare_oep_steal` — strip relocations, locate entry, steal
///      safe prologue bytes, 0xCC the stolen range in place.
///   3. Make `.rdata` writable so the stub can wipe the Import
///      Directory at runtime.
///   4. Generate the per-build random 32-byte RC4 key and encrypt
///      every target section in place (KSA seeded with j = 0 at
///      build time — see the anti-debug bias comment in Rc4State).
///   5. Ask the emitter for the stub bytes.
///   6. Append key, S-box scratch, optional P3 VM KSA blob, reprotect
///      section table, all into the same stub buffer so everything
///      lives inside one `.mxpack` section.
///   7. `finalize_packer_stub` — inject section, patch common rel32
///      slots (jmp → real entry, stolen CALL fix-ups), retarget
///      AddressOfEntryPoint.
///   8. Patch cipher-body rel32s (per-section LEA/ECX, key, S-box,
///      reprotect table, IAT wipe). Optionally overwrite the KSA
///      range with a `call rel32 <vm_entry>` if the VM lift
///      succeeded in step 6.
template <StubEmitter Emitter>
    requires std::constructible_from<Emitter, uint32_t>
[[nodiscard]] MxStatus execute_encrypted_stub(ProtectionContext& ctx,
                                              std::string_view   steal_label)
{
    auto target_indices = collect_target_sections(ctx.pe_image(),
                                                   ctx.section_names());
    if (target_indices.empty()) {
        ctx.log("PackerPass: нет подходящих секций, пропуск");
        return {};
    }

    auto steal_opt = prepare_oep_steal(ctx, steal_label);
    if (!steal_opt) return {};
    auto& steal = *steal_opt;

    // Make .rdata writable so the stub can zero the Import Directory at runtime.
    for (auto& sec : ctx.pe_image().sections()) {
        if (sec.name == ".rdata") {
            sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;
        }
    }

    // Per-build random 32-byte RC4 key.
    Randomizer rng;
    ByteBuffer key(kKeySize);
    for (auto& b : key) b = rng.next_u8();

    // Encrypt every target section with a single streaming RC4 state.
    // The S-box and (i, j) state are carried across sections so the
    // runtime stub rebuilds the same stream via one KSA pass and
    // consumes it in the same order. We seed KSA with j = 0 at build
    // time (no debugger); the stub starts its KSA with j = edx
    // (anti-debug probe result), so under a debugger the S-box
    // diverges on the very first iteration and every protected
    // section decrypts to garbage.
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

    // Emit the stub via the policy-specified emitter.
    Emitter emitter{static_cast<uint32_t>(encrypted.size())};
    auto [stub_buf, patches] = emitter.emit(
        rng, ByteView{steal.stolen_bytes.data(), steal.stolen_bytes.size()});

    // Append the 32-byte RC4 key.
    const uint32_t key_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), key.begin(), key.end());

    // S-box scratch: 256 bytes. At runtime the KSA overwrites the
    // whole region — the build-time content doesn't matter, we just
    // need the space inside the section so `lea r8, sbox` points at
    // valid memory.
    const uint32_t sbox_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), kSboxSize, uint8_t{0});

    // P3 — VM-protected KSA. If a disassembler is available, lift
    // the RC4 KSA range through the existing VM engine and append
    // the runtime blob to the stub buffer; the original plaintext
    // KSA bytes are later overwritten with `call rel32 <vm_entry>`.
    size_t   packer_vm_blob_offset    = 0;
    uint32_t packer_vm_entry_offset   = 0;
    bool     packer_vm_lift_succeeded = false;
    if (ctx.disassembler() != nullptr &&
        patches.ksa_block_end_offset > patches.ksa_block_start_offset)
    {
        const size_t ksa_size =
            patches.ksa_block_end_offset - patches.ksa_block_start_offset;
        ByteView ksa_view{
            stub_buf.data() + patches.ksa_block_start_offset,
            ksa_size};

        vm::VmLifter lifter(*ctx.disassembler());
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
            // `use_imagebase_key` reads `PEB.ImageBaseAddress` at VM
            // runtime and folds it into the handler-table key via a
            // build-time MBA chain anchored on `preferred_image_base`.
            // For an EXE, PEB.ImageBase == the exe's own preferred
            // base (we strip relocations), so the chain agrees. For
            // a DLL, PEB.ImageBase is the HOST exe's base regardless
            // of which module is running — a DLL VM using this key
            // would compute the wrong table_xor_key and dispatch
            // every handler into garbage. `VirtualizationPass` has
            // the same gate for the same reason.
            const bool is_exe =
                ctx.pe_image().pe_type() == PeType::executable;
            const vm::VmGenOptions opts{
                .emit_exit_as_jmp        = false,
                .use_imagebase_key       = is_exe,
                .preferred_image_base    =
                    static_cast<uint64_t>(ctx.pe_image().image_base()),
                .skip_anti_tamper_checks = true,
            };
            auto runtime = gen.generate(vm_insns, rng, opts);
            if (!runtime) {
                ctx.log_fmt("PackerPass: P3 VM-lift generate failed ({}), keeping plaintext",
                    runtime.error().message());
            } else {
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

    // Embed the reprotect section table right after the VM blob.
    const uint32_t reprotect_table_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), encrypted.size() * 8, uint8_t{0});

    // Inject the .mxpack section + apply the common rel32 patches.
    // Characteristics include MEM_WRITE because the RC4 KSA rebuilds
    // the S-box scratch area at runtime and the scratch lives inside
    // the stub section itself.
    constexpr uint32_t pack_characteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ |
        pe::IMAGE_SCN_MEM_WRITE;

    auto inject = finalize_packer_stub(
        ctx, std::move(stub_buf), pack_characteristics, steal, patches);
    if (!inject) return std::unexpected(inject.error());

    auto& pack_sec = ctx.pe_image().sections()[inject->pack_section_index];
    const Rva stub_rva = inject->stub_rva;

    // Per-section: lea rdi → section base, mov ecx → section size.
    for (size_t i = 0; i < encrypted.size(); ++i) {
        const auto& ds  = patches.sections[i];
        const auto& tgt = encrypted[i];

        const Rva lea_end_rva = stub_rva + ds.patch_lea_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(tgt.rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, ds.patch_lea_at, rel);
        write_i32(pack_sec.data, ds.patch_size_at, static_cast<int32_t>(tgt.size));
    }

    // lea rsi, [rip + rel] → embedded 32-byte RC4 key.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_key_at + 4;
        const Rva key_rva     = stub_rva + key_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_key_at, rel);
    }

    // lea r8, [rip + rel] → 256-byte S-box scratch area.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_sbox_at + 4;
        const Rva sbox_rva    = stub_rva + sbox_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(sbox_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_sbox_at, rel);
    }

    // P3 — if the KSA block was successfully lifted, overwrite the
    // plaintext KSA bytes with `call rel32 <vm_entry>` + NOP pad.
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

    // ImageBase rip-relative computation. The `lea rbx, [rip + 0];
    // sub rbx, imm32` pair in the reprotect block needs `imm32 =
    // stub_section_rva + imagebase_lea_anchor_offset` so that at
    // runtime `rbx = current_rip - imm32 = module_base`. This works
    // for both EXE (host == packed module) and DLL (host != packed
    // module) — we never read PEB.ImageBaseAddress.
    {
        const uint32_t imm32 =
            stub_rva + patches.imagebase_lea_anchor_offset;
        write_i32(pack_sec.data, patches.imagebase_sub_imm32_at,
                  static_cast<int32_t>(imm32));
    }

    // lea r14, [rip + rel] → reprotect section table + fill data.
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

    // IAT destruction: patch lea rdi → Import Directory + the size.
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
            const Rva lea_end_rva = stub_rva + patches.rel_to_impdir_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(impdir_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, patches.rel_to_impdir_at, rel);
            write_i32(pack_sec.data, patches.impdir_size_at,
                      static_cast<int32_t>(impdir_size / 4));
            ctx.log_fmt("PackerPass: IAT destruction — Import Directory 0x{:08X} ({} байт) "
                        "будет обнулён при запуске",
                impdir_rva, impdir_size);
        } else {
            write_i32(pack_sec.data, patches.impdir_size_at, 0);
        }
    }

    ctx.log("PackerPass: упаковка завершена");
    return {};
}

} // anonymous namespace

bool PackerPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    // The self-unpacking stub is assembled in x64 PE form; other targets
    // need their own packer implementations.
    if (!ctx.config().enable_packer)      return false;
    if (!ctx.target().is_windows_pe_x64()) return false;

    // Kernel drivers enter via DriverEntry (PDRIVER_OBJECT, PUNICODE_STRING)
    // and still need their own stub variant — auto-skip them.
    // DLLs enter via DllMain (HINSTANCE, DWORD reason, LPVOID). The DLL
    // path below emits a forwarding-only stub for now (no encryption yet);
    // full DLL packing will layer on top of that in a follow-up.
    const auto pe_type = ctx.pe_image().pe_type();
    if (pe_type != PeType::executable &&
        pe_type != PeType::dynamic_library) {
        return false;
    }

    return true;
}

MxStatus PackerPass::execute(ProtectionContext& ctx) {
    ctx.log("PackerPass: начало самораспаковывающейся защиты");

    const auto pe_type = ctx.pe_image().pe_type();
    if (pe_type == PeType::executable) {
        return execute_encrypted_stub<ExeStubEmitter>(ctx, "OEP");
    }
    if (pe_type == PeType::dynamic_library) {
        return execute_encrypted_stub<DllFullStubEmitter>(ctx, "DllMain");
    }
    return {};
}


} // namespace mx
