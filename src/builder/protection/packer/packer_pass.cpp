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
#include "mxprotector/protection/packer/rc4.hpp"
#include "mxprotector/protection/packer/stolen_bytes.hpp"
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

// Pull the packer helpers into this TU's anonymous namespace so the
// existing unqualified references to `kKeySize`, `kSboxSize`,
// `Rc4State`, `rc4_init`, `rc4_process`, `kMinStolenBytes`,
// `kMaxStolenBytes`, `StolenReloc`, `StolenPlan`, and
// `plan_stolen_bytes` keep compiling after the extraction. Future
// commits that split the stub emitter / cipher body / TLS callback
// out of this file will move their call sites to the fully-qualified
// `packer::` form.
using mx::packer::kKeySize;
using mx::packer::kSboxSize;
using mx::packer::Rc4State;
using mx::packer::rc4_init;
using mx::packer::rc4_process;

using mx::packer::kMinStolenBytes;
using mx::packer::kMaxStolenBytes;
using mx::packer::StolenReloc;
using mx::packer::StolenPlan;
using mx::packer::plan_stolen_bytes;

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

/// Patch offsets for ONE cipher layer inside a multi-layer stub.
///
/// Each layer has its own RC4 key (baked as 32 bytes elsewhere in the
/// stub buffer) and its own per-section decrypt loop. The runtime walks
/// layers from `N-1` down to `0`, so layer 0 is the innermost layer —
/// it's the last one undone at runtime and the one whose KSA is seeded
/// with the anti-debug bias. See `emit_decrypt_body` for the full layer
/// ordering rationale.
///
/// Both fields are stub-relative byte offsets:
///   * `rel_to_key_at`  — rel32 inside `lea rsi, [rip + key_rel32]`
///                       that selects this layer's key pointer.
///   * `sections`       — per-target-section decrypt-loop patch sites
///                       (one per encrypted section, filled by the
///                       caller with section RVA and byte count).
struct LayerPatches {
    uint32_t                    rel_to_key_at = 0;
    std::vector<DecryptSection> sections;
};

/// Patch offsets produced by the shared decrypt-body emitter
/// (`emit_decrypt_body`). Every stub that embeds the cipher pipeline —
/// EXE today, full DLL next — exposes these through multi-inheritance
/// so the caller code that patches them stays emitter-agnostic.
struct CipherBodyPatches {
    // One entry per cipher layer (see P2 multi-layer comment in
    // `emit_decrypt_body`). Layer 0 is the innermost (bias-seeded
    // layer, runtime: LAST) and layer N-1 is the outermost (runtime:
    // first). Each layer has its own 32-byte RC4 key and its own
    // per-section decrypt loop; the S-box scratch area below is
    // shared because every layer's KSA rebuilds it from scratch.
    std::vector<LayerPatches> layers;

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

/// Append the shared decrypt body to `buf`:
///   anti-debug probe → edx ∈ {0, 1}
///   mov r15d, edx                 ; save bias across layer boundaries
///   lea r8 = sbox                 ; shared scratch (every layer rebuilds it)
///   for k = layer_count-1 down to 0:
///     lea rsi = key[k]
///     RC4 KSA phase 1 / 2 / 3     ; phase 2 seeds j=r15d only for layer 0
///     per-section RC4 PRGA decrypt loop (state carried across sections)
///   reprotect loop (Hell's Gate → NtProtectVirtualMemory per section)
///   Import Directory wipe
///
/// P2 — Multi-layer unpack: the runtime applies `layer_count` cipher
/// rounds, each with its own embedded key. Build-time encryption runs
/// the layers in REVERSE order (layer 0 first, layer N-1 last) so that
/// runtime decryption — which walks layers from N-1 down to 0 — undoes
/// them in the correct order. XOR is self-inverse, so the cascade
/// reduces to applying the per-layer keystream in symmetric order.
///
/// Anti-debug bias is woven ONLY into layer 0 (the innermost, runtime-
/// last layer). Under a debugger, layer 0's KSA seeds `j = 1` instead
/// of `j = 0`, produces a divergent S-box, and its PRGA XORs with a
/// wrong keystream — the final bytes are garbage before the stub
/// reaches the OEP, regardless of how many outer layers decrypted
/// cleanly. The bias itself is captured into `r15d` right after the
/// probe (`mov r15d, edx`) and stays there across every outer layer's
/// KSA, because r15 is nonvolatile-enough for this block: it's free
/// from the start of the body until the reprotect loop reloads it
/// with its iteration count, which happens AFTER all layers finish.
///
/// Only layer 0's KSA is exposed to the P3 VM lifter via
/// `ksa_block_start/end_offset`. Outer layers' KSAs stay as plaintext
/// x64 — they would need their own ksa range tracking, and the MVP
/// keeps the lift surface minimal to avoid multiplying VM-blob size.
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
                       uint32_t section_count,
                       uint32_t layer_count)
{
    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };

    // P2 — allocate per-layer patch storage up front. The emission loop
    // below fills entries in runtime-decrypt order (N-1 first, 0 last);
    // the caller addresses each layer by its logical index and the
    // in-memory position of the per-layer LEAs is irrelevant to patching.
    patches.layers.resize(layer_count);
    for (auto& lp : patches.layers) lp.sections.reserve(section_count);

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

    // P2 — Bias carrier. `edx` holds the anti-debug bias right after
    // the probe, but we're about to clobber edx inside each layer's KSA
    // phase 2 (it's used as scratch for `mov dl, cl; and dl, 0x1F`).
    // Copy the bias into `r15d` so it survives every KSA call until
    // layer 0's phase 2 reads it back. r15 is free from here until the
    // reprotect loop reloads it with its iteration counter, which runs
    // AFTER all layers finish.
    //
    //   mov r15d, edx                           41 89 D7
    u8(0x41); u8(0x89); u8(0xD7);

    // (3) RC4 setup — load the shared S-box pointer.
    //
    // `r8` holds the 256-byte S-box scratch area. Every layer's KSA
    // rebuilds the full S-box from S[k]=k, so layers can share one
    // scratch region. The per-layer `lea rsi, key_K` load happens
    // inside the layer emission loop below.
    //
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
    //   Phase 2 — mix with the key, seeded by the anti-debug bias
    //             (only on layer 0; other layers start with j = 0):
    //     xor  ecx, ecx               ; k = 0
    //     mov  ebx, r15d              ; j = bias    (layer 0 only)
    //       or  xor  ebx, ebx         ; j = 0       (outer layers)
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

    // P2 — Emit `layer_count` cipher rounds in RUNTIME DECRYPT order
    // (N-1 first, 0 last). Layer 0 is the innermost; build-time
    // encryption applies layers in the reverse order (0, 1, ..., N-1)
    // so that runtime decryption undoes them correctly. Only layer 0's
    // KSA is exposed to the P3 VM lifter — the `ksa_block_start/end`
    // fields are filled in only when the inner iteration hits
    // `layer_idx == 0`.
    for (int32_t layer_idx = static_cast<int32_t>(layer_count) - 1;
         layer_idx >= 0; --layer_idx)
    {
        const bool is_bias_layer = (layer_idx == 0);
        LayerPatches& lp = patches.layers[layer_idx];

        // Per-layer: load this layer's RC4 key pointer. Placed BEFORE
        // the `ksa_block_start_offset` mark for layer 0 so the P3 VM
        // lift region stays register-only (no rip-relative memory).
        //
        //   lea rsi, [rip + key_K_rel32]   48 8D 35 rel32
        u8(0x48); u8(0x8D); u8(0x35);
        lp.rel_to_key_at = static_cast<uint32_t>(buf.size());
        u32(0);

        // Mark the start of the VM-liftable KSA block for layer 0.
        // Everything from here through `xor r10, r10` (PRGA state reset)
        // is pure register / r8-or-rsi-relative code — no rip-relative
        // memory operands, no syscalls, no external branches. Safe for
        // the VmLifter.
        if (is_bias_layer) {
            patches.ksa_block_start_offset = static_cast<uint32_t>(buf.size());
        }

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

        // Phase 2: KSA mix. Seed j from the bias on layer 0, else 0.
        u8(0x31); u8(0xC9);                          // xor ecx, ecx    (k = 0)
        if (is_bias_layer) {
            // mov ebx, r15d                          44 89 FB
            //   j = saved anti-debug bias (0 normally, 1 under debugger)
            u8(0x44); u8(0x89); u8(0xFB);
        } else {
            // xor ebx, ebx                           31 DB
            //   j = 0 — outer layers don't care about bias, they just
            //   rebuild a deterministic S-box from their own key.
            u8(0x31); u8(0xDB);
        }
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

        // Phase 3: zero the PRGA (i, j) state. Each layer restarts
        // PRGA from (0, 0) — cross-layer state sharing would require
        // matching build-time encryption to use a different initial
        // state on every layer, which gains nothing.
        u8(0x4D); u8(0x31); u8(0xC9);                // xor r9, r9     (i  = 0)
        u8(0x4D); u8(0x31); u8(0xD2);                // xor r10, r10   (j  = 0)

        // End of the VM-liftable KSA block for layer 0. The caller may
        // replace the range `[ksa_block_start_offset, ksa_block_end_offset)`
        // with a `call rel32 <vm_entry>` + NOP pad, hiding the RC4 setup
        // inside a VM region.
        if (is_bias_layer) {
            patches.ksa_block_end_offset = static_cast<uint32_t>(buf.size());
        }

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

            lp.sections.push_back(ds);

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
    uint32_t section_count,
    uint32_t layer_count)
{
    ByteBuffer buf;
    buf.reserve(128 + (32 + 32 * section_count) * layer_count +
                stolen_bytes.size() + kKeySize * layer_count);

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
    emit_decrypt_body(buf, patches, rng, section_count, layer_count);

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
    uint32_t section_count,
    uint32_t layer_count)
{
    ByteBuffer buf;
    buf.reserve(192 + (32 + 32 * section_count) * layer_count +
                stolen_bytes.size() + kKeySize * layer_count);

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
    emit_decrypt_body(buf, patches, rng, section_count, layer_count);

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

/// Per-stub emission parameters shared by EXE and full-DLL stubs.
///
/// `section_count` — number of target sections the decrypt loops walk.
/// `layer_count`   — number of cipher rounds (P2). Each round owns its
///                   own RC4 key and its own per-section PRGA loop; the
///                   runtime decrypts layers N-1 → 0, and build-time
///                   encryption applies them in the reverse order.
struct StubEmissionParams {
    uint32_t section_count;
    uint32_t layer_count;
};

class ExeStubEmitter {
public:
    using patches_type = ExeStubPatches;

    explicit ExeStubEmitter(StubEmissionParams params) noexcept
        : params_(params) {}

    [[nodiscard]] std::pair<ByteBuffer, ExeStubPatches> emit(
        Randomizer& rng, ByteView stolen_bytes) {
        return build_exe_stub_bytes(rng, stolen_bytes,
                                    params_.section_count,
                                    params_.layer_count);
    }

private:
    StubEmissionParams params_;
};

class DllFullStubEmitter {
public:
    using patches_type = DllFullStubPatches;

    explicit DllFullStubEmitter(StubEmissionParams params) noexcept
        : params_(params) {}

    [[nodiscard]] std::pair<ByteBuffer, DllFullStubPatches> emit(
        Randomizer& rng, ByteView stolen_bytes) {
        return build_dll_full_stub_bytes(rng, stolen_bytes,
                                         params_.section_count,
                                         params_.layer_count);
    }

private:
    StubEmissionParams params_;
};

static_assert(StubEmitter<ExeStubEmitter>,
    "ExeStubEmitter must satisfy the StubEmitter concept");
static_assert(StubEmitter<DllFullStubEmitter>,
    "DllFullStubEmitter must satisfy the StubEmitter concept");

// ---------------------------------------------------------------------------
// Little-endian helpers for writing 64- and 32-bit values into a byte buffer.
// The packer already has `write_i32` for signed rel32 slots; these
// complementary helpers are used by the P4 TLS callback path which has to
// emit 64-bit absolute VAs into the TLS directory and the callback array.
// ---------------------------------------------------------------------------
inline void write_u64_le(ByteBuffer& buf, size_t offset, uint64_t value) {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

inline void write_u32_le(ByteBuffer& buf, size_t offset, uint32_t value) {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

[[nodiscard]] inline uint64_t read_u64_le(const uint8_t* p) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

[[nodiscard]] inline uint32_t read_u32_le(const uint8_t* p) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// Find the section that contains a given RVA, or nullptr if none does.
// Used by the P4 TLS callback path to locate the existing TLS directory's
// in-memory bytes (if the input binary has one) and to walk its callback
// array.
// ---------------------------------------------------------------------------
[[nodiscard]] const pe::SectionInfo* find_section_containing_rva(const PeImage& image,
                                                                  Rva rva) noexcept
{
    for (const auto& sec : image.sections()) {
        if (rva >= sec.virtual_address &&
            rva <  sec.virtual_address + sec.virtual_size) {
            return &sec;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// P4 — TLS callback entry.
//
// We install an extra TLS callback at the head of the TLS callback array
// so that an anti-debug probe runs BEFORE `AddressOfEntryPoint` (for EXEs)
// or BEFORE `DllMain` (for DLLs). Windows' image loader walks the callback
// array in order at PROCESS_ATTACH, THREAD_ATTACH, etc., so a callback at
// position 0 fires earlier than any entry-point the protector redirected
// to the packer stub. Breakpoints set on the classic "start" / "main" /
// "DllMain" symbols do not intercept code run from a TLS callback, so a
// reverser single-stepping from the debugger break lands AFTER the
// anti-debug probe has already had its say.
//
// When the callback detects a debugger it XORs a per-build random mask
// into one byte of the embedded RC4 key in `.mxpack`. The subsequent
// packer stub (running from `AddressOfEntryPoint` or the DllMain
// forwarding stub) then builds its KSA off the corrupted key, produces a
// different S-box from the one `rc4_process` used at build time, and
// every protected section decrypts to garbage. The process crashes with
// a wild indirect branch before the real OEP is reached. This is the
// same silent-kill pattern the existing packer anti-debug probe uses
// (seeding j=edx in the KSA) — P4 layers an earlier detection point on
// top of it.
// ---------------------------------------------------------------------------

/// Information read from the input PE's existing TLS directory, if any.
/// We keep the non-callback-array fields verbatim so C++
/// `__declspec(thread)` data that the CRT relies on keeps working, and
/// we prepend our new callback to the existing callback list so every
/// original callback still gets invoked in order.
struct ExistingTlsDirectory {
    uint64_t              start_va          = 0;
    uint64_t              end_va            = 0;
    uint64_t              index_va          = 0;
    uint32_t              size_of_zero_fill = 0;
    uint32_t              characteristics   = 0;
    std::vector<uint64_t> callbacks;  // raw VAs, preserved order, NULL stripped
};

/// Parse the input's `IMAGE_TLS_DIRECTORY64` if `DataDirectory[TLS]` is
/// populated. Returns `std::nullopt` for binaries that ship with no TLS
/// directory at all (common for tiny MSVC EXEs that don't use thread-
/// local statics). Any parsing failure after a TLS directory was found
/// also returns nullopt — the packer logs it and proceeds without TLS
/// protection rather than crashing the build.
[[nodiscard]] std::optional<ExistingTlsDirectory>
read_existing_tls_directory(const PeImage& image)
{
    Rva      tls_rva  = 0;
    uint32_t tls_size = 0;
    std::visit([&](const auto& nt) {
        if (pe::IMAGE_DIRECTORY_ENTRY_TLS < nt.OptionalHeader.NumberOfRvaAndSizes) {
            tls_rva  = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            tls_size = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
    }, image.nt_headers());

    if (tls_rva == 0 || tls_size < 40) return std::nullopt;

    const auto* tls_sec = find_section_containing_rva(image, tls_rva);
    if (tls_sec == nullptr) return std::nullopt;

    const uint32_t off = tls_rva - tls_sec->virtual_address;
    if (static_cast<size_t>(off) + 40 > tls_sec->data.size()) return std::nullopt;

    const uint8_t* p = tls_sec->data.data() + off;
    ExistingTlsDirectory out{};
    out.start_va          = read_u64_le(p + 0x00);
    out.end_va            = read_u64_le(p + 0x08);
    out.index_va          = read_u64_le(p + 0x10);
    const uint64_t cb_va  = read_u64_le(p + 0x18);
    out.size_of_zero_fill = read_u32_le(p + 0x20);
    out.characteristics   = read_u32_le(p + 0x24);

    // Walk the existing callback array until the NULL terminator or the
    // end of whatever section it lives in. We copy the raw VAs — they
    // are correct for the preferred image base, which the packer stub
    // keeps (it strips relocations so the loaded base matches the
    // build-time preferred base).
    if (cb_va == 0) return out;  // no callbacks, but directory kept

    const auto image_base = static_cast<uint64_t>(image.image_base());
    if (cb_va < image_base) return out;  // garbage pointer — leave callbacks empty

    const auto cb_rva = static_cast<Rva>(cb_va - image_base);
    const auto* cb_sec = find_section_containing_rva(image, cb_rva);
    if (cb_sec == nullptr) return out;

    uint32_t cb_off = cb_rva - cb_sec->virtual_address;
    while (static_cast<size_t>(cb_off) + 8 <= cb_sec->data.size()) {
        const uint64_t entry = read_u64_le(cb_sec->data.data() + cb_off);
        if (entry == 0) break;
        out.callbacks.push_back(entry);
        cb_off += 8;
    }
    return out;
}

/// Offsets into `stub_buf` recorded while `emit_tls_callback_body`
/// emits its 32 bytes. The single patch slot, `xor_key_rel32_offset`,
/// is a rel32 that points at the embedded RC4 key byte to corrupt;
/// the caller fills it in after the stub section's runtime RVA is
/// known.
struct TlsCallbackEmit {
    uint32_t body_offset            = 0;  // offset of first byte of callback
    uint32_t xor_key_rel32_offset   = 0;  // rel32 inside the xor-byte instruction
    uint32_t xor_instruction_end    = 0;  // byte right after the xor imm8
    uint32_t body_end_offset        = 0;  // one past the last byte (for padding)
    uint32_t key_byte_offset_in_key = 0;  // 0..31 — which byte of the RC4 key to corrupt
    uint32_t key_layer_index        = 0;  // 0..layer_count-1 — which layer's key to corrupt
};

/// Emit the 32-byte TLS callback body and record its patch sites.
///
/// Layout:
///
///   83 FA 01                   cmp   edx, 1                 ; reason == PROCESS_ATTACH?
///   75 rel8                    jne   .done                  ; skip everything else
///   65 48 8B 04 25 60 00 00 00 mov   rax, gs:[0x60]          ; PEB
///   0F B6 40 02                movzx eax, byte [rax+2]     ; BeingDebugged
///   85 C0                      test  eax, eax
///   74 rel8                    je    .done                  ; clean host → skip XOR
///   80 35 rel32 imm8           xor   byte [rip+rel32], mask ; corrupt RC4 key byte
///   .done:
///   31 C0                      xor   eax, eax                ; return 0 (VOID cast)
///   C3                         ret
///
/// Registers used: `rax`, `edx` — both volatile in the Windows x64
/// ABI, and the caller is a VOID NTAPI callback so return value is
/// ignored. `rcx`, `r8` (hModule, lpReserved) are not touched, which
/// lets us coexist with any existing callback that reads them.
[[nodiscard]] TlsCallbackEmit emit_tls_callback_body(ByteBuffer& buf,
                                                     Randomizer& rng,
                                                     uint32_t layer_count)
{
    TlsCallbackEmit out{};
    out.body_offset = static_cast<uint32_t>(buf.size());

    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto patch_rel8 = [&](uint32_t at) {
        const int32_t target = static_cast<int32_t>(buf.size());
        const int32_t rel8   = target - (static_cast<int32_t>(at) + 1);
        buf[at] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    };

    // cmp edx, 1
    u8(0x83); u8(0xFA); u8(0x01);
    // jne .done   — rel8 backpatched
    u8(0x75);
    const uint32_t jne_done_rel8_at = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // mov rax, gs:[0x60]   ; PEB
    u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
    u8(0x60); u8(0x00); u8(0x00); u8(0x00);
    // movzx eax, byte [rax+2]
    u8(0x0F); u8(0xB6); u8(0x40); u8(0x02);
    // test eax, eax
    u8(0x85); u8(0xC0);
    // je .done   — rel8 backpatched
    u8(0x74);
    const uint32_t je_done_rel8_at = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // xor byte [rip + rel32], imm8
    //   Opcode: 80 /6 ib (XOR r/m8, imm8).
    //   ModRM: mod=00 reg=/6 rm=101 = 0x35 → rip-relative, no SIB.
    u8(0x80); u8(0x35);
    out.xor_key_rel32_offset = static_cast<uint32_t>(buf.size());
    u8(0x00); u8(0x00); u8(0x00); u8(0x00);  // rel32 placeholder
    const uint8_t mask = static_cast<uint8_t>(rng.next_range(1, 255));
    u8(mask);
    out.xor_instruction_end = static_cast<uint32_t>(buf.size());

    // .done: — back-patch the two forward rel8 branches above.
    patch_rel8(jne_done_rel8_at);
    patch_rel8(je_done_rel8_at);

    // xor eax, eax   — VOID NTAPI return, value is discarded but we
    //                  leave rax in a deterministic state.
    u8(0x31); u8(0xC0);
    // ret
    u8(0xC3);

    out.body_end_offset         = static_cast<uint32_t>(buf.size());
    out.key_byte_offset_in_key  = rng.next_range(0, kKeySize - 1);
    // P2 — randomise which cipher layer's key gets corrupted. Every
    // build picks a different target, so a reverser who extracts the
    // target offset from one binary cannot predict it on the next.
    // `layer_count` is clamped to ≥1 before this call, so the upper
    // bound is always valid.
    out.key_layer_index         = rng.next_range(0, layer_count - 1);
    return out;
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
    requires std::constructible_from<Emitter, StubEmissionParams>
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

    // P2 — Multi-layer cipher rounds. Each round has its own RC4 key
    // and its own PRGA decrypt loop. Layer 0 is the innermost (runtime
    // decrypted LAST, anti-debug bias woven into its KSA); build-time
    // encryption applies layers in the reverse of runtime order, i.e.
    // `layer 0 first, then 1, ..., then N-1`. `layer_count` is clamped
    // to at least 1 — a config value of 0 is promoted to 1 so the
    // decrypt body still emits one cipher round.
    const uint32_t layer_count =
        std::max<uint32_t>(1, ctx.config().packer_cipher_layers);

    Randomizer rng;
    std::vector<ByteBuffer> layer_keys(layer_count);
    for (auto& k : layer_keys) {
        k.resize(kKeySize);
        for (auto& b : k) b = rng.next_u8();
    }

    struct EncryptedTarget {
        size_t   image_index;
        Rva      rva;
        uint32_t size;
    };
    std::vector<EncryptedTarget> encrypted;
    encrypted.reserve(target_indices.size());

    // Walk the target sections once to skip empty ones and mark them
    // writable. The layer-encryption loop below re-walks the resulting
    // `encrypted` vector so every layer sees the same section order
    // that the runtime stub's PRGA loops will walk.
    for (const size_t idx : target_indices) {
        auto& sec = ctx.pe_image().sections()[idx];
        const uint32_t sec_size = static_cast<uint32_t>(sec.data.size());
        if (sec_size == 0) continue;

        // Allow the stub to decrypt in place.
        sec.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

        encrypted.push_back({idx, sec.virtual_address, sec_size});
    }

    if (encrypted.empty()) {
        ctx.log("PackerPass: все кандидаты пусты, пропуск");
        return {};
    }

    // Apply N RC4 rounds in BUILD order (0 first, N-1 last). The
    // runtime decrypts in the opposite order (N-1 first, 0 last),
    // and since each RC4 round is self-inverse the nested cascade
    // unwinds to plaintext. Within a single layer we carry one
    // `Rc4State` across all target sections so the build-time PRGA
    // stream matches the runtime stream — the runtime's layer PRGA
    // loops reset `(i, j)` to (0, 0) at the start of each layer but
    // carry them across sections inside the layer.
    //
    // Build-time bias is 0 for every layer: there's no debugger at
    // build time. Runtime's layer 0 seeds `j` from the anti-debug
    // probe, which matches the build-time 0 on a clean host and
    // diverges on a debugged one.
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        Rc4State rc4{};
        rc4_init(rc4,
                 ByteView{layer_keys[layer].data(), layer_keys[layer].size()},
                 /*anti_debug_bias=*/0);
        for (const auto& tgt : encrypted) {
            auto& sec = ctx.pe_image().sections()[tgt.image_index];
            rc4_process(rc4,
                        MutableByteView{sec.data.data(), sec.data.size()});
        }
    }

    for (const auto& tgt : encrypted) {
        const auto& sec = ctx.pe_image().sections()[tgt.image_index];
        ctx.log_fmt("PackerPass: зашифрована (RC4 ×{}) '{}' (RVA=0x{:08X}, {} байт)",
            layer_count, sec.name, sec.virtual_address, tgt.size);
    }

    // Emit the stub via the policy-specified emitter.
    Emitter emitter{StubEmissionParams{
        .section_count = static_cast<uint32_t>(encrypted.size()),
        .layer_count   = layer_count,
    }};
    auto [stub_buf, patches] = emitter.emit(
        rng, ByteView{steal.stolen_bytes.data(), steal.stolen_bytes.size()});

    // Append each layer's 32-byte RC4 key to the stub buffer and
    // record the stub-relative offsets so each layer's `lea rsi, key_K`
    // rel32 can be patched after the stub section is injected.
    std::vector<uint32_t> key_offsets_in_stub(layer_count);
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        key_offsets_in_stub[layer] = static_cast<uint32_t>(stub_buf.size());
        stub_buf.insert(stub_buf.end(),
                        layer_keys[layer].begin(),
                        layer_keys[layer].end());
    }

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

    // ----------------------------------------------------------
    // P4 — TLS callback artefacts.
    //
    // Layout appended to the end of stub_buf (all inside the same
    // .mxpack section, so everything lives in one R+W+X page the
    // loader maps as one unit):
    //
    //     [callback body]           ~32 bytes
    //     [8-byte alignment pad]
    //     [IMAGE_TLS_DIRECTORY64]   40 bytes
    //     [8-byte alignment pad]
    //     [callback array]          (N+2) × 8 bytes, NULL terminated
    //     [optional index slot]     4 bytes, only if no existing TLS
    //
    // For inputs that already ship with a TLS directory (C++
    // programs with `__declspec(thread)` statics, for instance) we
    // parse the existing one first and preserve its fields —
    // StartAddressOfRawData / EndAddressOfRawData / AddressOfIndex /
    // SizeOfZeroFill / Characteristics — verbatim. Our new callback
    // prepends itself to the front of the existing callback array
    // so the anti-debug probe fires before any CRT-registered TLS
    // initialiser, and every original callback still runs in its
    // original order afterward.
    //
    // Everything past this point lives at a fixed offset inside
    // `stub_buf`; the runtime RVA of each slot is
    // `stub_rva + offset_in_stub_buf`. We record the offsets now
    // and back-patch them (along with the RC4-key rel32 inside the
    // callback body) after `finalize_packer_stub` has placed the
    // .mxpack section and we know `stub_rva`.
    const auto existing_tls_opt = read_existing_tls_directory(ctx.pe_image());

    // Align to 8 bytes before the callback body so every downstream
    // 8-byte field lands at a naturally-aligned offset.
    while (stub_buf.size() % 8 != 0) stub_buf.push_back(0xCC);

    const TlsCallbackEmit tls_cb = emit_tls_callback_body(stub_buf, rng, layer_count);

    while (stub_buf.size() % 8 != 0) stub_buf.push_back(0xCC);
    const uint32_t tls_dir_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), 40, uint8_t{0});  // IMAGE_TLS_DIRECTORY64

    while (stub_buf.size() % 8 != 0) stub_buf.push_back(0xCC);
    const uint32_t tls_cb_array_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    const size_t tls_cb_array_entries =
        (existing_tls_opt.has_value()
            ? existing_tls_opt->callbacks.size()
            : 0) + 2;  // +1 for our callback, +1 for the NULL terminator
    stub_buf.insert(stub_buf.end(), tls_cb_array_entries * 8, uint8_t{0});

    // Index slot — only needed when the input had no TLS directory
    // of its own. If an existing directory was found its
    // AddressOfIndex already points at a valid 4-byte slot in one
    // of the preserved input sections, so we reuse that.
    uint32_t tls_index_slot_offset_in_stub = 0;
    if (!existing_tls_opt.has_value()) {
        while (stub_buf.size() % 4 != 0) stub_buf.push_back(0xCC);
        tls_index_slot_offset_in_stub =
            static_cast<uint32_t>(stub_buf.size());
        stub_buf.insert(stub_buf.end(), 4, uint8_t{0});
    }

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

    // Per-layer patching: every layer has its own `lea rsi, key_K`
    // and its own per-section `lea rdi / mov ecx` pair.
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        const auto& lp = patches.layers[layer];

        // lea rsi, [rip + rel] → this layer's 32-byte RC4 key.
        {
            const Rva lea_end_rva = stub_rva + lp.rel_to_key_at + 4;
            const Rva key_rva     = stub_rva + key_offsets_in_stub[layer];
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, lp.rel_to_key_at, rel);
        }

        // Per-section: lea rdi → section base, mov ecx → section size.
        for (size_t i = 0; i < encrypted.size(); ++i) {
            const auto& ds  = lp.sections[i];
            const auto& tgt = encrypted[i];

            const Rva lea_end_rva = stub_rva + ds.patch_lea_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(tgt.rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(pack_sec.data, ds.patch_lea_at, rel);
            write_i32(pack_sec.data, ds.patch_size_at,
                      static_cast<int32_t>(tgt.size));
        }
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

    // ----------------------------------------------------------
    // P4 — TLS callback finalisation.
    //
    // At this point the .mxpack section has been placed at
    // `stub_rva` and every byte of stub_buf has been copied into
    // `pack_sec.data`. We can now compute the absolute VAs for our
    // TLS callback, the callback array, the TLS directory fields,
    // and the (optional) index slot, and patch them into the
    // section bytes. Finally we update `DataDirectory[TLS]` in the
    // PE header to point at the new directory.
    //
    // Absolute VAs are safe because the packer strips base
    // relocations at the very top of `execute_encrypted_stub`
    // (via `prepare_oep_steal` → `disable_relocations`), so the
    // runtime image base equals the build-time preferred base.
    {
        const auto image_base =
            static_cast<uint64_t>(ctx.pe_image().image_base());
        const uint64_t cb_body_va =
            image_base + stub_rva + tls_cb.body_offset;
        const uint64_t tls_dir_va =
            image_base + stub_rva + tls_dir_offset_in_stub;
        const uint64_t cb_array_va =
            image_base + stub_rva + tls_cb_array_offset_in_stub;

        // 1. Patch the `xor byte [rip + rel32], imm8` inside the
        //    callback body to point at one byte of a per-build
        //    random cipher layer's RC4 key. Corrupting ANY layer's
        //    key is sufficient to cascade: a wrong S-box for one
        //    layer produces a wrong PRGA output which means the
        //    other layers decrypt the intermediate bytes into
        //    garbage. Randomising the target layer per build
        //    denies reversers a stable pivot — extracting the
        //    corruption site from one binary tells them nothing
        //    about the next. The rel32 is computed from the end
        //    of the xor instruction (`xor_instruction_end`) to
        //    the target byte.
        const uint32_t key_target_offset_in_stub =
            key_offsets_in_stub[tls_cb.key_layer_index] +
            tls_cb.key_byte_offset_in_key;
        const int32_t xor_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(key_target_offset_in_stub) -
            static_cast<int64_t>(tls_cb.xor_instruction_end));
        write_i32(pack_sec.data, tls_cb.xor_key_rel32_offset, xor_rel32);

        // 2. Fill the callback array: our callback first, then
        //    every existing callback from the input TLS directory
        //    in its original order, then a NULL terminator.
        uint32_t write_off = tls_cb_array_offset_in_stub;
        write_u64_le(pack_sec.data, write_off, cb_body_va);
        write_off += 8;
        if (existing_tls_opt.has_value()) {
            for (const uint64_t old_cb : existing_tls_opt->callbacks) {
                write_u64_le(pack_sec.data, write_off, old_cb);
                write_off += 8;
            }
        }
        write_u64_le(pack_sec.data, write_off, 0);  // terminator

        // 3. Fill the TLS directory. Non-callback fields come from
        //    the existing directory when present, so C++
        //    `__declspec(thread)` data still works.
        uint64_t index_va = 0;
        uint64_t start_va = 0;
        uint64_t end_va   = 0;
        uint32_t zero_fill = 0;
        uint32_t characteristics = 0;
        if (existing_tls_opt.has_value()) {
            start_va        = existing_tls_opt->start_va;
            end_va          = existing_tls_opt->end_va;
            index_va        = existing_tls_opt->index_va;
            zero_fill       = existing_tls_opt->size_of_zero_fill;
            characteristics = existing_tls_opt->characteristics;
        } else {
            // No existing TLS — point AddressOfIndex at our own
            // 4-byte scratch slot inside .mxpack.
            index_va = image_base + stub_rva + tls_index_slot_offset_in_stub;
        }
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x00, start_va);
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x08, end_va);
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x10, index_va);
        write_u64_le(pack_sec.data, tls_dir_offset_in_stub + 0x18, cb_array_va);
        write_u32_le(pack_sec.data, tls_dir_offset_in_stub + 0x20, zero_fill);
        write_u32_le(pack_sec.data, tls_dir_offset_in_stub + 0x24, characteristics);

        // 4. Point the PE header's TLS data directory at our new
        //    in-.mxpack directory.
        const Rva tls_dir_rva =
            static_cast<Rva>(stub_rva + tls_dir_offset_in_stub);
        std::visit([&](auto& nt) {
            if (pe::IMAGE_DIRECTORY_ENTRY_TLS < nt.OptionalHeader.NumberOfRvaAndSizes) {
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
                    = tls_dir_rva;
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].Size
                    = 40;
            }
        }, ctx.pe_image().nt_headers());

        ctx.log_fmt("PackerPass: P4 TLS callback planted @ RVA=0x{:08X}, "
                    "chain length {} (existing={}, ours=1), "
                    "corrupts key[layer={}, byte={}]",
            stub_rva + tls_cb.body_offset,
            static_cast<uint32_t>(tls_cb_array_entries - 1),
            existing_tls_opt.has_value()
                ? static_cast<uint32_t>(existing_tls_opt->callbacks.size())
                : 0u,
            tls_cb.key_layer_index,
            tls_cb.key_byte_offset_in_key);
        (void)tls_dir_va;  // reserved for future use (direct self-reference)
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
