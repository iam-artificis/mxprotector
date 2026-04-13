/**
 * @file import_hook_check.cpp
 * @brief Anti-tamper probe — reads a critical NTDLL function prologue
 *        and verifies it hasn't been rewritten by an inline hook.
 *
 * EDR agents, Frida, Detours, and similar user-mode instrumentation
 * frameworks redirect sensitive NTDLL functions by overwriting their
 * first few instruction bytes with an unconditional branch to a
 * thunk. The thunk runs the hook's logic, optionally calls a saved
 * prologue trampoline, and returns — making the hooker's callbacks
 * transparent to any caller that invokes the export normally.
 *
 * The typical inline-hook opening sequences are:
 *
 *   * `E9 rel32`                     — short forward jmp (5 bytes)
 *   * `EB rel8; ...`                 — short jmp trampoline start
 *   * `48 B8 <imm64>; FF E0`         — mov rax, absolute; jmp rax
 *   * `FF 25 <rel32>`                — jmp [rip + rel32] indirect
 *
 * An unhooked ntdll syscall stub, by contrast, ALWAYS starts with
 * `4C 8B D1 B8` (mov r10, rcx; mov eax, ssn; ...). The first four
 * bytes are stable across every Windows build since Vista.
 *
 * This check picks a commonly-hooked function (`NtProtectVirtualMemory` —
 * virtually every EDR hooks it for memory-allocation monitoring),
 * walks the PEB to find ntdll, scans the export table by DJB2 hash
 * to locate the function, reads the first 4 bytes, and compares
 * them against the expected prologue. A mismatch indicates a hook
 * is installed; the check corrupts the handler-table key slot and
 * every subsequent VM dispatch crashes on a bad handler offset.
 *
 * Critically, we do NOT syscall `NtProtectVirtualMemory` — we just
 * probe its prologue. The syscall itself is irrelevant; its
 * presence in memory, unhooked, is what we're verifying. This
 * means the check works independent of the Hell's Gate SSN
 * resolver that the HW-breakpoint check depends on.
 *
 * ### Walker duplication
 *
 * The check emits its own PEB-walk + PE-parse + name-scan sequence
 * rather than sharing the Hell's Gate resolver's walker. The two
 * walkers do almost the same work but target different exports and
 * have different post-processing (Hell's Gate extracts an SSN,
 * this check validates a prologue). A future refactor may extract
 * a shared helper; for now the ~140 bytes of duplication keeps the
 * check self-contained and avoids touching the Hell's Gate code.
 *
 * ### Register usage
 *
 * Same discipline as the Hell's Gate resolver: all GPRs except r12
 * are fair game to clobber because they're already saved in the
 * VM-context slots from the entry stub's push sequence. The check
 * leaves no state behind — no register is expected to hold
 * anything meaningful after the final `xor [rsp + key_disp], eax`.
 */

#include "mxprotector/protection/anti_tamper/check.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

#include <memory>

namespace mx::anti_tamper {

namespace {

inline void patch_rel8(RawEmitter& e, size_t patch, size_t target) noexcept {
    const int delta = static_cast<int>(target) - static_cast<int>(patch + 1);
    e.buf[patch] = static_cast<uint8_t>(static_cast<int8_t>(delta));
}

} // anonymous namespace

class ImportHookDetectCheck final : public ICheck {
public:
    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng,
              const CheckContext& /*ctx*/) const override
    {
        // Per-build random corruption mask (non-zero).
        const uint32_t corruption = rng.next_u32() | 1u;

        // DJB2 hash of the target function name, computed at build
        // time so the literal name never appears in the blob.
        constexpr uint32_t kTargetHash =
            djb2_ascii_hash("NtProtectVirtualMemory");

        // --------------------------------------------------------
        // Walker — mirrors the Hell's Gate resolver's PEB walk and
        // export scan, except we extract the function address
        // (into rdi) instead of the SSN, and there's no prologue
        // validation step inside the walker (we do our own below).
        // --------------------------------------------------------

        // mov rax, gs:[0x60]                 65 48 8B 04 25 60 00 00 00
        e.u8(0x65); e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0x25);
        e.u8(0x60); e.u8(0x00); e.u8(0x00); e.u8(0x00);
        // mov rax, [rax + 0x18]              48 8B 40 18           ; PEB.Ldr
        e.u8(0x48); e.u8(0x8B); e.u8(0x40); e.u8(0x18);
        // lea rcx, [rax + 0x20]              48 8D 48 20           ; &InMemoryOrderModuleList
        e.u8(0x48); e.u8(0x8D); e.u8(0x48); e.u8(0x20);
        // mov rax, [rcx]                     48 8B 01              ; Flink → exe
        e.u8(0x48); e.u8(0x8B); e.u8(0x01);
        // mov rax, [rax]                     48 8B 00              ; Flink → ntdll
        e.u8(0x48); e.u8(0x8B); e.u8(0x00);
        // mov rbx, [rax + 0x20]              48 8B 58 20           ; rbx = ntdll DllBase
        e.u8(0x48); e.u8(0x8B); e.u8(0x58); e.u8(0x20);

        // mov eax, [rbx + 0x3C]              8B 43 3C              ; e_lfanew
        e.u8(0x8B); e.u8(0x43); e.u8(0x3C);
        // mov ecx, [rbx + rax + 0x88]        8B 8C 03 88 00 00 00  ; ExportRVA
        e.u8(0x8B); e.u8(0x8C); e.u8(0x03);
        e.u8(0x88); e.u8(0x00); e.u8(0x00); e.u8(0x00);
        // lea rdi, [rbx + rcx]               48 8D 3C 0B           ; export dir
        e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x0B);

        // mov ecx, [rdi + 0x18]              8B 4F 18              ; num_names
        e.u8(0x8B); e.u8(0x4F); e.u8(0x18);
        // mov eax, [rdi + 0x20]              8B 47 20
        e.u8(0x8B); e.u8(0x47); e.u8(0x20);
        // lea r8, [rbx + rax]                4C 8D 04 03           ; names table
        e.u8(0x4C); e.u8(0x8D); e.u8(0x04); e.u8(0x03);
        // mov eax, [rdi + 0x24]              8B 47 24
        e.u8(0x8B); e.u8(0x47); e.u8(0x24);
        // lea r9, [rbx + rax]                4C 8D 0C 03           ; ordinals table
        e.u8(0x4C); e.u8(0x8D); e.u8(0x0C); e.u8(0x03);
        // mov eax, [rdi + 0x1C]              8B 47 1C
        e.u8(0x8B); e.u8(0x47); e.u8(0x1C);
        // lea r10, [rbx + rax]               4C 8D 14 03           ; functions table
        e.u8(0x4C); e.u8(0x8D); e.u8(0x14); e.u8(0x03);

        // xor r11d, r11d                     45 31 DB              ; i = 0
        e.u8(0x45); e.u8(0x31); e.u8(0xDB);
        // xor edi, edi                       31 FF                 ; function addr = 0 (not found)
        e.u8(0x31); e.u8(0xFF);

        // .scan:
        const size_t label_scan = e.size();
        // cmp r11d, ecx                      41 39 CB
        e.u8(0x41); e.u8(0x39); e.u8(0xCB);
        // jae short .done                    73 rel8               ; all names exhausted
        e.u8(0x73);
        const size_t patch_jae_done = e.size();
        e.u8(0x00);

        // mov eax, [r8 + r11*4]              43 8B 04 98           ; name RVA
        e.u8(0x43); e.u8(0x8B); e.u8(0x04); e.u8(0x98);
        // lea rdx, [rbx + rax]               48 8D 14 03           ; rdx = name ptr
        e.u8(0x48); e.u8(0x8D); e.u8(0x14); e.u8(0x03);

        // mov eax, 5381                      B8 05 15 00 00        ; DJB2 init
        e.u8(0xB8); e.u8(0x05); e.u8(0x15); e.u8(0x00); e.u8(0x00);

        // .hash_loop:
        const size_t label_hash_loop = e.size();
        // movzx r14d, byte [rdx]             44 0F B6 32
        e.u8(0x44); e.u8(0x0F); e.u8(0xB6); e.u8(0x32);
        // test r14b, r14b                    45 84 F6
        e.u8(0x45); e.u8(0x84); e.u8(0xF6);
        // jz short .hash_done                74 rel8
        e.u8(0x74);
        const size_t patch_jz_hash_done = e.size();
        e.u8(0x00);
        // mov r15d, eax                      41 89 C7
        e.u8(0x41); e.u8(0x89); e.u8(0xC7);
        // shl eax, 5                         C1 E0 05
        e.u8(0xC1); e.u8(0xE0); e.u8(0x05);
        // add eax, r15d                      44 01 F8              ; h *= 33
        e.u8(0x44); e.u8(0x01); e.u8(0xF8);
        // add eax, r14d                      44 01 F0              ; h += c
        e.u8(0x44); e.u8(0x01); e.u8(0xF0);
        // inc rdx                            48 FF C2
        e.u8(0x48); e.u8(0xFF); e.u8(0xC2);
        // jmp short .hash_loop               EB rel8
        e.u8(0xEB);
        {
            const size_t patch = e.size();
            e.u8(0x00);
            patch_rel8(e, patch, label_hash_loop);
        }

        // .hash_done:
        const size_t label_hash_done = e.size();
        patch_rel8(e, patch_jz_hash_done, label_hash_done);

        // cmp eax, <kTargetHash>             3D imm32
        e.u8(0x3D);
        e.u32(kTargetHash);
        // jne short .next                    75 rel8
        e.u8(0x75);
        const size_t patch_jne_next = e.size();
        e.u8(0x00);

        // --- match: resolve function address into rdi ---
        // movzx eax, word [r9 + r11*2]       43 0F B7 04 59        ; ordinal
        e.u8(0x43); e.u8(0x0F); e.u8(0xB7); e.u8(0x04); e.u8(0x59);
        // mov eax, [r10 + rax*4]             41 8B 04 82           ; func RVA
        e.u8(0x41); e.u8(0x8B); e.u8(0x04); e.u8(0x82);
        // lea rdi, [rbx + rax]               48 8D 3C 03           ; rdi = func start
        e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x03);
        // jmp short .done                    EB rel8
        e.u8(0xEB);
        const size_t patch_jmp_done_match = e.size();
        e.u8(0x00);

        // .next:
        const size_t label_next = e.size();
        patch_rel8(e, patch_jne_next, label_next);
        // inc r11                            49 FF C3
        e.u8(0x49); e.u8(0xFF); e.u8(0xC3);
        // jmp short .scan                    EB rel8
        e.u8(0xEB);
        {
            const size_t patch = e.size();
            e.u8(0x00);
            patch_rel8(e, patch, label_scan);
        }

        // .done:
        const size_t label_done = e.size();
        patch_rel8(e, patch_jae_done, label_done);
        patch_rel8(e, patch_jmp_done_match, label_done);

        // --------------------------------------------------------
        // Prologue check + key corruption.
        //
        // rdi = function address (or 0 if not found).
        // ----
        // If rdi == 0 → clean (function missing, treat as OK; do not
        //               raise a false positive on non-standard ntdll).
        // If dword [rdi] == 0xB8D18B4C → clean (prologue intact).
        // Otherwise → corruption mask into key slot.
        // --------------------------------------------------------

        // xor eax, eax                       31 C0                 ; assume clean
        e.u8(0x31); e.u8(0xC0);

        // test rdi, rdi                      48 85 FF
        e.u8(0x48); e.u8(0x85); e.u8(0xFF);
        // jz short .apply                    74 rel8               ; function missing → clean
        e.u8(0x74);
        const size_t patch_jz_apply_missing = e.size();
        e.u8(0x00);

        // cmp dword [rdi], 0xB8D18B4C        81 3F 4C 8B D1 B8
        e.u8(0x81); e.u8(0x3F);
        e.u8(0x4C); e.u8(0x8B); e.u8(0xD1); e.u8(0xB8);
        // je short .apply                    74 rel8               ; prologue OK → clean
        e.u8(0x74);
        const size_t patch_je_apply_ok = e.size();
        e.u8(0x00);

        // Prologue tampered → load corruption mask.
        // mov eax, <corruption>              B8 imm32
        e.u8(0xB8);
        e.u32(corruption);

        // .apply:
        const size_t label_apply = e.size();
        patch_rel8(e, patch_jz_apply_missing, label_apply);
        patch_rel8(e, patch_je_apply_ok,      label_apply);

        // xor [rsp + disp8], eax             31 44 24 disp8
        e.u8(0x31); e.u8(0x44); e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "import_hook_detect";
    }
};

std::unique_ptr<ICheck> make_import_hook_detect_check() {
    return std::make_unique<ImportHookDetectCheck>();
}

} // namespace mx::anti_tamper
