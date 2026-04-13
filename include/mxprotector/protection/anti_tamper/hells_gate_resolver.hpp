/**
 * @file hells_gate_resolver.hpp
 * @brief [BUILDER] Emits a runtime Hell's Gate SSN resolver into the
 *        protected binary's entry stub.
 *
 * ### The problem
 *
 * System Service Numbers (SSNs) — the integer the kernel reads from
 * `eax` at a `syscall` boundary — change between Windows builds.
 * An anti-tamper check that bakes an SSN at build time only works
 * when the protected binary runs on a Windows build whose ntdll
 * numbers the syscalls the same way as the builder host. Major
 * Windows feature updates routinely renumber syscalls, so a binary
 * built on Win11 24H2 and shipped to Win10 21H2 will `syscall` the
 * wrong service, triggering `STATUS_INVALID_SYSTEM_SERVICE` or
 * worse, executing an unrelated kernel routine.
 *
 * ### The fix
 *
 * This file emits a self-contained SSN resolver directly into the
 * VM entry stub. At runtime, the protected binary walks its own
 * Process Environment Block, parses ntdll's PE headers, iterates
 * the export name table, hashes each name and compares to a
 * build-time-computed DJB2 hash, then extracts the SSN from the
 * matching function's prologue. The resolved SSN lands in `r13`
 * and the HW-breakpoint check (and any future syscall-based check)
 * reads its SSN from `r13d` instead of a hard-coded imm32.
 *
 * The resolver runs once per region, right before the anti-tamper
 * loop. Its runtime cost is a few hundred cycles — a PEB pointer
 * read, two LIST_ENTRY dereferences, a handful of PE header reads,
 * and a DJB2 scan of ~2400 ntdll exports. Negligible compared to
 * the syscall that follows.
 *
 * ### Why DJB2
 *
 * The alternative is `memcmp` against the literal function name
 * ("NtGetContextThread"). That would put the plaintext name in the
 * VM blob, where `strings binary.exe` trivially lists it — not
 * helpful when the whole point of the check is to hide from
 * reverse engineers what NTDLL functions the protection uses.
 * DJB2 is a 32-bit hash, stored as one `cmp eax, imm32`, which is
 * indistinguishable from any other constant comparison in the
 * code.
 *
 * DJB2 is case-sensitive. NTDLL export names are stable — always
 * "NtGetContextThread", never "NTGetContextThread" or any other
 * casing — so this is safe.
 *
 * ### The "2nd module" shortcut
 *
 * Windows has loaded ntdll as the second entry in
 * `PEB.Ldr.InMemoryOrderModuleList` on every NT version since XP
 * (the first entry is the main executable). Walking the list
 * looking for "ntdll.dll" by name is more robust but adds another
 * ~40 bytes of emission. For mainstream Windows this simpler
 * path is correct; if it ever needs to handle exotic loader
 * configurations (shim engine, detours-style pre-loaded helpers),
 * switch to a name-scan loop.
 *
 * ### Register discipline
 *
 * The emitted resolver clobbers:
 *   - `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi` — scratch pointers
 *   - `r8`, `r9`, `r10` — PE table base pointers
 *   - `r11`, `r14`, `r15` — loop counter and hash scratch
 *
 * And sets:
 *   - `r13d` — resolved SSN, or 0 on any failure path
 *
 * Every clobbered register already lives in its VM-context slot
 * from the entry stub's push sequence, so there's nothing to save
 * or restore. `r12` is left untouched because the HW-breakpoint
 * check uses it as its saved-rsp register.
 *
 * After the resolver runs, the next thing the entry stub emits is
 * the anti-tamper check that consumes `r13`. Nothing between the
 * resolver and the check modifies `r13`, so the SSN stays live
 * where the check expects it.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"

namespace mx::anti_tamper {

/// Compile-time DJB2 hash over a null-terminated ASCII string.
/// Used both to compute the build-time hash constants that are
/// baked into the resolver and to mirror exactly what the runtime
/// code does — if the two implementations disagree the lookup
/// silently fails.
[[nodiscard]] constexpr uint32_t djb2_ascii_hash(const char* s) noexcept {
    uint32_t h = 5381u;
    while (*s != '\0') {
        h = h * 33u
          + static_cast<uint32_t>(static_cast<unsigned char>(*s));
        ++s;
    }
    return h;
}

/// Emit the runtime Hell's Gate SSN resolver.
///
/// The emitted code walks the PEB, finds ntdll (assuming it is the
/// second entry in `InMemoryOrderModuleList`, which is true on all
/// mainstream Windows versions), parses its PE export table, and
/// looks up the function whose DJB2 hash matches `target_name_hash`.
/// On success the resolved SSN is placed in `r13d`; on any failure
/// (export directory missing, name not found, prologue mismatch)
/// `r13d` is left at 0.
///
/// The caller is responsible for computing `target_name_hash` at
/// build time via `djb2_ascii_hash(...)` — the literal ASCII name
/// never appears in the emitted code.
void emit_hells_gate_resolver(RawEmitter& e, uint32_t target_name_hash);

} // namespace mx::anti_tamper
