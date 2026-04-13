/**
 * @file syscall_resolver.cpp
 * @brief [BUILDER] SSN resolver via manual PEB walk — no Win32 API.
 *
 * Previously this file used `GetModuleHandleA` + `GetProcAddress` to
 * reach ntdll. That was simple but had two problems:
 *
 *   1. It made the builder itself rely on the Win32 loader / export
 *      resolver. Any user-mode hook on either function (e.g. an EDR
 *      running inside the builder's process, a sandboxed dev VM with
 *      an API-monitor helper, or a corrupted ntdll cache) could feed
 *      the resolver bogus bytes and the extracted SSN would be
 *      silently wrong — leading the protected binary to
 *      `syscall` a completely unrelated service at runtime.
 *
 *   2. It leaked the dependency on `<Windows.h>` into the builder
 *      object files. The anti-tamper checks are supposed to bypass
 *      user-mode hooks; having the thing that generates them go
 *      through the exact chokepoint we're trying to avoid was
 *      inelegant.
 *
 * This implementation walks the Process Environment Block (PEB)
 * directly. It locates ntdll by name in the in-memory module list,
 * parses its PE headers to reach the export directory, and looks
 * up the target function by ASCII name — all via ordinary pointer
 * dereferences. The only OS-level primitive used is the compiler
 * intrinsic `__readgsqword(0x60)`, which the MSVC x64 compiler
 * lowers to a single `mov rax, gs:[0x60]` — no DLL boundary, no
 * Win32 call, no hookable surface.
 *
 * The returned SSN still has the same semantics: ≥ 1 on success,
 * 0 on any failure (unknown function, unexpected prologue, etc.).
 *
 * This implementation has only been tested on x86-64 Windows. On
 * Linux / macOS builders it short-circuits to 0 because PEB/NTDLL
 * do not exist.
 */

#include "mxprotector/protection/anti_tamper/syscall_resolver.hpp"

#if defined(_WIN32) && defined(_M_X64)
#  include <intrin.h>   // __readgsqword — compiler intrinsic, not Win32
#  include <cstdint>
#  include <cstddef>
#endif

namespace mx::anti_tamper {

#if defined(_WIN32) && defined(_M_X64)

namespace {

// ----------------------------------------------------------------------------
// Minimal NT type definitions — carved out of winternl.h / ntdef.h
//
// We intentionally don't `#include <Windows.h>` or `<winternl.h>` here:
//
//   * Avoids pulling in the entire Win32 API surface for three structs
//     we need.
//   * Makes the offset discipline explicit — any developer auditing
//     this file can verify the layout against ReactOS / public NT
//     documentation without chasing MS headers.
//   * Self-contained: the structs carry nothing we don't actually
//     touch. Unused PEB / LDR fields are represented as byte padding.
//
// Layouts are stable across every 64-bit Windows release since Vista.
// ----------------------------------------------------------------------------

struct ListEntry {
    ListEntry* Flink;
    ListEntry* Blink;
};
static_assert(sizeof(ListEntry) == 0x10, "ListEntry must be 16 bytes");

struct UnicodeString {
    uint16_t  Length;         // in bytes (NOT characters)
    uint16_t  MaximumLength;
    uint32_t  _pad;           // natural alignment of Buffer on x64
    wchar_t*  Buffer;
};
static_assert(sizeof(UnicodeString) == 0x10, "UnicodeString must be 16 bytes");

// We only need `Ldr` from PEB. It lives at offset 0x18 on x64.
struct PebMin {
    uint8_t     _skip_00[0x18];
    void*       Ldr;            // PEB_LDR_DATA*
};
static_assert(offsetof(PebMin, Ldr) == 0x18, "PEB.Ldr must be at 0x18");

// Only the InMemoryOrderModuleList head matters — it's the list we walk.
// It lives at offset 0x20 in PEB_LDR_DATA on x64.
struct PebLdrDataMin {
    uint8_t     _skip_00[0x20];
    ListEntry   InMemoryOrderModuleList;   // offset 0x20
};
static_assert(offsetof(PebLdrDataMin, InMemoryOrderModuleList) == 0x20,
              "PEB_LDR_DATA.InMemoryOrderModuleList must be at 0x20");

// LDR_DATA_TABLE_ENTRY — we need DllBase and BaseDllName. InMemoryOrderLinks
// is the list node the walk visits; LDR entry start is at -0x10 from it.
struct LdrDataTableEntry {
    ListEntry      InLoadOrderLinks;           // 0x00
    ListEntry      InMemoryOrderLinks;         // 0x10
    ListEntry      InInitializationOrderLinks; // 0x20
    void*          DllBase;                    // 0x30
    void*          EntryPoint;                 // 0x38
    uint32_t       SizeOfImage;                // 0x40
    uint32_t       _pad_44;
    UnicodeString  FullDllName;                // 0x48
    UnicodeString  BaseDllName;                // 0x58
};
static_assert(offsetof(LdrDataTableEntry, DllBase) == 0x30, "DllBase offset");
static_assert(offsetof(LdrDataTableEntry, BaseDllName) == 0x58, "BaseDllName offset");

// ----------------------------------------------------------------------------
// Case-insensitive UTF-16 ↔ ASCII comparison
//
// Windows keeps module names with their original casing ("ntdll.dll"),
// but nothing in the NT loader contract guarantees that. We lower-case
// both sides and compare byte-wise.
// ----------------------------------------------------------------------------

[[nodiscard]] constexpr wchar_t to_lower_wide(wchar_t c) noexcept {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

[[nodiscard]] constexpr char to_lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

/// True iff the wide string `wide[0..wide_len_chars)` is case-insensitively
/// equal to the null-terminated ASCII string `ascii`.
[[nodiscard]] bool wide_ieq_ascii(const wchar_t* wide,
                                   size_t wide_len_chars,
                                   const char* ascii) noexcept
{
    size_t i = 0;
    for (; i < wide_len_chars && ascii[i] != '\0'; ++i) {
        const wchar_t a = to_lower_wide(wide[i]);
        const wchar_t b = static_cast<wchar_t>(to_lower_ascii(ascii[i]));
        if (a != b) return false;
    }
    return i == wide_len_chars && ascii[i] == '\0';
}

/// True iff the two null-terminated ASCII strings are byte-wise equal.
/// Case-sensitive — NTDLL export names are all upper-camelCase and we
/// look them up with exact-case names.
[[nodiscard]] bool ascii_eq(const char* a, const char* b) noexcept {
    for (size_t i = 0; ; ++i) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') return true;
    }
}

// ----------------------------------------------------------------------------
// Module walk
// ----------------------------------------------------------------------------

/// Return the base address of the module whose BaseDllName
/// case-insensitively matches `name`, or nullptr if not found.
[[nodiscard]] void* find_module_base(const char* name) noexcept {
    // PEB = gs:[0x60]. The intrinsic compiles to a single mov.
    auto* peb = reinterpret_cast<PebMin*>(__readgsqword(0x60));
    if (peb == nullptr || peb->Ldr == nullptr) return nullptr;

    auto* ldr = static_cast<PebLdrDataMin*>(peb->Ldr);

    // Circular doubly-linked list. The head is the LIST_ENTRY inside
    // PEB_LDR_DATA itself; each real entry's InMemoryOrderLinks node
    // lives at offset 0x10 inside an LDR_DATA_TABLE_ENTRY, so from a
    // list node pointer we subtract 0x10 to reach the entry start.
    ListEntry* head = &ldr->InMemoryOrderModuleList;
    for (ListEntry* cur = head->Flink; cur != head; cur = cur->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntry*>(
            reinterpret_cast<uint8_t*>(cur) - 0x10);

        const UnicodeString& base_name = entry->BaseDllName;
        if (base_name.Buffer == nullptr || base_name.Length == 0) continue;

        const size_t chars = static_cast<size_t>(base_name.Length) / sizeof(wchar_t);
        if (wide_ieq_ascii(base_name.Buffer, chars, name)) {
            return entry->DllBase;
        }
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
// PE export table parse
// ----------------------------------------------------------------------------

/// Read a little-endian uint32 from an unaligned pointer. Avoids UB
/// from reinterpret_cast on unaligned addresses in strict modes.
[[nodiscard]] uint32_t read_u32_le(const uint8_t* p) noexcept {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

/// Find the address of `function_name` in the export table of the PE
/// image based at `dll_base`. Returns nullptr if the name is missing
/// or the export directory is malformed.
///
/// We walk the name table linearly — ntdll has ~2400 exports so the
/// scan is O(2400) per resolution. That's one-time-at-startup cost in
/// the builder; not worth binary-searching.
[[nodiscard]] const uint8_t* find_export(void* dll_base,
                                          const char* function_name) noexcept
{
    const auto* base = static_cast<const uint8_t*>(dll_base);

    // DOS header — only `e_lfanew` at offset 0x3C matters.
    const uint32_t e_lfanew = read_u32_le(base + 0x3C);
    const uint8_t* nt = base + e_lfanew;

    // NT headers layout on x64:
    //   nt + 0x00 : "PE\0\0" signature (DWORD)
    //   nt + 0x04 : IMAGE_FILE_HEADER (20 bytes)
    //   nt + 0x18 : IMAGE_OPTIONAL_HEADER64 start
    //     ... + 0x70 (offset 0x88 from nt) : DataDirectory[0] (Export)
    //         + 0x00 : VirtualAddress (RVA) — this is ExportRVA
    //         + 0x04 : Size
    const uint32_t export_rva  = read_u32_le(nt + 0x88);
    const uint32_t export_size = read_u32_le(nt + 0x8C);
    (void)export_size;  // unused — we trust ntdll is well-formed
    if (export_rva == 0) return nullptr;

    const uint8_t* exp = base + export_rva;
    // IMAGE_EXPORT_DIRECTORY:
    //   0x14 NumberOfFunctions  (DWORD)
    //   0x18 NumberOfNames      (DWORD)
    //   0x1C AddressOfFunctions (RVA → DWORD[])
    //   0x20 AddressOfNames     (RVA → DWORD[])
    //   0x24 AddressOfNameOrdinals (RVA → WORD[])
    const uint32_t num_names     = read_u32_le(exp + 0x18);
    const uint32_t funcs_rva     = read_u32_le(exp + 0x1C);
    const uint32_t names_rva     = read_u32_le(exp + 0x20);
    const uint32_t ordinals_rva  = read_u32_le(exp + 0x24);
    if (num_names == 0) return nullptr;

    const uint8_t*  funcs_table    = base + funcs_rva;
    const uint8_t*  names_table    = base + names_rva;
    const uint8_t*  ordinals_table = base + ordinals_rva;

    for (uint32_t i = 0; i < num_names; ++i) {
        const uint32_t name_rva = read_u32_le(names_table + i * 4);
        const auto* name_ptr = reinterpret_cast<const char*>(base + name_rva);
        if (!ascii_eq(name_ptr, function_name)) continue;

        // Ordinal table is WORD[] — 2 bytes per entry.
        const uint16_t ord = static_cast<uint16_t>(
            ordinals_table[i * 2]
          | (static_cast<uint16_t>(ordinals_table[i * 2 + 1]) << 8));

        const uint32_t func_rva = read_u32_le(funcs_table + ord * 4);
        return base + func_rva;
    }
    return nullptr;
}

} // anonymous namespace

uint32_t SyscallResolver::resolve(const char* function_name) const noexcept {
    if (function_name == nullptr) return 0;

    void* ntdll_base = find_module_base("ntdll.dll");
    if (ntdll_base == nullptr) return 0;

    const uint8_t* func = find_export(ntdll_base, function_name);
    if (func == nullptr) return 0;

    // Validate the syscall-stub prologue:
    //   4C 8B D1                 mov r10, rcx
    //   B8 ?? ?? ?? ??           mov eax, ssn
    //   ...
    // Anything else means the export was hooked (jmp/call rel32, mov
    // rax imm64, etc.) or points at a forwarded/non-syscall function.
    // Either way we refuse rather than extract a bogus SSN.
    if (func[0] != 0x4C || func[1] != 0x8B
     || func[2] != 0xD1 || func[3] != 0xB8)
    {
        return 0;
    }

    const uint32_t ssn = read_u32_le(func + 4);

    // Sanity bound: SSNs on modern Windows are well under 0x1000.
    // An SSN above 0xFFFF means the bytes we read were not the SSN
    // immediate at all.
    if (ssn > 0xFFFFu) return 0;
    return ssn;
}

#else   // !(_WIN32 && _M_X64)

uint32_t SyscallResolver::resolve(const char* function_name) const noexcept {
    (void)function_name;
    return 0;  // Non-Windows or non-x64 builder: anti-tamper is disabled.
}

#endif

} // namespace mx::anti_tamper
