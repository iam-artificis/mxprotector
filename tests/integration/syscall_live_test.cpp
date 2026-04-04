/**
 * @file syscall_live_test.cpp
 * @brief [INTEGRATION] Live-тест indirect syscall: NtProtectVirtualMemory через gate.asm.
 *
 * @details Standalone интеграционный тест для верификации полной цепочки:
 *          1. get_peb() — получение PEB из ASM
 *          2. Hell's Gate — извлечение SSN из ntdll
 *          3. Поиск `syscall; ret` гаджета в ntdll
 *          4. indirect_syscall → NtProtectVirtualMemory (5 Nt-аргументов)
 *          5. Проверка через VirtualQuery, что защита реально изменилась
 *          6. Обратная смена защиты (валидация стабильности)
 *
 *          Этот тест линкуется с gate.asm напрямую. Он НЕ зависит от
 *          GoogleTest и может компилироваться standalone:
 *
 *            ml64 /c /nologo gate.asm /Fo gate.obj
 *            cl /std:c++20 /EHsc /W4 syscall_live_test.cpp gate.obj /Fe:syscall_test.exe
 *
 *          Или через CMake с MXPROTECTOR_BUILD_INTEGRATION_TESTS=ON.
 *
 * @note Требует: Windows x64, MSVC, MASM (ml64). Только MSVC x64 target.
 *       Тест пишет диагностику в stdout и возвращает 0 при успехе.
 */

#ifdef _WIN64

#include <cstdint>
#include <cstdio>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

// ============================================================================
// Внешние функции из gate.asm
// ============================================================================

extern "C" uint64_t indirect_syscall(
    uint32_t ssn,          // ECX -> EAX
    uint64_t syscall_addr, // RDX -> R11
    uint64_t arg1,         // R8  -> R10
    uint64_t arg2,         // R9  -> RDX
    uint64_t arg3,         // [RSP+28h] -> R8
    uint64_t arg4,         // [RSP+30h] -> R9
    uint64_t arg5);        // [RSP+38h] -> [RSP+28h] (сдвигается)

extern "C" void* get_peb();

// ============================================================================
// Структуры PE для парсинга ntdll
// ============================================================================

#pragma pack(push, 1)
struct MiniDosHdr   { uint16_t e_magic; uint8_t pad[58]; int32_t e_lfanew; };
struct MiniFileHdr  { uint16_t Machine; uint16_t NumberOfSections;
                      uint32_t TimeDateStamp; uint32_t PointerToSymbolTable;
                      uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader;
                      uint16_t Characteristics; };
struct MiniDataDir  { uint32_t VirtualAddress; uint32_t Size; };
struct MiniOptHdr64 {
    uint16_t Magic; uint8_t pad1[14];
    uint32_t AddressOfEntryPoint; uint32_t BaseOfCode;
    uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment;
    uint8_t pad2[16]; uint32_t SizeOfImage; uint32_t SizeOfHeaders;
    uint8_t pad3[8]; uint64_t pad4[4]; uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes; MiniDataDir DataDirectory[16];
};
struct MiniNtHdr64  { uint32_t Signature; MiniFileHdr FileHeader; MiniOptHdr64 OptionalHeader; };
struct MiniSecHdr   { uint8_t Name[8]; uint32_t VirtualSize; uint32_t VirtualAddress;
                      uint32_t SizeOfRawData; uint32_t PointerToRawData;
                      uint8_t pad[12]; uint32_t Characteristics; };
#pragma pack(pop)

// ============================================================================
// Утилиты
// ============================================================================

namespace {

constexpr const char* PASS = "[PASS]";
constexpr const char* FAIL = "[FAIL]";

int g_tests_total = 0;
int g_tests_passed = 0;

void check(bool condition, const char* name, const char* detail = nullptr) {
    ++g_tests_total;
    if (condition) {
        ++g_tests_passed;
        std::printf("  %s %s", PASS, name);
    } else {
        std::printf("  %s %s", FAIL, name);
    }
    if (detail) std::printf(" (%s)", detail);
    std::printf("\n");
}

/// @brief Hell's Gate: извлекает SSN из стандартного Nt*-пролога.
bool extract_ssn(const uint8_t* func, uint32_t& ssn) {
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
        std::memcpy(&ssn, func + 4, sizeof(uint32_t));
        return true;
    }
    return false;
}

/// @brief Поиск `syscall; ret` (0F 05 C3) в .text секции ntdll.
uint64_t find_syscall_ret_in_ntdll(const uint8_t* ntdll_base) {
    const auto* dos = reinterpret_cast<const MiniDosHdr*>(ntdll_base);
    if (dos->e_magic != 0x5A4D) return 0;

    const auto* nt = reinterpret_cast<const MiniNtHdr64*>(ntdll_base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    const auto* sections = reinterpret_cast<const MiniSecHdr*>(
        reinterpret_cast<const uint8_t*>(&nt->OptionalHeader) +
        nt->FileHeader.SizeOfOptionalHeader);

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sections[i].Name[0] == '.' && sections[i].Name[1] == 't' &&
            sections[i].Name[2] == 'e' && sections[i].Name[3] == 'x' &&
            sections[i].Name[4] == 't')
        {
            const auto* text = ntdll_base + sections[i].VirtualAddress;
            const uint32_t text_size = sections[i].VirtualSize;

            for (uint32_t j = 0; j + 2 < text_size; ++j) {
                if (text[j] == 0x0F && text[j + 1] == 0x05 && text[j + 2] == 0xC3) {
                    return reinterpret_cast<uint64_t>(text + j);
                }
            }
        }
    }
    return 0;
}

} // anonymous namespace

// ============================================================================
// Тесты
// ============================================================================

int main() {
    std::printf("=== MxProtector Syscall Engine Integration Test ===\n");
    std::printf("Platform: Windows x64, MSVC\n\n");

    // -----------------------------------------------------------------------
    // Test 1: get_peb()
    // -----------------------------------------------------------------------
    std::printf("[Test 1] get_peb()\n");
    {
        void* peb = get_peb();
        char detail[64];
        std::snprintf(detail, sizeof(detail), "PEB = %p", peb);
        check(peb != nullptr, "PEB is non-null", detail);

        // PEB->ImageBaseAddress (offset 0x10) должен указывать на наш .exe
        if (peb) {
            auto* peb_bytes = static_cast<const uint8_t*>(peb);
            uint64_t image_base = 0;
            std::memcpy(&image_base, peb_bytes + 0x10, sizeof(uint64_t));

            const auto* dos = reinterpret_cast<const MiniDosHdr*>(image_base);
            check(dos->e_magic == 0x5A4D, "PEB->ImageBase has valid MZ signature");
        }
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 2: Hell's Gate — SSN extraction
    // -----------------------------------------------------------------------
    std::printf("[Test 2] Hell's Gate SSN extraction\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    check(ntdll != nullptr, "ntdll.dll loaded");

    auto* nt_protect_raw = reinterpret_cast<const uint8_t*>(
        GetProcAddress(ntdll, "NtProtectVirtualMemory"));
    check(nt_protect_raw != nullptr, "NtProtectVirtualMemory found");

    uint32_t ssn = 0;
    bool ssn_extracted = extract_ssn(nt_protect_raw, ssn);
    {
        char detail[64];
        std::snprintf(detail, sizeof(detail), "SSN = 0x%X", ssn);
        check(ssn_extracted, "SSN extracted via Hell's Gate", detail);
    }

    if (!ssn_extracted) {
        std::printf("\n  Function may be hooked (EDR/AV). Dumping first 8 bytes:\n  ");
        for (int i = 0; i < 8; ++i) std::printf("%02X ", nt_protect_raw[i]);
        std::printf("\n\n  Cannot continue without SSN. Aborting.\n");
        return 1;
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 3: syscall;ret gadget search
    // -----------------------------------------------------------------------
    std::printf("[Test 3] syscall;ret gadget search in ntdll .text\n");

    auto* ntdll_base = reinterpret_cast<const uint8_t*>(ntdll);
    uint64_t syscall_addr = find_syscall_ret_in_ntdll(ntdll_base);
    {
        char detail[64];
        std::snprintf(detail, sizeof(detail), "addr = 0x%llX", syscall_addr);
        check(syscall_addr != 0, "syscall;ret gadget found", detail);
    }

    if (syscall_addr == 0) {
        std::printf("  Cannot continue without syscall gadget. Aborting.\n");
        return 1;
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 4: NtProtectVirtualMemory — PAGE_READWRITE -> PAGE_EXECUTE_READ
    // -----------------------------------------------------------------------
    std::printf("[Test 4] indirect_syscall -> NtProtectVirtualMemory (5 Nt args)\n");

    void* test_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    check(test_mem != nullptr, "VirtualAlloc succeeded");

    if (!test_mem) {
        std::printf("  Cannot continue without allocated memory. Aborting.\n");
        return 1;
    }

    // Верификация начального состояния
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(test_mem, &mbi, sizeof(mbi));
    check(mbi.Protect == PAGE_READWRITE, "Initial protection is PAGE_READWRITE (0x04)");

    // Вызов NtProtectVirtualMemory через indirect_syscall
    void*  base_addr   = test_mem;
    SIZE_T region_size  = 4096;
    ULONG  old_protect  = 0;

    uint64_t status = indirect_syscall(
        ssn, syscall_addr,
        static_cast<uint64_t>(~static_cast<uint64_t>(0)),   // ProcessHandle = -1 (current)
        reinterpret_cast<uint64_t>(&base_addr),              // &BaseAddress
        reinterpret_cast<uint64_t>(&region_size),            // &RegionSize
        static_cast<uint64_t>(PAGE_EXECUTE_READ),            // NewProtect (4th Nt arg)
        reinterpret_cast<uint64_t>(&old_protect));           // &OldProtect (5th Nt arg)

    {
        char detail[128];
        std::snprintf(detail, sizeof(detail),
            "NTSTATUS=0x%08llX, OldProtect=0x%lX", status, old_protect);
        check(status == 0, "NtProtectVirtualMemory returned STATUS_SUCCESS", detail);
    }
    check(old_protect == PAGE_READWRITE,
        "OldProtect == PAGE_READWRITE (0x04)");

    // Верификация через VirtualQuery
    VirtualQuery(test_mem, &mbi, sizeof(mbi));
    {
        char detail[64];
        std::snprintf(detail, sizeof(detail), "actual = 0x%lX", mbi.Protect);
        check(mbi.Protect == PAGE_EXECUTE_READ,
            "VirtualQuery confirms PAGE_EXECUTE_READ (0x20)", detail);
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 5: Обратная смена — PAGE_EXECUTE_READ -> PAGE_READWRITE
    // -----------------------------------------------------------------------
    std::printf("[Test 5] Reverse: PAGE_EXECUTE_READ -> PAGE_READWRITE\n");

    base_addr   = test_mem;
    region_size = 4096;
    old_protect = 0;

    status = indirect_syscall(
        ssn, syscall_addr,
        static_cast<uint64_t>(~static_cast<uint64_t>(0)),
        reinterpret_cast<uint64_t>(&base_addr),
        reinterpret_cast<uint64_t>(&region_size),
        static_cast<uint64_t>(PAGE_READWRITE),
        reinterpret_cast<uint64_t>(&old_protect));

    check(status == 0, "NtProtectVirtualMemory returned STATUS_SUCCESS");
    check(old_protect == PAGE_EXECUTE_READ,
        "OldProtect == PAGE_EXECUTE_READ (0x20)");

    VirtualQuery(test_mem, &mbi, sizeof(mbi));
    check(mbi.Protect == PAGE_READWRITE,
        "VirtualQuery confirms PAGE_READWRITE (0x04)");
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 6: Ещё одна смена — PAGE_READWRITE -> PAGE_READONLY
    // -----------------------------------------------------------------------
    std::printf("[Test 6] PAGE_READWRITE -> PAGE_READONLY\n");

    base_addr   = test_mem;
    region_size = 4096;
    old_protect = 0;

    status = indirect_syscall(
        ssn, syscall_addr,
        static_cast<uint64_t>(~static_cast<uint64_t>(0)),
        reinterpret_cast<uint64_t>(&base_addr),
        reinterpret_cast<uint64_t>(&region_size),
        static_cast<uint64_t>(PAGE_READONLY),
        reinterpret_cast<uint64_t>(&old_protect));

    check(status == 0, "NtProtectVirtualMemory returned STATUS_SUCCESS");
    check(old_protect == PAGE_READWRITE,
        "OldProtect == PAGE_READWRITE (0x04)");

    VirtualQuery(test_mem, &mbi, sizeof(mbi));
    check(mbi.Protect == PAGE_READONLY,
        "VirtualQuery confirms PAGE_READONLY (0x02)");
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 7: Проверка PAGE_GUARD (если поддерживается)
    // -----------------------------------------------------------------------
    std::printf("[Test 7] PAGE_GUARD trap setup\n");

    base_addr   = test_mem;
    region_size = 4096;
    old_protect = 0;

    status = indirect_syscall(
        ssn, syscall_addr,
        static_cast<uint64_t>(~static_cast<uint64_t>(0)),
        reinterpret_cast<uint64_t>(&base_addr),
        reinterpret_cast<uint64_t>(&region_size),
        static_cast<uint64_t>(PAGE_READWRITE | PAGE_GUARD),
        reinterpret_cast<uint64_t>(&old_protect));

    check(status == 0, "NtProtectVirtualMemory with PAGE_GUARD succeeded");

    VirtualQuery(test_mem, &mbi, sizeof(mbi));
    bool has_guard = (mbi.Protect & PAGE_GUARD) != 0;
    check(has_guard, "VirtualQuery confirms PAGE_GUARD flag set");

    // Снимаем PAGE_GUARD перед VirtualFree
    base_addr   = test_mem;
    region_size = 4096;
    old_protect = 0;

    // Первое обращение к PAGE_GUARD-странице снимет флаг (STATUS_GUARD_PAGE_VIOLATION).
    // Вместо этого меняем защиту обратно через syscall.
    indirect_syscall(
        ssn, syscall_addr,
        static_cast<uint64_t>(~static_cast<uint64_t>(0)),
        reinterpret_cast<uint64_t>(&base_addr),
        reinterpret_cast<uint64_t>(&region_size),
        static_cast<uint64_t>(PAGE_READWRITE),
        reinterpret_cast<uint64_t>(&old_protect));
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 8: Многократные быстрые вызовы (стабильность стека)
    // -----------------------------------------------------------------------
    std::printf("[Test 8] Stability: 100 rapid NtProtectVirtualMemory calls\n");
    {
        bool all_ok = true;
        for (int i = 0; i < 100; ++i) {
            base_addr   = test_mem;
            region_size = 4096;
            old_protect = 0;

            const DWORD target = (i % 2 == 0) ? PAGE_READONLY : PAGE_READWRITE;

            uint64_t st = indirect_syscall(
                ssn, syscall_addr,
                static_cast<uint64_t>(~static_cast<uint64_t>(0)),
                reinterpret_cast<uint64_t>(&base_addr),
                reinterpret_cast<uint64_t>(&region_size),
                static_cast<uint64_t>(target),
                reinterpret_cast<uint64_t>(&old_protect));

            if (st != 0) { all_ok = false; break; }

            VirtualQuery(test_mem, &mbi, sizeof(mbi));
            if (mbi.Protect != target) { all_ok = false; break; }
        }
        check(all_ok, "100 rapid protection changes all succeeded");
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------
    VirtualFree(test_mem, 0, MEM_RELEASE);

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    std::printf("========================================\n");
    std::printf("Results: %d/%d tests passed\n", g_tests_passed, g_tests_total);
    std::printf("========================================\n");

    if (g_tests_passed == g_tests_total) {
        std::printf("\nAll tests PASSED. Syscall engine is operational.\n");
        return 0;
    } else {
        std::printf("\nSome tests FAILED.\n");
        return 1;
    }
}

#else // !_WIN64

#include <cstdio>
int main() {
    std::printf("Syscall live test requires Windows x64 (MSVC). Skipping.\n");
    return 0;
}

#endif
