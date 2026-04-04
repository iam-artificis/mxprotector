/**
 * @file syscall_live_test.cpp
 * @brief [INTEGRATION] Live-тест indirect syscall через gate.asm.
 *
 * @details Standalone интеграционный тест для верификации полной цепочки:
 *          1. get_peb() — получение PEB из ASM
 *          2. Hell's Gate — извлечение SSN из ntdll
 *          3. Поиск `syscall; ret` гаджета в ntdll
 *          4. indirect_syscall → NtProtectVirtualMemory (5 Nt-аргументов)
 *          5. indirect_syscall → NtAllocateVirtualMemory (6 Nt-аргументов)
 *          6. Проверка через VirtualQuery, что результат реальный
 *          7. Обратная смена / освобождение (валидация стабильности)
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
    uint32_t ssn,          // ECX  -> EAX
    uint64_t syscall_addr, // RDX  -> R11
    uint64_t arg1,         // R8   -> R10
    uint64_t arg2,         // R9   -> RDX
    uint64_t arg3,         // [RSP+28h] -> R8
    uint64_t arg4,         // [RSP+30h] -> R9
    uint64_t arg5,         // [RSP+38h] -> [RSP+28h]
    uint64_t arg6 = 0,     // [RSP+40h] -> [RSP+30h]
    uint64_t arg7 = 0,     // [RSP+48h] -> [RSP+38h]
    uint64_t arg8 = 0,     // [RSP+50h] -> [RSP+40h]
    uint64_t arg9 = 0,     // [RSP+58h] -> [RSP+48h]
    uint64_t arg10 = 0,    // [RSP+60h] -> [RSP+50h]
    uint64_t arg11 = 0);   // [RSP+68h] -> [RSP+58h]

extern "C" void* get_peb();

// ============================================================================
// Внешние функции из test_helpers.asm
// ============================================================================

/// @brief Clobber test: выполняет NtClose(handle) через indirect_syscall,
///        проверяя сохранность всех non-volatile GPR (RBX, RBP, RDI, RSI, R12-R15).
///        Возвращает 0 при успехе, bitmask повреждённых регистров при провале.
extern "C" uint64_t nonvolatile_check_syscall(
    uint32_t ssn,
    uint64_t syscall_addr,
    uint64_t handle);

/// @brief Проверка 16-byte выравнивания стека для 13-параметровых вызовов.
///        Сигнатура идентична indirect_syscall — валидирует поведение компилятора.
///        Возвращает 0 при корректном выравнивании.
extern "C" uint64_t alignment_check_13args(
    uint32_t p1,  uint64_t p2,  uint64_t p3,  uint64_t p4,
    uint64_t p5,  uint64_t p6,  uint64_t p7,  uint64_t p8,
    uint64_t p9,  uint64_t p10, uint64_t p11, uint64_t p12,
    uint64_t p13);

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

/// @brief Минимальная thread-процедура для тестирования NtCreateThreadEx.
static DWORD WINAPI dummy_thread_proc(LPVOID) { return 0; }

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
    // Test 9: NtAllocateVirtualMemory (6 Nt args — верификация расширенного стека)
    // -----------------------------------------------------------------------
    std::printf("[Test 9] indirect_syscall -> NtAllocateVirtualMemory (6 Nt args)\n");
    {
        auto* nt_alloc_raw = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
        check(nt_alloc_raw != nullptr, "NtAllocateVirtualMemory found in ntdll");

        uint32_t alloc_ssn = 0;
        bool alloc_ssn_ok = extract_ssn(nt_alloc_raw, alloc_ssn);
        {
            char detail[64];
            std::snprintf(detail, sizeof(detail), "SSN = 0x%X", alloc_ssn);
            check(alloc_ssn_ok, "NtAllocateVirtualMemory SSN extracted", detail);
        }

        if (alloc_ssn_ok) {
            void*  alloc_base = nullptr;
            SIZE_T alloc_size = 8192;

            uint64_t alloc_status = indirect_syscall(
                alloc_ssn, syscall_addr,
                static_cast<uint64_t>(~static_cast<uint64_t>(0)),  // ProcessHandle = -1
                reinterpret_cast<uint64_t>(&alloc_base),            // &BaseAddress
                static_cast<uint64_t>(0),                           // ZeroBits
                reinterpret_cast<uint64_t>(&alloc_size),            // &RegionSize
                static_cast<uint64_t>(MEM_COMMIT | MEM_RESERVE),    // AllocationType (5th)
                static_cast<uint64_t>(PAGE_READWRITE));              // Protect (6th)

            {
                char detail[128];
                std::snprintf(detail, sizeof(detail),
                    "NTSTATUS=0x%08llX, base=%p, size=0x%llX",
                    alloc_status, alloc_base, static_cast<uint64_t>(alloc_size));
                check(alloc_status == 0, "NtAllocateVirtualMemory STATUS_SUCCESS", detail);
            }
            check(alloc_base != nullptr, "Allocated base is non-null");

            if (alloc_status == 0 && alloc_base != nullptr) {
                MEMORY_BASIC_INFORMATION alloc_mbi{};
                VirtualQuery(alloc_base, &alloc_mbi, sizeof(alloc_mbi));
                check(alloc_mbi.Protect == PAGE_READWRITE,
                    "Allocated region has PAGE_READWRITE protection");
                check(alloc_mbi.RegionSize >= 8192,
                    "Allocated region size >= requested 8192");

                // Запись/чтение для проверки доступности
                auto* ptr = static_cast<volatile uint8_t*>(alloc_base);
                ptr[0] = 0xAA;
                ptr[4095] = 0xBB;
                check(ptr[0] == 0xAA && ptr[4095] == 0xBB,
                    "Read/write to allocated memory succeeds");

                // Освобождение через NtFreeVirtualMemory (4 Nt args)
                auto* nt_free_raw = reinterpret_cast<const uint8_t*>(
                    GetProcAddress(ntdll, "NtFreeVirtualMemory"));
                uint32_t free_ssn = 0;

                if (nt_free_raw && extract_ssn(nt_free_raw, free_ssn)) {
                    void*  free_base = alloc_base;
                    SIZE_T free_size = 0;

                    uint64_t free_status = indirect_syscall(
                        free_ssn, syscall_addr,
                        static_cast<uint64_t>(~static_cast<uint64_t>(0)),
                        reinterpret_cast<uint64_t>(&free_base),
                        reinterpret_cast<uint64_t>(&free_size),
                        static_cast<uint64_t>(MEM_RELEASE),
                        0);

                    check(free_status == 0, "NtFreeVirtualMemory STATUS_SUCCESS");
                } else {
                    VirtualFree(alloc_base, 0, MEM_RELEASE);
                }
            }
        }
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 10: NtAllocateVirtualMemory — rapid alloc/free stability (6 Nt args)
    // -----------------------------------------------------------------------
    std::printf("[Test 10] Stability: 50 rapid NtAllocateVirtualMemory + NtFreeVirtualMemory\n");
    {
        auto* nt_alloc_raw = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
        auto* nt_free_raw = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "NtFreeVirtualMemory"));

        uint32_t alloc_ssn = 0, free_ssn = 0;
        bool ssns_ok = nt_alloc_raw && nt_free_raw &&
                       extract_ssn(nt_alloc_raw, alloc_ssn) &&
                       extract_ssn(nt_free_raw, free_ssn);

        if (ssns_ok) {
            bool all_ok = true;
            for (int i = 0; i < 50; ++i) {
                void*  base = nullptr;
                SIZE_T size = 4096;

                uint64_t st = indirect_syscall(
                    alloc_ssn, syscall_addr,
                    static_cast<uint64_t>(~static_cast<uint64_t>(0)),
                    reinterpret_cast<uint64_t>(&base),
                    0,
                    reinterpret_cast<uint64_t>(&size),
                    static_cast<uint64_t>(MEM_COMMIT | MEM_RESERVE),
                    static_cast<uint64_t>(PAGE_READWRITE));

                if (st != 0 || base == nullptr) { all_ok = false; break; }

                SIZE_T free_size = 0;
                st = indirect_syscall(
                    free_ssn, syscall_addr,
                    static_cast<uint64_t>(~static_cast<uint64_t>(0)),
                    reinterpret_cast<uint64_t>(&base),
                    reinterpret_cast<uint64_t>(&free_size),
                    static_cast<uint64_t>(MEM_RELEASE),
                    0);

                if (st != 0) { all_ok = false; break; }
            }
            check(all_ok, "50 rapid alloc/free cycles all succeeded");
        } else {
            check(false, "SSN extraction failed — skipped rapid test");
        }
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 11: NtCreateThreadEx — 11 Nt-аргументов (critical: max arg count)
    // -----------------------------------------------------------------------
    std::printf("[Test 11] indirect_syscall -> NtCreateThreadEx (11 Nt args)\n");
    {
        auto* nt_create_thread_raw = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "NtCreateThreadEx"));
        check(nt_create_thread_raw != nullptr, "NtCreateThreadEx found in ntdll");

        uint32_t ct_ssn = 0;
        bool ct_ssn_ok = nt_create_thread_raw &&
                         extract_ssn(nt_create_thread_raw, ct_ssn);
        if (ct_ssn_ok) {
            char detail[64];
            std::snprintf(detail, sizeof(detail), "SSN = 0x%X", ct_ssn);
            check(true, "NtCreateThreadEx SSN extracted", detail);
        }

        if (ct_ssn_ok) {
            HANDLE thread_handle = nullptr;

            // NtCreateThreadEx: все 11 Nt-аргументов через indirect_syscall.
            // Если ядро корректно прочитало ВСЕ 11 сдвинутых аргументов,
            // получаем STATUS_SUCCESS и валидный handle.
            uint64_t ct_status = indirect_syscall(
                ct_ssn, syscall_addr,
                reinterpret_cast<uint64_t>(&thread_handle),           // arg1:  &ThreadHandle (OUT)
                static_cast<uint64_t>(0x1FFFFF),                      // arg2:  THREAD_ALL_ACCESS
                0,                                                     // arg3:  ObjectAttributes = NULL
                static_cast<uint64_t>(~static_cast<uint64_t>(0)),     // arg4:  ProcessHandle = -1
                reinterpret_cast<uint64_t>(&dummy_thread_proc),       // arg5:  StartRoutine
                0,                                                     // arg6:  Argument = NULL
                static_cast<uint64_t>(1),                             // arg7:  THREAD_CREATE_FLAGS_CREATE_SUSPENDED
                0,                                                     // arg8:  ZeroBits
                0,                                                     // arg9:  StackSize (default)
                0,                                                     // arg10: MaximumStackSize (default)
                0);                                                    // arg11: AttributeList = NULL

            {
                char detail[128];
                std::snprintf(detail, sizeof(detail),
                    "NTSTATUS=0x%08llX, handle=%p", ct_status, thread_handle);
                check(ct_status == 0,
                    "NtCreateThreadEx returned STATUS_SUCCESS", detail);
            }
            check(thread_handle != nullptr && thread_handle != INVALID_HANDLE_VALUE,
                "Thread handle is valid");

            if (ct_status == 0 && thread_handle) {
                ResumeThread(thread_handle);
                WaitForSingleObject(thread_handle, 5000);
                CloseHandle(thread_handle);
                check(true, "Suspended thread resumed, completed, handle closed");
            }
        } else {
            check(false,
                "NtCreateThreadEx SSN extraction failed (function may be hooked)");
        }
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 12: Non-volatile register preservation (clobber test)
    // -----------------------------------------------------------------------
    std::printf("[Test 12] Non-volatile GPR preservation across indirect syscall\n");
    {
        auto* nt_close_raw = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "NtClose"));
        check(nt_close_raw != nullptr, "NtClose found in ntdll");

        uint32_t close_ssn = 0;
        bool close_ssn_ok = nt_close_raw && extract_ssn(nt_close_raw, close_ssn);
        {
            char detail[64];
            std::snprintf(detail, sizeof(detail), "SSN = 0x%X", close_ssn);
            check(close_ssn_ok, "NtClose SSN extracted", detail);
        }

        if (close_ssn_ok) {
            // Однократная проверка: sentinel-значения в RBX, RBP, RDI, RSI, R12-R15
            HANDLE evt = CreateEventA(nullptr, FALSE, FALSE, nullptr);
            check(evt != nullptr, "Test event created");

            if (evt) {
                uint64_t clobber_mask = nonvolatile_check_syscall(
                    close_ssn, syscall_addr,
                    reinterpret_cast<uint64_t>(evt));

                if (clobber_mask != 0) {
                    const char* reg_names[] = {
                        "RBX", "RDI", "RSI", "R12", "R13", "R14", "R15", "RBP"
                    };
                    char detail[128];
                    char* p = detail;
                    p += std::snprintf(p, sizeof(detail), "mask=0x%02llX, corrupted:",
                                       clobber_mask);
                    for (int i = 0; i < 8; ++i) {
                        if (clobber_mask & (1ull << i)) {
                            p += std::snprintf(p,
                                static_cast<size_t>(detail + sizeof(detail) - p),
                                " %s", reg_names[i]);
                        }
                    }
                    check(false, "Non-volatile GPRs preserved (single call)", detail);
                } else {
                    check(true, "Non-volatile GPRs preserved (single call)");
                }
            }

            // Многократная проверка: 100 итераций
            bool all_clobber_ok = true;
            uint64_t fail_mask = 0;
            for (int i = 0; i < 100; ++i) {
                HANDLE h = CreateEventA(nullptr, FALSE, FALSE, nullptr);
                if (!h) { all_clobber_ok = false; break; }

                uint64_t mask = nonvolatile_check_syscall(
                    close_ssn, syscall_addr,
                    reinterpret_cast<uint64_t>(h));

                if (mask != 0) {
                    all_clobber_ok = false;
                    fail_mask = mask;
                    break;
                }
            }
            {
                char detail[64];
                std::snprintf(detail, sizeof(detail),
                    all_clobber_ok ? "all clean" : "fail mask=0x%02llX", fail_mask);
                check(all_clobber_ok,
                    "100 rapid clobber tests: all non-volatile GPRs preserved", detail);
            }
        }
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Test 13: Stack alignment — 16-byte для 13-параметровых вызовов
    // -----------------------------------------------------------------------
    std::printf("[Test 13] Stack alignment for 13-parameter calls\n");
    {
        // alignment_check_13args имеет ту же сигнатуру, что и indirect_syscall.
        // Проверяет, что компилятор корректно выравнивает RSP перед CALL
        // при передаче 13 параметров (4 в регистрах + 9 на стеке).
        uint64_t align_result = alignment_check_13args(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13);

        {
            char detail[64];
            std::snprintf(detail, sizeof(detail),
                "RSP mod 16 - 8 = %lld (expect 0)", static_cast<long long>(align_result));
            check(align_result == 0,
                "RSP aligned correctly for 13-param call (RSP %% 16 == 8)", detail);
        }

        // Повторная проверка из другого контекста вызова (вложенный scope)
        auto run_alignment = [&]() {
            volatile uint64_t padding = 0x42;
            (void)padding;
            return alignment_check_13args(
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77);
        };
        uint64_t align_result2 = run_alignment();
        check(align_result2 == 0,
            "RSP aligned in nested scope with local variables");
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
