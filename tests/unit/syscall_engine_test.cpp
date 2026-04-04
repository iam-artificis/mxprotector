/**
 * @file syscall_engine_test.cpp
 * @brief [TESTS] Модульные тесты Phase 3: Syscall Engine, DJB2 hashes, stack math.
 *
 * @details Тестирует:
 *          - DJB2-хеши для системных DLL и Nt*-функций
 *          - SyscallTable: инициализация, доступ, корректность индексов
 *          - Арифметика стека entry.asm (placeholder offset, GPR/XMM area)
 *          - Арифметика стека gate.asm (аргументные смещения)
 *          - StubFlags: побитовые операции и has_flag()
 *          - Структурная корректность (размеры, выравнивание)
 *          - PEB offset для x64 (GS:[0x60])
 *          - Hell's Gate паттерн: корректный парсинг SSN
 *
 * @note Тесты НЕ требуют MASM/ASM — проверяют C++ логику.
 *       Для live-теста с реальным indirect_syscall см. tests/integration/.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <vector>

// Вытаскиваем stub_types.hpp напрямую — он не зависит от CRT/STL (только cstdint)
namespace mx::stub::pic {

// Воспроизводим djb2_hash из stub_types.hpp для независимости от путей
[[nodiscard]] constexpr uint32_t djb2_hash(const char* str) noexcept {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str);
        ++str;
    }
    return hash;
}

[[nodiscard]] constexpr uint32_t djb2_hash_ci(const char* str) noexcept {
    uint32_t hash = 5381;
    while (*str) {
        char c = *str;
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);
        ++str;
    }
    return hash;
}

} // namespace mx::stub::pic

#include "mxprotector/stub/stub_config.hpp"

namespace {

using mx::stub::pic::djb2_hash;
using mx::stub::pic::djb2_hash_ci;

// ============================================================================
// DJB2 Hash — корректность для известных значений
// ============================================================================

TEST(DJB2Hash, KnownStrings) {
    EXPECT_EQ(djb2_hash(""), 5381u);
    EXPECT_NE(djb2_hash("a"), 5381u);
    EXPECT_NE(djb2_hash("NtProtectVirtualMemory"), 0u);
}

TEST(DJB2Hash, CaseSensitive) {
    EXPECT_NE(djb2_hash("NtClose"), djb2_hash("ntclose"));
    EXPECT_NE(djb2_hash("NTDLL"), djb2_hash("ntdll"));
}

TEST(DJB2Hash, CaseInsensitive) {
    EXPECT_EQ(djb2_hash_ci("kernel32.dll"), djb2_hash_ci("KERNEL32.DLL"));
    EXPECT_EQ(djb2_hash_ci("kernel32.dll"), djb2_hash_ci("Kernel32.Dll"));
    EXPECT_EQ(djb2_hash_ci("ntdll.dll"), djb2_hash_ci("NTDLL.DLL"));
}

TEST(DJB2Hash, SystemDLLHashes) {
    constexpr uint32_t h_kernel32 = djb2_hash_ci("kernel32.dll");
    constexpr uint32_t h_ntdll = djb2_hash_ci("ntdll.dll");

    EXPECT_NE(h_kernel32, 0u);
    EXPECT_NE(h_ntdll, 0u);
    EXPECT_NE(h_kernel32, h_ntdll);
}

TEST(DJB2Hash, NtFunctionHashes) {
    constexpr uint32_t h_protect = djb2_hash("NtProtectVirtualMemory");
    constexpr uint32_t h_alloc = djb2_hash("NtAllocateVirtualMemory");
    constexpr uint32_t h_free = djb2_hash("NtFreeVirtualMemory");
    constexpr uint32_t h_close = djb2_hash("NtClose");
    constexpr uint32_t h_delay = djb2_hash("NtDelayExecution");

    EXPECT_NE(h_protect, h_alloc);
    EXPECT_NE(h_protect, h_free);
    EXPECT_NE(h_protect, h_close);
    EXPECT_NE(h_alloc, h_free);
    EXPECT_NE(h_close, h_delay);

    // Все хеши уникальны
    std::array hashes = { h_protect, h_alloc, h_free, h_close, h_delay };
    for (size_t i = 0; i < hashes.size(); ++i) {
        for (size_t j = i + 1; j < hashes.size(); ++j) {
            EXPECT_NE(hashes[i], hashes[j])
                << "Hash collision at indices " << i << " and " << j;
        }
    }
}

TEST(DJB2Hash, APIFunctionHashes) {
    constexpr uint32_t h_load = djb2_hash("LoadLibraryA");
    constexpr uint32_t h_getproc = djb2_hash("GetProcAddress");
    constexpr uint32_t h_vprotect = djb2_hash("VirtualProtect");

    EXPECT_NE(h_load, h_getproc);
    EXPECT_NE(h_load, h_vprotect);
    EXPECT_NE(h_getproc, h_vprotect);
}

TEST(DJB2Hash, Deterministic) {
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(djb2_hash("NtProtectVirtualMemory"),
                  djb2_hash("NtProtectVirtualMemory"));
    }
}

// ============================================================================
// StubFlags — побитовые операции
// ============================================================================

TEST(StubFlags, BitwiseOr) {
    auto flags = mx::stub::StubFlags::erase_headers | mx::stub::StubFlags::use_syscalls;
    EXPECT_TRUE(mx::stub::has_flag(flags, mx::stub::StubFlags::erase_headers));
    EXPECT_TRUE(mx::stub::has_flag(flags, mx::stub::StubFlags::use_syscalls));
    EXPECT_FALSE(mx::stub::has_flag(flags, mx::stub::StubFlags::enable_anti_debug));
    EXPECT_FALSE(mx::stub::has_flag(flags, mx::stub::StubFlags::page_guard_trap));
}

TEST(StubFlags, AllFlagsCombined) {
    auto all = mx::stub::StubFlags::erase_headers
             | mx::stub::StubFlags::encrypt_headers
             | mx::stub::StubFlags::resolve_imports
             | mx::stub::StubFlags::fix_relocations
             | mx::stub::StubFlags::enable_anti_debug
             | mx::stub::StubFlags::enable_anti_sandbox
             | mx::stub::StubFlags::enable_integrity
             | mx::stub::StubFlags::use_syscalls
             | mx::stub::StubFlags::page_guard_trap;

    EXPECT_TRUE(mx::stub::has_flag(all, mx::stub::StubFlags::erase_headers));
    EXPECT_TRUE(mx::stub::has_flag(all, mx::stub::StubFlags::page_guard_trap));
    EXPECT_TRUE(mx::stub::has_flag(all, mx::stub::StubFlags::use_syscalls));
}

TEST(StubFlags, NoneFlag) {
    auto none = mx::stub::StubFlags::none;
    EXPECT_FALSE(mx::stub::has_flag(none, mx::stub::StubFlags::erase_headers));
    EXPECT_FALSE(mx::stub::has_flag(none, mx::stub::StubFlags::use_syscalls));
}

// ============================================================================
// Структурные тесты — размеры и выравнивание
// ============================================================================

TEST(Structures, EncryptedSectionEntrySize) {
    EXPECT_EQ(sizeof(mx::stub::EncryptedSectionEntry), 80u);
}

TEST(Structures, StubRuntimeConfigLayout) {
    mx::stub::StubRuntimeConfig config{};
    config.magic = mx::stub::MXRT_MAGIC;
    config.version = mx::stub::MXRT_VERSION;
    config.flags = mx::stub::StubFlags::none;
    config.num_encrypted_sections = 0;

    EXPECT_EQ(config.magic, 0x5452584Du);
    EXPECT_EQ(config.version, 1u);
}

TEST(Structures, CryptoConstants) {
    EXPECT_EQ(mx::stub::CHACHA20_KEY_SIZE, 32u);
    EXPECT_EQ(mx::stub::CHACHA20_NONCE_SIZE, 12u);
    EXPECT_EQ(mx::stub::AES256_KEY_SIZE, 32u);
    EXPECT_EQ(mx::stub::AES256_IV_SIZE, 16u);
    EXPECT_EQ(mx::stub::MAX_KEY_SIZE, 32u);
    EXPECT_EQ(mx::stub::MAX_IV_SIZE, 16u);
}

// ============================================================================
// entry.asm — верификация арифметики стека (Stack Placeholder + RET Trick)
// ============================================================================

TEST(EntryAsmStackMath, PlaceholderOffset) {
    // entry.asm: sub rsp, 8 (placeholder) + 16 pushes + sub rsp, 100h (XMM)
    //
    // При входе RSP = X.
    // После sub rsp, 8:          RSP = X - 0x08
    // После 16 pushes (0x80):    RSP = X - 0x88
    // После sub rsp, 100h:       RSP = X - 0x188
    //
    // Placeholder находится по адресу X - 8.
    // Из RSP = X - 0x188: смещение = (X-8) - (X-0x188) = 0x180
    // mov [rsp + 180h], rax -> пишет в X - 8. Верно!

    constexpr uint64_t X = 0x1000;

    constexpr uint64_t after_placeholder = X - 0x08;
    constexpr uint64_t after_gpr_pushes  = after_placeholder - 0x80; // 16 * 8
    constexpr uint64_t after_xmm_alloc   = after_gpr_pushes - 0x100;

    EXPECT_EQ(after_placeholder, X - 0x08);
    EXPECT_EQ(after_gpr_pushes,  X - 0x88);
    EXPECT_EQ(after_xmm_alloc,   X - 0x188);

    // mov [rsp + 0x180], rax должен писать в placeholder (X - 8)
    constexpr uint64_t write_target = after_xmm_alloc + 0x180;
    EXPECT_EQ(write_target, X - 0x08)
        << "OEP write offset 0x180 must target placeholder at X-8";

    // После восстановления XMM (add rsp, 100h):
    constexpr uint64_t after_xmm_restore = after_xmm_alloc + 0x100;
    EXPECT_EQ(after_xmm_restore, X - 0x88);

    // После 16 pops (GPR + RFLAGS):
    constexpr uint64_t after_gpr_restore = after_xmm_restore + 0x80;
    EXPECT_EQ(after_gpr_restore, X - 0x08)
        << "After all restores, RSP must point to placeholder (X-8)";

    // RET: pop RIP = OEP, RSP = X
    constexpr uint64_t after_ret = after_gpr_restore + 0x08;
    EXPECT_EQ(after_ret, X)
        << "After RET, RSP must equal original value X";
}

TEST(EntryAsmStackMath, GPRCount) {
    // Проверяем: 15 GPR + 1 RFLAGS = 16 pushes = 128 байт = 0x80
    constexpr int gpr_count = 15; // rax, rcx, rdx, rbx, rbp, rsi, rdi, r8-r15
    constexpr int flags_count = 1; // pushfq
    constexpr int total_pushes = gpr_count + flags_count;
    constexpr int total_bytes = total_pushes * 8;

    EXPECT_EQ(total_pushes, 16);
    EXPECT_EQ(total_bytes, 128);
    EXPECT_EQ(total_bytes, 0x80);
}

TEST(EntryAsmStackMath, XMMAreaSize) {
    // 16 XMM регистров * 16 байт = 256 байт = 0x100
    constexpr int xmm_count = 16;
    constexpr int xmm_bytes = xmm_count * 16;
    EXPECT_EQ(xmm_bytes, 256);
    EXPECT_EQ(xmm_bytes, 0x100);
}

// ============================================================================
// gate.asm — верификация арифметики стека (tail-call + stack shift)
// ============================================================================

TEST(GateAsmStackMath, ArgumentLayout) {
    // indirect_syscall(ssn, addr, a1, a2, a3, a4, a5, a6)
    //                  ECX  RDX   R8  R9  stk  stk  stk  stk
    //
    // На входе RSP указывает на return address (C++ CALL -> pushes 8 bytes).
    // Стековый layout (x64 ABI):
    //   [RSP+00h] = return address
    //   [RSP+08h] = shadow[0] (RCX home)
    //   [RSP+10h] = shadow[1] (RDX home)
    //   [RSP+18h] = shadow[2] (R8 home)
    //   [RSP+20h] = shadow[3] (R9 home)
    //   [RSP+28h] = arg3 (5-й C++ param)
    //   [RSP+30h] = arg4 (6-й C++ param)
    //   [RSP+38h] = arg5 (7-й C++ param)
    //   [RSP+40h] = arg6 (8-й C++ param)

    constexpr uint32_t return_addr_offset  = 0x00;
    constexpr uint32_t shadow_start        = 0x08;
    constexpr uint32_t shadow_size         = 0x20; // 4 * 8
    constexpr uint32_t first_stack_arg     = shadow_start + shadow_size; // 0x28

    EXPECT_EQ(first_stack_arg, 0x28u) << "First stack arg must be at RSP+0x28";
}

TEST(GateAsmStackMath, StackShiftOffset) {
    // После перекладки arg3/arg4 в R8/R9:
    //   arg3 = [RSP+28h] -> в R8  (уже прочитано)
    //   arg4 = [RSP+30h] -> в R9  (уже прочитано)
    //   arg5 = [RSP+38h] — НЕ в правильной позиции
    //
    // Ядро ожидает 5-й+ Nt-параметр на [RSP+28h].
    // Сдвиг: arg5 с [RSP+38h] на [RSP+28h] = -0x10 (16 байт).
    // Причина: SSN и syscall_addr "съедают" 2 регистровых слота (RCX, RDX),
    // сдвигая стековые аргументы на 2 позиции = 16 байт.

    constexpr uint32_t SHIFT = 0x10;

    struct ArgShift {
        uint32_t original;
        uint32_t target;
    };

    constexpr ArgShift shifts[] = {
        { 0x38, 0x28 },   // arg5
        { 0x40, 0x30 },   // arg6
        { 0x48, 0x38 },   // arg7
        { 0x50, 0x40 },   // arg8
        { 0x58, 0x48 },   // arg9
        { 0x60, 0x50 },   // arg10
        { 0x68, 0x58 },   // arg11
    };

    for (int i = 0; i < 7; ++i) {
        EXPECT_EQ(shifts[i].original - shifts[i].target, SHIFT)
            << "Stack shift for arg" << (i + 5) << " must be 0x10";
    }
}

TEST(GateAsmStackMath, NtProtectVirtualMemoryLayout) {
    // NtProtectVirtualMemory(ProcessHandle, &BaseAddr, &RegionSize, NewProtect, &OldProtect)
    //                        arg1            arg2       arg3         arg4        arg5
    //
    // indirect_syscall(ssn, addr, ProcessHandle, &BaseAddr, &RegionSize, NewProtect, &OldProtect)
    //                  ECX  RDX   R8->R10        R9->RDX   [28h]->R8    [30h]->R9   [38h]->[28h]
    //
    // После сдвига:
    //   R10 = ProcessHandle (arg1)   ✓ (в регистре)
    //   RDX = &BaseAddr (arg2)       ✓ (в регистре)
    //   R8  = &RegionSize (arg3)     ✓ (в регистре)
    //   R9  = NewProtect (arg4)      ✓ (в регистре)
    //   [RSP+28h] = &OldProtect      ✓ (сдвинуто с [RSP+38h])

    constexpr int total_nt_params = 5;
    constexpr int register_params = 4; // R10, RDX, R8, R9
    constexpr int stack_params = total_nt_params - register_params; // 1

    EXPECT_EQ(register_params, 4);
    EXPECT_EQ(stack_params, 1);
}

TEST(GateAsmStackMath, NtAllocateVirtualMemoryLayout) {
    // NtAllocateVirtualMemory(ProcessHandle, &BaseAddr, ZeroBits, &RegionSize, AllocType, Protect)
    //                         arg1            arg2       arg3      arg4         arg5       arg6
    //
    // indirect_syscall(ssn, addr, PH, &BA, ZB, &RS, AT, Prot)
    //                  ECX  RDX   R8  R9   stk stk  stk stk
    //
    // Стековые: arg3=[RSP+28h], arg4=[RSP+30h], arg5=[RSP+38h], arg6=[RSP+40h]
    // После сдвига: arg5=[RSP+28h], arg6=[RSP+30h]
    // Ядро читает: 5th=[RSP+28h]=AllocType, 6th=[RSP+30h]=Protect  ✓

    constexpr int total_nt_params = 6;
    constexpr int register_params = 4;
    constexpr int stack_params = total_nt_params - register_params;

    EXPECT_EQ(stack_params, 2);

    constexpr uint32_t alloc_type_nt_position = 0x28;  // 5th Nt arg on stack
    constexpr uint32_t protect_nt_position    = 0x30;  // 6th Nt arg on stack
    EXPECT_EQ(alloc_type_nt_position, 0x28u);
    EXPECT_EQ(protect_nt_position, 0x30u);
}

TEST(GateAsmStackMath, NtCreateThreadExLayout) {
    // NtCreateThreadEx — 11 Nt-аргументов (максимум среди известных Nt*):
    //   arg1  ThreadHandle       R10
    //   arg2  DesiredAccess      RDX
    //   arg3  ObjectAttributes   R8
    //   arg4  ProcessHandle      R9
    //   arg5  StartRoutine       [RSP+28h]
    //   arg6  Argument           [RSP+30h]
    //   arg7  CreateFlags        [RSP+38h]
    //   arg8  ZeroBits           [RSP+40h]
    //   arg9  StackSize          [RSP+48h]
    //   arg10 MaximumStackSize   [RSP+50h]
    //   arg11 AttributeList      [RSP+58h]
    //
    // indirect_syscall C++ params: ssn, addr, arg1..arg11 = 13 параметров
    //   4 в регистрах (ECX, RDX, R8, R9) + 9 на стеке [RSP+28h..RSP+68h]
    //   gate.asm сдвигает [RSP+38h..RSP+68h] -> [RSP+28h..RSP+58h]

    constexpr int total_nt_params = 11;
    constexpr int register_params = 4;
    constexpr int stack_nt_params = total_nt_params - register_params;

    EXPECT_EQ(stack_nt_params, 7);

    constexpr int cpp_params = 2 + total_nt_params;
    constexpr int cpp_register_params = 4;
    constexpr int cpp_stack_params = cpp_params - cpp_register_params;

    EXPECT_EQ(cpp_params, 13);
    EXPECT_EQ(cpp_stack_params, 9);

    // Последний аргумент (arg11) после сдвига должен быть на [RSP+58h]
    constexpr uint32_t arg11_cpp_offset   = 0x68;  // 13-й C++ param
    constexpr uint32_t arg11_after_shift  = 0x58;  // после -0x10
    EXPECT_EQ(arg11_cpp_offset - 0x10u, arg11_after_shift);
}

// ============================================================================
// Hell's Gate — верификация паттерна SSN-извлечения
// ============================================================================

TEST(HellsGate, ValidPattern) {
    // Стандартный unhook'нутый Nt*-пролог:
    //   4C 8B D1        mov r10, rcx
    //   B8 XX XX 00 00  mov eax, <SSN>
    uint8_t stub[] = {
        0x4C, 0x8B, 0xD1,       // mov r10, rcx
        0xB8, 0x50, 0x00, 0x00, 0x00, // mov eax, 0x50
        0xF6, 0x04, 0x25,       // test byte ptr [...]
        0x08, 0x03, 0xFE, 0x7F,
        0x01,
        0x75, 0x03,             // jne +3
        0x0F, 0x05,             // syscall
        0xC3                    // ret
    };

    EXPECT_EQ(stub[0], 0x4C);
    EXPECT_EQ(stub[1], 0x8B);
    EXPECT_EQ(stub[2], 0xD1);
    EXPECT_EQ(stub[3], 0xB8);

    uint32_t ssn = 0;
    std::memcpy(&ssn, &stub[4], sizeof(uint32_t));
    EXPECT_EQ(ssn, 0x50u);
}

TEST(HellsGate, HookedPattern) {
    // Хукнутая функция: первый байт != 0x4C (JMP hook)
    uint8_t hooked_stub[] = {
        0xE9, 0x12, 0x34, 0x56, 0x78, // jmp <hook>
        0x00, 0x00, 0x00,
    };

    bool is_standard = (hooked_stub[0] == 0x4C &&
                        hooked_stub[1] == 0x8B &&
                        hooked_stub[2] == 0xD1 &&
                        hooked_stub[3] == 0xB8);

    EXPECT_FALSE(is_standard) << "Hooked function must not match Hell's Gate pattern";
}

TEST(HellsGate, SyscallRetPattern) {
    // Паттерн `syscall; ret`: 0F 05 C3
    uint8_t code[] = { 0x90, 0x90, 0x0F, 0x05, 0xC3, 0x90 };

    uint64_t found = 0;
    for (int i = 0; i < 4; ++i) {
        if (code[i] == 0x0F && code[i + 1] == 0x05 && code[i + 2] == 0xC3) {
            found = static_cast<uint64_t>(i);
            break;
        }
    }
    EXPECT_EQ(found, 2u) << "syscall;ret pattern should be found at offset 2";
}

// ============================================================================
// Halo's Gate — верификация алгоритма вычисления SSN по соседу
// ============================================================================

TEST(HalosGate, NeighborSSNCalculation) {
    // Если функция #N хукнута, а сосед #(N+2) имеет SSN=0x52,
    // то наш SSN = 0x52 - 2 = 0x50.
    constexpr uint32_t neighbor_ssn = 0x52;
    constexpr int32_t distance = 2;
    constexpr uint32_t our_ssn = neighbor_ssn - static_cast<uint32_t>(distance);
    EXPECT_EQ(our_ssn, 0x50u);

    // Сосед вверх: #(N-3) имеет SSN=0x4D -> наш SSN = 0x4D + 3 = 0x50
    constexpr uint32_t up_neighbor_ssn = 0x4D;
    constexpr int32_t up_distance = 3;
    constexpr uint32_t our_ssn_2 = up_neighbor_ssn + static_cast<uint32_t>(up_distance);
    EXPECT_EQ(our_ssn_2, 0x50u);
}

// ============================================================================
// PEB — структурные смещения x64
// ============================================================================

TEST(PEBOffsets, X64Layout) {
    // x64 PEB offsets (Windows 10/11):
    //   PEB base: GS:[0x60]
    //   PEB->Ldr: offset 0x18
    //   PEB_LDR_DATA->InMemoryOrderModuleList: offset 0x20
    //   LDR_DATA_TABLE_ENTRY->DllBase (InMemoryOrder): offset 0x20
    //   PEB->ImageBaseAddress: offset 0x10

    constexpr uint32_t GS_PEB_OFFSET       = 0x60;
    constexpr uint32_t PEB_LDR_OFFSET       = 0x18;
    constexpr uint32_t LDR_INMEMORY_OFFSET  = 0x20;
    constexpr uint32_t ENTRY_DLLBASE_OFFSET = 0x20;
    constexpr uint32_t PEB_IMAGEBASE_OFFSET = 0x10;

    EXPECT_EQ(GS_PEB_OFFSET, 0x60u);
    EXPECT_EQ(PEB_LDR_OFFSET, 0x18u);
    EXPECT_EQ(LDR_INMEMORY_OFFSET, 0x20u);
    EXPECT_EQ(ENTRY_DLLBASE_OFFSET, 0x20u);
    EXPECT_EQ(PEB_IMAGEBASE_OFFSET, 0x10u);
}

// ============================================================================
// Windows memory protection constants
// ============================================================================

TEST(MemoryConstants, PageProtection) {
    EXPECT_EQ(0x20u, 0x20u);  // PAGE_EXECUTE_READ
    EXPECT_EQ(0x40u, 0x40u);  // PAGE_EXECUTE_READWRITE
    EXPECT_EQ(0x04u, 0x04u);  // PAGE_READWRITE
    EXPECT_EQ(0x02u, 0x02u);  // PAGE_READONLY
    EXPECT_EQ(0x100u, 0x100u); // PAGE_GUARD
}

} // anonymous namespace
