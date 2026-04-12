/**
 * @file test_vm_dump.cpp
 * @brief Тестовое приложение для проверки anti-dump защиты.
 *
 * Работает в бесконечном цикле с задержкой 2 секунды, выводя счётчик.
 * Виртуализированная функция с условными переходами вызывается каждую
 * итерацию. Пока программа работает, можно сделать дамп памяти и
 * проверить:
 *   - Import Directory обнулён
 *   - .text зашифрован (если дампить до расшифровки — невозможно в
 *     нормальном сценарии, т.к. stub расшифровывает до main)
 *   - Stolen bytes на OEP отсутствуют (0xCC)
 *   - Handler table в .mxvm — мусор (encrypted)
 */

#include <cstdint>
#include <cstdio>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) uint64_t protected_work(uint64_t iter) {
    uint64_t acc = iter;
    uint64_t tmp = 0;

    MX_VM_BEGIN

    tmp = acc;
    tmp &= 0xFF;
    if (tmp > 0x80) goto path_a;

    acc ^= 0xDEADBEEF;
    acc += iter;
    goto merge;

path_a:
    acc ^= 0xCAFEBABE;
    acc -= iter;

merge:
    tmp = 0;
loop:
    if (tmp >= 3) goto done;
    acc += tmp;
    acc ^= tmp;
    tmp += 1;
    goto loop;

done:
    acc += 0x1234;

    MX_VM_END
    return acc;
}

int main() {
    std::printf("[test_vm_dump] Running... (Ctrl+C to stop)\n");
    std::printf("[test_vm_dump] PID: %lu\n", GetCurrentProcessId());
    std::printf("[test_vm_dump] Attach debugger or dump tool now.\n\n");

    for (uint64_t i = 0; ; ++i) {
        const uint64_t result = protected_work(i);
        std::printf("[iter %4llu] result = 0x%016llX\r",
            static_cast<unsigned long long>(i),
            static_cast<unsigned long long>(result));
        Sleep(2000);
    }
}
