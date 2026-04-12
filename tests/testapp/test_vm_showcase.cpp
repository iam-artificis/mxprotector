/**
 * @file test_vm_showcase.cpp
 * @brief Showcase: сложная функция с множеством условных переходов внутри VM.
 *
 * Функция classify_and_transform принимает число и выполняет серию ветвлений:
 * - Проверка чётности
 * - Проверка диапазонов (0-10, 11-100, 101-1000, >1000)
 * - Разные арифметические трансформации в каждой ветке
 * - Цикл с условным выходом
 *
 * Всё это виртуализировано через MX_VM_BEGIN/END.
 */

#include <cstdint>
#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) uint64_t classify_and_transform(uint64_t input) {
    uint64_t result = input;
    uint64_t temp = 0;
    uint64_t counter = 0;

    MX_VM_BEGIN

    // Ветка 1: чётность
    temp = result;
    temp &= 1;
    if (temp != 0) goto odd_path;

    // Чётное число
    result += 0x100;
    goto range_check;

odd_path:
    result += 0x200;

range_check:
    // Ветка 2: проверка диапазонов
    if (result > 1000) goto big_number;
    if (result > 100)  goto medium_number;
    if (result > 10)   goto small_number;

    // Крошечное число (0-10)
    result ^= 0xDEAD;
    goto loop_phase;

small_number:
    result ^= 0xBEEF;
    goto loop_phase;

medium_number:
    result ^= 0xCAFE;
    goto loop_phase;

big_number:
    result ^= 0xF00D;

loop_phase:
    // Ветка 3: цикл с условным выходом
    counter = 0;
loop_top:
    if (counter >= 5) goto loop_done;
    result += counter;
    result ^= counter;
    counter += 1;
    goto loop_top;

loop_done:
    // Финальная трансформация
    result += 0x1234;
    temp = result;
    temp &= 0xFF;
    if (temp > 0x80) goto high_byte;

    result ^= 0xAAAA;
    goto vm_exit;

high_byte:
    result ^= 0x5555;

vm_exit:
    MX_VM_END
    return result;
}

static uint64_t reference_impl(uint64_t input) {
    uint64_t result = input;
    uint64_t temp = 0;
    uint64_t counter = 0;

    temp = result & 1;
    if (temp != 0)
        result += 0x200;
    else
        result += 0x100;

    if (result > 1000)
        result ^= 0xF00D;
    else if (result > 100)
        result ^= 0xCAFE;
    else if (result > 10)
        result ^= 0xBEEF;
    else
        result ^= 0xDEAD;

    for (counter = 0; counter < 5; counter++) {
        result += counter;
        result ^= counter;
    }

    result += 0x1234;
    temp = result & 0xFF;
    if (temp > 0x80)
        result ^= 0x5555;
    else
        result ^= 0xAAAA;

    return result;
}

int main() {
    std::printf("[test_vm_showcase] start\n");

    const uint64_t inputs[] = {
        0, 1, 5, 10, 11, 42, 50, 99, 100, 101,
        255, 500, 777, 999, 1000, 1001, 5000, 12345,
        0xDEAD, 0xFFFF, 0x10000, 0xCAFEBABE
    };

    bool all_ok = true;
    for (uint64_t input : inputs) {
        const uint64_t got  = classify_and_transform(input);
        const uint64_t want = reference_impl(input);
        const bool ok = (got == want);
        if (!ok) {
            std::printf("  input=0x%llX got=0x%llX want=0x%llX FAIL\n",
                static_cast<unsigned long long>(input),
                static_cast<unsigned long long>(got),
                static_cast<unsigned long long>(want));
            all_ok = false;
        }
    }

    if (all_ok) {
        std::printf("[test_vm_showcase] ALL %d CHECKS PASSED\n",
            static_cast<int>(sizeof(inputs) / sizeof(inputs[0])));
        return 0;
    }
    std::printf("[test_vm_showcase] CHECKS FAILED\n");
    return 1;
}
