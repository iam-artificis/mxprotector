/**
 * @file test_vm_basic.cpp
 * @brief Простой тест VM: проверяет, что чисто регистровая ALU работает внутри
 *        маркированного региона идентично после виртуализации.
 */

#include <cstdint>
#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

// Простой счётчик-ксорщик — всё в локальных переменных.
// Компилятор, скорее всего, держит `acc` в регистре и использует
// непересекающиеся с rsp/rbp регистры.
__declspec(noinline) uint64_t virtualized_kernel(uint64_t seed) {
    // Работаем исключительно через регистры: acc хранится в non-volatile GPR,
    // t — во втором. VM-лифтер требует чистых reg-reg / reg-imm форм без RSP-base.
    uint64_t acc = seed;
    uint64_t t   = 0;
    MX_VM_BEGIN
    t   = 0xA5A5A5A5u;
    acc ^= t;
    acc += 0x1234;
    t    = acc;
    acc += t;   // acc = 2*acc
    acc += t;   // acc = 3*acc
    t    = 0xDEADBEEFu;
    acc ^= t;
    acc -= 0x1000;
    MX_VM_END
    return acc;
}

int main() {
    std::printf("[test_vm_basic] start\n");

    const uint64_t a = virtualized_kernel(0x0000000011111111ULL);
    const uint64_t b = virtualized_kernel(0x0000000022222222ULL);
    const uint64_t c = virtualized_kernel(0x00000000DEADBEEFULL);

    std::printf("[test_vm_basic] a=0x%016llX\n", static_cast<unsigned long long>(a));
    std::printf("[test_vm_basic] b=0x%016llX\n", static_cast<unsigned long long>(b));
    std::printf("[test_vm_basic] c=0x%016llX\n", static_cast<unsigned long long>(c));

    // Детерминированные эталоны
    auto expected = [](uint64_t seed) -> uint64_t {
        uint64_t x = seed;
        x ^= 0xA5A5A5A5ULL;
        x += 0x1234ULL;
        x *= 3ULL;
        x ^= 0xDEADBEEFULL;
        x -= 0x1000ULL;
        return x;
    };

    const bool ok =
        (a == expected(0x0000000011111111ULL)) &&
        (b == expected(0x0000000022222222ULL)) &&
        (c == expected(0x00000000DEADBEEFULL));

    if (ok) {
        std::printf("[test_vm_basic] ALL CHECKS PASSED\n");
        return 0;
    }
    std::printf("[test_vm_basic] CHECKS FAILED\n");
    return 1;
}
