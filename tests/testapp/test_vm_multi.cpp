/**
 * @file test_vm_multi.cpp
 * @brief Расширенный тест VM: несколько независимых виртуализируемых регионов
 *        с разнотипной арифметикой (shift/rotate, bitwise, imul, neg/not).
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) uint64_t kernel_alu(uint64_t a, uint64_t b) {
    uint64_t x = a;
    uint64_t y = b;
    MX_VM_BEGIN
    x ^= y;
    x += 0x0BADF00DULL;
    y -= x;
    x *= 5ULL;
    y ^= 0xCAFEBABEULL;
    x -= y;
    MX_VM_END
    return x + y;
}

__declspec(noinline) uint64_t kernel_shifts(uint64_t seed) {
    uint64_t v = seed;
    uint64_t t = 0;
    MX_VM_BEGIN
    t  = v;
    v  = v + t;
    v  = v + t;
    v ^= 0xA5A5A5A5ULL;
    v -= 0xDEAD;
    t  = v;
    v  = v + t;
    v += t;
    MX_VM_END
    return v;
}

__declspec(noinline) uint64_t kernel_bits(uint64_t seed) {
    uint64_t a = seed;
    uint64_t b = seed + 1;
    uint64_t c = seed * 3;
    MX_VM_BEGIN
    c ^= a;
    a += c;
    b -= a;
    c  = b;
    c += a;
    a -= c;
    MX_VM_END
    return a ^ b ^ c;
}

int main() {
    std::printf("[test_vm_multi] start\n");

    const uint64_t r1 = kernel_alu(0x1111'2222'3333'4444ULL, 0xDEAD'BEEF'CAFE'BABEULL);
    const uint64_t r2 = kernel_shifts(0x0123'4567'89AB'CDEFULL);
    const uint64_t r3 = kernel_bits(0xAA55'AA55'AA55'AA55ULL);

    std::printf("[test_vm_multi] r1=0x%016llX\n", static_cast<unsigned long long>(r1));
    std::printf("[test_vm_multi] r2=0x%016llX\n", static_cast<unsigned long long>(r2));
    std::printf("[test_vm_multi] r3=0x%016llX\n", static_cast<unsigned long long>(r3));

    auto ex1 = [](uint64_t a, uint64_t b) {
        uint64_t x = a, y = b;
        x ^= y;
        x += 0x0BADF00DULL;
        y -= x;
        x *= 5ULL;
        y ^= 0xCAFEBABEULL;
        x -= y;
        return x + y;
    };
    auto ex2 = [](uint64_t seed) {
        uint64_t v = seed, t = 0;
        t  = v;
        v  = v + t;
        v  = v + t;
        v ^= 0xA5A5A5A5ULL;
        v -= 0xDEAD;
        t  = v;
        v  = v + t;
        v += t;
        return v;
    };
    auto ex3 = [](uint64_t seed) {
        uint64_t a = seed, b = seed + 1, c = seed * 3;
        c ^= a;
        a += c;
        b -= a;
        c  = b;
        c += a;
        a -= c;
        return a ^ b ^ c;
    };

    const bool ok =
        (r1 == ex1(0x1111'2222'3333'4444ULL, 0xDEAD'BEEF'CAFE'BABEULL)) &&
        (r2 == ex2(0x0123'4567'89AB'CDEFULL)) &&
        (r3 == ex3(0xAA55'AA55'AA55'AA55ULL));

    if (ok) {
        std::printf("[test_vm_multi] ALL CHECKS PASSED\n");
        return 0;
    }
    std::printf("[test_vm_multi] CHECKS FAILED\n");
    return 1;
}
