/**
 * @file test_vm_stress.cpp
 * @brief Нагрузочный тест VM: один большой регион с большим числом
 *        разнотипных ALU-операций. Проверяет правильность всех вариантов
 *        handler'ов (включая MBA) и корректность rolling-key stream cipher.
 */

#include <cstdint>
#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) uint64_t stress_kernel(uint64_t a, uint64_t b, uint64_t c) {
    uint64_t x = a;
    uint64_t y = b;
    uint64_t z = c;
    uint64_t t = 0;

    MX_VM_BEGIN
    // Достаточно сложная цепочка чтобы MSVC не свернул — несколько шагов,
    // каждый зависит от предыдущих. Только reg-reg add/sub/xor.
    x ^= y;
    y += x;
    z -= y;
    t  = x;
    t += z;
    x ^= t;
    y -= z;
    z ^= t;
    x += z;
    t -= y;
    y ^= x;
    z += y;
    x -= t;
    t ^= z;
    MX_VM_END

    return x ^ (y << 1) ^ (z >> 1) ^ t;
}

int main() {
    std::printf("[test_vm_stress] start\n");

    struct Case {
        uint64_t a, b, c;
    };

    const Case cases[] = {
        {0x0000'0000'0000'0001ULL, 0x0000'0000'0000'0002ULL, 0x0000'0000'0000'0003ULL},
        {0xFFFFFFFF'FFFFFFFFULL, 0x1111'2222'3333'4444ULL, 0xDEAD'BEEF'CAFE'BABEULL},
        {0x0123'4567'89AB'CDEFULL, 0xA5A5'A5A5'A5A5'A5A5ULL, 0x5A5A'5A5A'5A5A'5A5AULL},
        {0x8000'0000'0000'0000ULL, 0x7FFF'FFFF'FFFF'FFFFULL, 0x1234'5678'9ABC'DEF0ULL},
    };

    auto expected = [](uint64_t a, uint64_t b, uint64_t c) -> uint64_t {
        uint64_t x = a, y = b, z = c, t = 0;
        x ^= y;
        y += x;
        z -= y;
        t  = x;
        t += z;
        x ^= t;
        y -= z;
        z ^= t;
        x += z;
        t -= y;
        y ^= x;
        z += y;
        x -= t;
        t ^= z;
        return x ^ (y << 1) ^ (z >> 1) ^ t;
    };

    bool all_ok = true;
    for (const auto& cs : cases) {
        const uint64_t actual = stress_kernel(cs.a, cs.b, cs.c);
        const uint64_t want   = expected(cs.a, cs.b, cs.c);
        const bool ok = (actual == want);
        std::printf("[test_vm_stress] a=0x%016llX b=0x%016llX c=0x%016llX -> 0x%016llX (%s)\n",
            static_cast<unsigned long long>(cs.a),
            static_cast<unsigned long long>(cs.b),
            static_cast<unsigned long long>(cs.c),
            static_cast<unsigned long long>(actual),
            ok ? "OK" : "FAIL");
        if (!ok) all_ok = false;
    }

    if (all_ok) {
        std::printf("[test_vm_stress] ALL CHECKS PASSED\n");
        return 0;
    }
    std::printf("[test_vm_stress] CHECKS FAILED\n");
    return 1;
}
