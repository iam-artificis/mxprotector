/**
 * @file test_vm_branch.cpp
 * @brief Тест виртуальных переходов (VJMP/VJCC) в VM.
 *
 * Содержит условные ветвления и цикл внутри MX_VM_BEGIN/END.
 * Проверяет, что VM правильно выполняет JMP/JCC путём сравнения
 * результатов с незащищённой эталонной реализацией.
 */

#include <cstdint>
#include <cstdio>

#include "mxprotector_sdk/markers.hpp"

__declspec(noinline) uint64_t branch_kernel(uint64_t n) {
    uint64_t acc = 0;
    uint64_t i   = 0;
    MX_VM_BEGIN
loop:
    if (i >= n) goto done;
    acc += i;
    i   += 1;
    goto loop;
done:
    acc ^= 0xCAFE;
    MX_VM_END
    return acc;
}

int main() {
    std::printf("[test_vm_branch] start\n");

    auto expected = [](uint64_t n) -> uint64_t {
        uint64_t acc = 0;
        for (uint64_t i = 0; i < n; ++i) acc += i;
        acc ^= 0xCAFE;
        return acc;
    };

    struct Case { uint64_t n; };
    const Case cases[] = { {0}, {1}, {5}, {10}, {100}, {1000} };
    bool all_ok = true;

    for (const auto& cs : cases) {
        const uint64_t actual = branch_kernel(cs.n);
        const uint64_t want  = expected(cs.n);
        const bool ok = (actual == want);
        std::printf("[test_vm_branch] n=%llu -> 0x%016llX (%s)\n",
            static_cast<unsigned long long>(cs.n),
            static_cast<unsigned long long>(actual),
            ok ? "OK" : "FAIL");
        if (!ok) all_ok = false;
    }

    if (all_ok) {
        std::printf("[test_vm_branch] ALL CHECKS PASSED\n");
        return 0;
    }
    std::printf("[test_vm_branch] CHECKS FAILED\n");
    return 1;
}
