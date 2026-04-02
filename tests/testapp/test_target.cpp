#include <cstdio>
#include <cstdint>
#include <cstdlib>

static volatile uint32_t g_counter = 0;

uint32_t compute_fibonacci(uint32_t n) {
    if (n <= 1) return n;
    uint32_t a = 0, b = 1;
    for (uint32_t i = 2; i <= n; ++i) {
        uint32_t tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

uint32_t compute_hash(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint32_t>(*str);
        ++str;
    }
    return hash;
}

void do_arithmetic_work() {
    volatile uint32_t x = 42;
    volatile uint32_t y = 17;

    uint32_t sum = x + y;
    uint32_t diff = x - y;
    uint32_t prod = x * y;
    uint32_t xored = x ^ y;
    uint32_t ored = x | y;
    uint32_t anded = x & y;

    g_counter += sum + diff + prod + xored + ored + anded;

    for (int i = 0; i < 100; ++i) {
        g_counter ^= static_cast<uint32_t>(i);
        g_counter += 1;
    }
}

int main() {
    std::printf("[test_target] MxProtector Phase 2 test\n");

    do_arithmetic_work();
    std::printf("[test_target] arithmetic counter = %u\n", g_counter);

    uint32_t fib20 = compute_fibonacci(20);
    std::printf("[test_target] fib(20) = %u\n", fib20);

    uint32_t h = compute_hash("MxProtector");
    std::printf("[test_target] hash('MxProtector') = 0x%08X\n", h);

    if (fib20 == 6765 && g_counter != 0) {
        std::printf("[test_target] ALL CHECKS PASSED\n");
        return 0;
    }

    std::printf("[test_target] CHECKS FAILED\n");
    return 1;
}
