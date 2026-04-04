#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static volatile uint32_t g_counter = 0;

__declspec(noinline) uint32_t compute_fibonacci(uint32_t n) {
    if (n <= 1) return n;
    uint32_t a = 0, b = 1;
    for (uint32_t i = 2; i <= n; ++i) {
        uint32_t tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

__declspec(noinline) uint32_t compute_hash(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint32_t>(*str);
        ++str;
    }
    return hash;
}

__declspec(noinline) void do_arithmetic_work() {
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

__declspec(noinline) uint32_t compute_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

__declspec(noinline) uint32_t bit_manipulation_test(uint32_t seed) {
    uint32_t val = seed;
    for (int i = 0; i < 16; ++i) {
        val ^= (val << 13);
        val ^= (val >> 17);
        val ^= (val << 5);
    }
    return val;
}

__declspec(noinline) int32_t array_sort_and_sum(int32_t* arr, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (arr[j] < arr[i]) {
                int32_t tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
    int32_t sum = 0;
    for (size_t i = 0; i < n; ++i) {
        sum += arr[i];
    }
    return sum;
}

__declspec(noinline) uint64_t modular_exponent(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

int main() {
    DWORD pid = GetCurrentProcessId();
    std::printf("[test_target] PID = %u (via WinAPI GetCurrentProcessId)\n", pid);
    std::printf("[test_target] MxProtector CFF test\n");

    do_arithmetic_work();
    std::printf("[test_target] arithmetic counter = %u\n", g_counter);

    uint32_t fib20 = compute_fibonacci(20);
    std::printf("[test_target] fib(20) = %u\n", fib20);

    uint32_t h = compute_hash("MxProtector");
    std::printf("[test_target] hash('MxProtector') = 0x%08X\n", h);

    const char* msg = "CFF Engine Test Data";
    uint32_t crc = compute_crc32(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));
    std::printf("[test_target] crc32('%s') = 0x%08X\n", msg, crc);

    uint32_t xorshift = bit_manipulation_test(0xDEADBEEF);
    std::printf("[test_target] xorshift(0xDEADBEEF) = 0x%08X\n", xorshift);

    int32_t data[] = {42, -7, 13, 99, -33, 5, 0, 77, -1, 8};
    int32_t sorted_sum = array_sort_and_sum(data, 10);
    std::printf("[test_target] sorted_sum = %d\n", sorted_sum);

    uint64_t modexp = modular_exponent(7, 256, 1000000007ULL);
    std::printf("[test_target] modexp(7,256,1e9+7) = %llu\n", modexp);

    bool all_ok = (fib20 == 6765)
               && (g_counter != 0)
               && (crc == 0xFC61FD6D)
               && (sorted_sum == 203)
               && (modexp == 699853951ULL);

    if (all_ok) {
        std::printf("[test_target] ALL CHECKS PASSED\n");
        return 0;
    }

    std::printf("[test_target] CHECKS FAILED\n");
    return 1;
}
