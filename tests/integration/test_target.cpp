#include <cstdio>
#include <cstdint>

__declspec(noinline) int compute_sum(int a, int b) {
    int result = 0;
    for (int i = a; i <= b; ++i) {
        result += i;
    }
    return result;
}

__declspec(noinline) int compute_factorial(int n) {
    if (n <= 1) return 1;
    int result = 1;
    for (int i = 2; i <= n; ++i) {
        result *= i;
    }
    return result;
}

__declspec(noinline) uint32_t compute_fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    uint32_t a = 0, b = 1;
    for (int i = 2; i <= n; ++i) {
        uint32_t c = a + b;
        a = b;
        b = c;
    }
    return b;
}

__declspec(noinline) int bitwise_ops(int x, int y) {
    int a = x ^ y;
    int b = x & y;
    int c = x | y;
    return a + b + c;
}

int main() {
    printf("=== MxProtector Test Target ===\n");

    int sum = compute_sum(1, 100);
    printf("Sum(1..100)    = %d (expected 5050)\n", sum);

    int fact = compute_factorial(10);
    printf("Factorial(10)  = %d (expected 3628800)\n", fact);

    uint32_t fib = compute_fibonacci(20);
    printf("Fibonacci(20)  = %u (expected 6765)\n", fib);

    int bits = bitwise_ops(0xDEAD, 0xBEEF);
    printf("BitwiseOps     = %d (expected %d)\n", bits,
           (0xDEAD ^ 0xBEEF) + (0xDEAD & 0xBEEF) + (0xDEAD | 0xBEEF));

    bool all_ok = (sum == 5050)
               && (fact == 3628800)
               && (fib == 6765)
               && (bits == ((0xDEAD ^ 0xBEEF) + (0xDEAD & 0xBEEF) + (0xDEAD | 0xBEEF)));

    printf("\nResult: %s\n", all_ok ? "ALL PASSED" : "FAILED");
    return all_ok ? 0 : 1;
}
