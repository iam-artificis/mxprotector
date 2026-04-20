/**
 * @file pure_cff.cpp
 * @brief Corpus sample — CFF surface, no VM markers.
 *
 * Several small functions with branches and a loop. The CFG-flattening
 * pass turns each into a dispatcher + state table, which is the
 * surface that the CFF benchmark measures (d810 state-recovery rate,
 * HexRays microcode goto count, back-edge ratio).
 *
 * Deliberately no SDK markers — we want the protector's automatic
 * function selection to pick up these functions and flatten them
 * based on the `strong` heuristics rather than explicit hints.
 */

#include <cstdio>
#include <cstdint>

namespace {

int leaf_a(int x) {
    if (x > 0) {
        return x * 2 + 1;
    }
    if (x == 0) {
        return 7;
    }
    return -x + 3;
}

int leaf_b(int x) {
    int base = leaf_a(x);
    return (x & 1) ? base + 11 : base - 5;
}

int core(int x) {
    int acc = 0;
    for (int i = 0; i < 6; ++i) {
        int v = leaf_b(x + i);
        if (v > 100) {
            acc += v / 2;
        } else if (v < -50) {
            acc -= v;
        } else {
            acc ^= v;
        }
    }
    return acc;
}

} // namespace

int main() {
    int r = 0;
    for (int x = 1; x <= 10; ++x) {
        r ^= core(x);
    }
    std::printf("pure_cff: %d\n", r);
    return 0;
}
