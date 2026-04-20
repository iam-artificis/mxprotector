/**
 * @file mixed.cpp
 * @brief Corpus sample — realistic mix: VM region + mutation region +
 *        string literal + ordinary branching.
 *
 * Representative of a protected binary produced at level=strong with
 * default markers. Benchmarks that don't filter by corpus tag end up
 * reading this sample as the "average case" — it's the one where
 * ensemble effects between VM / mutation / strings / CFF actually
 * show up.
 */

#include <cstdio>
#include <cstdint>

#include <mxprotector_sdk/api.hpp>

namespace {

std::uint32_t compute_vm(std::uint32_t x) {
    std::uint32_t r = 0;
    MX_VM_BEGIN
    r = x * x + 13u;
    r ^= (x << 3);
    r = (r * 0x9E3779B1u) ^ (r >> 11);
    MX_VM_END
    return r;
}

std::uint32_t compute_mutated(std::uint32_t x) {
    MX_MUTATE_BEGIN
    std::uint32_t r = x + 1u;
    r = r * 3u;
    r ^= 0xABu;
    r += (x >> 2);
    MX_MUTATE_END
    return r;
}

} // namespace

int main() {
    auto banner = MX_STR("corpus:mixed:v1");
    std::printf("%s\n", banner.c_str());

    std::uint32_t acc = 0;
    for (std::uint32_t i = 0; i < 8u; ++i) {
        acc ^= compute_vm(i) + compute_mutated(i);
    }
    std::printf("mixed: %u\n", acc);
    return 0;
}
