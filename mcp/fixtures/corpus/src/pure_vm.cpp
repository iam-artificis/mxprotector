/**
 * @file pure_vm.cpp
 * @brief Corpus sample — VM-heavy, no CFF surface to speak of.
 *
 * Single function with one MX_VM_BEGIN/END region wrapping an
 * integer-only computation. The protected binary exercises the VM
 * handler table on a tight loop + XOR pattern, making this a focused
 * input for the VM benchmark (angr handler-summarization, bytecode
 * entropy, handler opcode histogram).
 *
 * Kept small on purpose: the benchmark signal should come from the VM
 * pass, not from incidental flow complexity.
 */

#include <cstdio>
#include <cstdint>

#include <mxprotector_sdk/api.hpp>

int main() {
    std::uint32_t acc = 0;

    MX_VM_BEGIN
    for (int i = 1; i <= 16; ++i) {
        acc += static_cast<std::uint32_t>(i * i);
        acc = (acc << 3) ^ (acc >> 5);
    }
    acc ^= 0xDEADBEEFu;
    MX_VM_END

    std::printf("pure_vm: %u\n", acc);
    return 0;
}
