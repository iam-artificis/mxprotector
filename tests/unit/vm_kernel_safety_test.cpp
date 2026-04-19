/**
 * @file vm_kernel_safety_test.cpp
 * @brief [TESTS] Ring0-safety invariants of the VM runtime entry stub.
 *
 * The VM entry stub has two optional code paths that reach into the
 * user-mode PEB:
 *
 *   1. `emit_imagebase_key_block` — reads `PEB.ImageBaseAddress` via
 *      `mov rax, gs:[0x60]`. Gated by `VmGenOptions::use_imagebase_key`.
 *   2. Anti-tamper / anti-emulation picks — some of them resolve ntdll
 *      syscalls via Hell's Gate, which also walks `gs:[0x60]` to find
 *      the PEB. Gated by `VmGenOptions::skip_anti_tamper_checks`.
 *
 * In ring0 `gs:` is KPCR, not PEB — the same byte sequence reads
 * garbage and corrupts the handler-table key on the first dispatch.
 * `VirtualizationPass` now flips both gates when it sees a kernel-
 * driver target; these tests pin the invariant at the generator level
 * so a future edit that removes `skip_anti_tamper_checks` from the
 * driver-path options, or that introduces a new PEB-touching block
 * without gating it, fails loudly.
 *
 * Strategy: generate a minimal VM runtime with both flags set to the
 * ring0-safe combination, and assert the raw blob contains no
 * `mov rax, gs:[0x60]` signature (`65 48 8B 04 25 60 00 00 00`).
 *
 * A sanity test with `use_imagebase_key = true` proves the pattern
 * actually appears when the gate is opened, so the negative test
 * isn't vacuous.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace {

using mx::Randomizer;
using mx::vm::VmGenOptions;
using mx::vm::VmInstruction;
using mx::vm::VmOp;
using mx::vm::VmRuntimeGenerator;

// `mov rax, gs:[0x60]` — the one PEB fetch we must never emit in a
// driver-path runtime. GS override + REX.W + MOV r64, r/m64 + ModR/M
// (rax, SIB follows) + SIB (no index, disp32 base) + disp32 == 0x60.
constexpr std::array<uint8_t, 9> kPebFetchPattern = {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
};

// Build a minimal single-instruction VM body: one NATIVE NOP. The
// generator rejects fully-empty input (it needs at least one op to
// emit a dispatch after the entry stub), so we feed it the smallest
// byte-stable instruction that carries no flags invariants.
std::vector<VmInstruction> make_minimal_body() {
    VmInstruction nop{};
    nop.op = VmOp::native;
    nop.native_bytes = {0x90};  // NOP
    return {nop};
}

// Return true iff `needle` appears anywhere in `haystack`.
bool blob_contains(const mx::ByteBuffer& haystack,
                   const std::array<uint8_t, 9>& needle)
{
    return std::search(haystack.begin(), haystack.end(),
                       needle.begin(), needle.end()) != haystack.end();
}

TEST(VmKernelSafety, NoPebFetchWhenDriverPathOptionsSet) {
    Randomizer rng{0xD12E57ull};  // deterministic
    VmGenOptions opts{
        .emit_exit_as_jmp        = false,
        .use_imagebase_key       = false,      // no emit_imagebase_key_block
        .preferred_image_base    = 0x140000000ULL,
        .skip_anti_tamper_checks = true,       // no anti-tamper + no Hell's Gate
    };

    auto result = VmRuntimeGenerator{}.generate(make_minimal_body(), rng, opts);
    ASSERT_TRUE(result.has_value()) << result.error().message();

    EXPECT_FALSE(blob_contains(result->blob, kPebFetchPattern))
        << "Driver-path VM runtime unexpectedly contains "
           "`mov rax, gs:[0x60]`. Either the imagebase-key block or a "
           "Hell's Gate resolver snuck past the VmGenOptions gates.";
}

// Sanity: flipping `use_imagebase_key` back on must restore the PEB
// fetch. If this ever starts producing an empty blob or failing to
// emit the pattern, the negative test above is no longer meaningful —
// the assertion structure itself has drifted from reality and should
// be revisited.
TEST(VmKernelSafety, PebFetchReappearsWhenImagebaseKeyEnabled) {
    Randomizer rng{0xD12E57ull};
    VmGenOptions opts{
        .emit_exit_as_jmp        = false,
        .use_imagebase_key       = true,       // block now emitted
        .preferred_image_base    = 0x140000000ULL,
        .skip_anti_tamper_checks = true,       // still suppress random picks
    };

    auto result = VmRuntimeGenerator{}.generate(make_minimal_body(), rng, opts);
    ASSERT_TRUE(result.has_value()) << result.error().message();

    EXPECT_TRUE(blob_contains(result->blob, kPebFetchPattern))
        << "VM runtime with use_imagebase_key=true is expected to emit "
           "`mov rax, gs:[0x60]` inside emit_imagebase_key_block — "
           "the pattern signature drifted or the block was moved.";
}

} // namespace
