/**
 * @file hash_opaque_predicate.cpp
 * @brief G6 — hash-based opaque predicate emitter implementation.
 *
 * See hash_opaque_predicate.hpp for the design rationale.
 */

#include "mxprotector/protection/obfuscation/hash_opaque_predicate.hpp"

#include <bit>
#include <cstring>

namespace mx::obf {

namespace {

/// `std::rotl` requires C++20; the project is on C++23 so it is
/// always available, but we wrap it in a constexpr alias so the
/// compute helper stays self-documenting at the call site.
[[nodiscard]] constexpr uint32_t rotl32(uint32_t v, uint8_t r) noexcept {
    return std::rotl(v, r);
}

} // namespace

HashOpaqueParams randomize_hash_opaque_params(Randomizer& rng) {
    HashOpaqueParams p;
    p.input_value = rng.next_u32();
    // Force multipliers odd so each round stays bijective on uint32.
    // An even multiplier loses one bit of entropy per round (the
    // low bit of the result is always 0), which over three rounds
    // would collapse the output space and make the build-time hash
    // value statistically biased toward small values.
    p.mul1 = rng.next_u32() | 1u;
    p.mul2 = rng.next_u32() | 1u;
    p.mul3 = rng.next_u32() | 1u;
    p.xor1 = rng.next_u32();
    p.xor2 = rng.next_u32();
    // [1, 31] — 0 and 32 are encoded fine but produce no rotation,
    // collapsing one of the three mixing primitives to a no-op.
    p.rotation = static_cast<uint8_t>(rng.next_range(1, 31));
    return p;
}

uint32_t compute_hash_opaque(const HashOpaqueParams& p) noexcept {
    uint32_t acc = p.input_value;
    acc *= p.mul1;
    acc ^= p.xor1;
    acc *= p.mul2;
    acc  = rotl32(acc, p.rotation);
    acc *= p.mul3;
    acc ^= p.xor2;
    return acc;
}

void emit_hash_opaque_predicate(RawEmitter&             e,
                                const HashOpaqueParams& p,
                                Randomizer&             rng)
{
    const uint32_t target = compute_hash_opaque(p);

    // ----------------------------------------------------------------
    // (1) mov eax, [rip + disp32]              8B 05 disp32
    //
    //     The displacement is patched at the end of this function once
    //     the location of the embedded `.input` blob is known. The
    //     `rip` value Intel uses for this addressing form is the
    //     address of the byte right after the instruction, so
    //     `disp32 = .input_offset - end_of_mov_offset`.
    // ----------------------------------------------------------------
    e.u8(0x8B); e.u8(0x05);
    const size_t disp_patch_offset = e.size();
    e.u32(0);
    const size_t end_of_mov_offset = e.size();

    // ----------------------------------------------------------------
    // (2..7) Three-round mixing: imul / xor / imul / rol / imul / xor
    //
    // Each `imul eax, eax, imm32` is `69 C0 imm32` (6 bytes). Each
    // `xor eax, imm32` is `35 imm32` (5 bytes — the EAX-special form
    // is shorter than the generic `81 F0 imm32`). The rotation is
    // `C1 C0 imm8` (3 bytes).
    //
    // Engines that reason symbolically about the predicate end up
    // with a constraint of the form
    //     ((((I * m1) ^ x1) * m2) <<< r * m3) ^ x2 == target
    // which mixes integer multiplication with XOR and a rotation —
    // a combination that defeats most off-the-shelf SAT/SMT-backed
    // symbolic execution engines. Concrete evaluation through the
    // memory load is still trivially cheap, so engines that prefer
    // concrete propagation just confirm the predicate is always-true
    // and prune the false branch.
    // ----------------------------------------------------------------

    // imul eax, eax, mul1                    69 C0 imm32
    e.u8(0x69); e.u8(0xC0); e.u32(p.mul1);

    // xor eax, xor1                          35 imm32
    e.u8(0x35); e.u32(p.xor1);

    // imul eax, eax, mul2                    69 C0 imm32
    e.u8(0x69); e.u8(0xC0); e.u32(p.mul2);

    // rol eax, rotation                      C1 C0 imm8
    e.u8(0xC1); e.u8(0xC0); e.u8(p.rotation);

    // imul eax, eax, mul3                    69 C0 imm32
    e.u8(0x69); e.u8(0xC0); e.u32(p.mul3);

    // xor eax, xor2                          35 imm32
    e.u8(0x35); e.u32(p.xor2);

    // ----------------------------------------------------------------
    // (8) cmp eax, target                    3D imm32
    //     target = compute_hash_opaque(p) — the value the runtime
    //     hash chain is GUARANTEED to produce on a clean host. The
    //     subsequent `jne` therefore always falls through.
    // ----------------------------------------------------------------
    e.u8(0x3D); e.u32(target);

    // ----------------------------------------------------------------
    // (9) jne short .false                   75 rel8 (placeholder)
    //
    //     Distance is small enough for rel8 — the false-branch body
    //     and the embedded input together fit inside ~16 bytes.
    // ----------------------------------------------------------------
    e.u8(0x75);
    const size_t jne_rel8_offset = e.size();
    e.u8(0x00);

    // ----------------------------------------------------------------
    // (10) jmp short .end                    EB rel8 (placeholder)
    //
    //     Always taken at runtime. The fall-through path resumes at
    //     `.end`, which lives PAST both the false-branch body and
    //     the embedded input data — so neither is ever executed.
    // ----------------------------------------------------------------
    e.u8(0xEB);
    const size_t jmp_to_end_rel8_offset = e.size();
    e.u8(0x00);

    // ----------------------------------------------------------------
    // .false: never reached at runtime, but a static disassembler
    // following the `jne` will decode and explore the body. Keep it
    // shaped like ordinary code so symbolic engines that try to
    // pursue the false path have to allocate state for it instead
    // of immediately recognising it as garbage.
    //
    //   mov eax, <junk_imm>                  B8 imm32     (5 bytes)
    //   ret                                  C3            (1 byte)
    //
    // Total: 6 bytes. The trailing `ret` makes the false-branch look
    // like a tiny tail-call, which matches the kind of pattern engines
    // expect at the end of a basic block — they stop following past it
    // and return to whoever invoked them, multiplying confusion in the
    // surrounding callgraph view without affecting real execution.
    // ----------------------------------------------------------------
    {
        const size_t false_label = e.size();
        const int32_t jne_rel = static_cast<int32_t>(false_label) -
                                static_cast<int32_t>(jne_rel8_offset + 1);
        e.buf[jne_rel8_offset] = static_cast<uint8_t>(static_cast<int8_t>(jne_rel));
    }

    // mov eax, <junk_imm>                    B8 imm32
    e.u8(0xB8);
    e.u32(rng.next_u32());
    // ret                                    C3
    e.u8(0xC3);

    // ----------------------------------------------------------------
    // .input: 4 bytes of constant input, read by the rip-relative
    // mov at the start of the predicate. Lives PAST the false branch
    // so it's never reached by linear execution but always reachable
    // via the rip-relative load (which is just a memory read,
    // doesn't care that the bytes don't decode as instructions).
    // ----------------------------------------------------------------
    const size_t input_offset = e.size();
    e.u32(p.input_value);

    // ----------------------------------------------------------------
    // .end: predicate exit point. The caller's next emission lands
    // here on the always-taken path.
    // ----------------------------------------------------------------
    {
        const size_t end_label = e.size();
        const int32_t jmp_rel = static_cast<int32_t>(end_label) -
                                static_cast<int32_t>(jmp_to_end_rel8_offset + 1);
        e.buf[jmp_to_end_rel8_offset] = static_cast<uint8_t>(static_cast<int8_t>(jmp_rel));
    }

    // Patch the rip-relative disp32 in the initial mov.
    {
        const int32_t disp = static_cast<int32_t>(input_offset) -
                             static_cast<int32_t>(end_of_mov_offset);
        std::memcpy(e.buf.data() + disp_patch_offset, &disp, sizeof(disp));
    }
}

} // namespace mx::obf
