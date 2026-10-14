/**
 * @file x64_entry_stub.cpp
 * @brief [BUILDER, x64] Entry stub emission — implementation.
 *
 * Split out of `x64_vm_backend.cpp` (R1.4). Owns the emission of the
 * VM entry stub: save rflags + 16 registers, seed the rolling key,
 * scramble vEFLAGS, derive the handler-table XOR key from the running
 * ImageBase through the G6 loop + MBA chain, run the handler-table
 * integrity check and the anti-emulation / anti-tamper picks, and
 * finish with the inline first dispatch.
 *
 * The implementation mirrors the original sequence byte-for-byte —
 * the only change is that the emitter no longer reaches into a
 * function-local RawEmitter / patch lists, it takes them via the
 * `EntryStubInputs` / `EntryStubSinks` boundary.
 */

#include "mxprotector/protection/vm/x64/x64_entry_stub.hpp"

#include <algorithm>
#include <cstdint>

#include "mxprotector/protection/anti_emulation/check_registry.hpp"
#include "mxprotector/protection/anti_tamper/check_registry.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"
#include "mxprotector/protection/cfg/mba_transition_gen.hpp"
#include "mxprotector/protection/vm/x64/x64_emitters.hpp"
#include "mxprotector/protection/vm/x64/x64_handlers.hpp"
#include "mxprotector/protection/vm/x64/x64_vflags.hpp"

namespace mx::vm::x64 {

namespace {

// ----------------------------------------------------------------------------
// G6 — loop-based key schedule.
//
// Before feeding the ImageBase into the MBA chain, run a short iterated
// bit-mix `f(x) = g(x) op K` applied N times. A symbolic execution
// engine that tries to express the full key derivation as a single
// constraint has to either unroll the loop N times (path explosion for
// N≥32) or infer a closed-form invariant for the iterated rotate-xor
// transform (no general technique does this at bit level). The loop
// adds ~17 emitted bytes and ~N ALU ops at runtime — microseconds for
// any sensible N, invisible next to the syscalls the tail anti-tamper
// checks already make.
//
// Three polymorphic shapes are chosen uniformly per build. Each is an
// 8-byte body encoded by hand; they all use eax as accumulator and no
// other register, so the loop counter sits in ecx without interference.
// ecx is freely clobberable here — the very next thing the entry stub
// emits after the MBA chain is a `mov ecx, total_handlers` for the
// integrity-check loop, so ecx is already dead at this point. Likewise
// for rflags: every instruction down to the anti-tamper checks clobbers
// them.
// ----------------------------------------------------------------------------

constexpr uint32_t kLoopVariantCount = 3;
enum : uint32_t {
    kVariantRolXor = 0,  // rol eax, rot; xor eax, K
    kVariantRorAdd = 1,  // ror eax, rot; add eax, K
    kVariantXorRol = 2,  // xor eax, K;   rol eax, rot
};

// Build-time application of the loop step, so the MBA chain's input
// matches what the runtime loop produces after `loop_count` iterations.
[[nodiscard]] uint32_t apply_g6_loop_step(
    uint32_t x, uint32_t variant, uint8_t rot, uint32_t key) noexcept
{
    switch (variant) {
        case kVariantRolXor: {
            const uint32_t r = (x << rot) | (x >> (32u - rot));
            return r ^ key;
        }
        case kVariantRorAdd: {
            const uint32_t r = (x >> rot) | (x << (32u - rot));
            return r + key;
        }
        case kVariantXorRol: {
            const uint32_t y = x ^ key;
            return (y << rot) | (y >> (32u - rot));
        }
        default:
            return x;  // unreachable — caller must clamp.
    }
}

// Emit the ImageBase → table-key derivation block. Returns the rel32 /
// imm32 patch positions that the later patcher needs (integrity-check
// `lea rbx, [rip + rel32]` and the expected-sum `xor edx, imm32`).
struct ImageBaseBlockOutputs {
    size_t integrity_table_lea_patch;
    size_t integrity_expected_patch;
};

ImageBaseBlockOutputs emit_imagebase_key_block(
    RawEmitter&                                    rt,
    const EntryStubInputs&                         in,
    uint32_t                                       table_xor_key,
    int32_t                                        imagebase_key_disp,
    size_t                                         entry_offset,
    std::vector<TablePatch>&                       table_patches,
    std::vector<anti_tamper::SelfCrcPatchRecord>&  self_crc_patches)
{
    ImageBaseBlockOutputs out{0, 0};

    //   65 48 8B 04 25 60 00 00 00   mov rax, gs:[0x60]    ; PEB
    //   48 8B 40 10                  mov rax, [rax + 0x10] ; ImageBase
    rt.u8(0x65); rt.u8(0x48); rt.u8(0x8B); rt.u8(0x04); rt.u8(0x25);
    rt.u8(0x60); rt.u8(0x00); rt.u8(0x00); rt.u8(0x00);
    rt.u8(0x48); rt.u8(0x8B); rt.u8(0x40); rt.u8(0x10);

    const uint32_t ib_low32 =
        static_cast<uint32_t>(in.opts.preferred_image_base & 0xFFFFFFFFULL);

    const uint32_t loop_variant = in.rng.next_range(0, kLoopVariantCount - 1);
    const uint32_t loop_count   = in.rng.next_range(32, 128);
    const uint8_t  loop_rot     = static_cast<uint8_t>(in.rng.next_range(1, 31));
    const uint32_t loop_key     = in.rng.next_u32();

    // Invariant: applying the runtime loop body N times to ib_low32
    // at build time yields the same value the runtime will have in
    // eax when the loop exits. Feed that into the MBA chain so the
    // MBA's output (=> table_xor_key) is identical at build and
    // runtime.
    uint32_t loop_output = ib_low32;
    for (uint32_t i = 0; i < loop_count; ++i) {
        loop_output = apply_g6_loop_step(loop_output, loop_variant, loop_rot, loop_key);
    }

    //   mov ecx, loop_count           B9 imm32
    rt.u8(0xB9);
    rt.u32(loop_count);
    // .loop:
    const size_t g6_loop_body_start = rt.size();
    switch (loop_variant) {
        case kVariantRolXor:
            //   rol eax, rot          C1 C0 rot
            rt.u8(0xC1); rt.u8(0xC0); rt.u8(loop_rot);
            //   xor eax, K            35 imm32
            rt.u8(0x35); rt.u32(loop_key);
            break;
        case kVariantRorAdd:
            //   ror eax, rot          C1 C8 rot
            rt.u8(0xC1); rt.u8(0xC8); rt.u8(loop_rot);
            //   add eax, K            05 imm32
            rt.u8(0x05); rt.u32(loop_key);
            break;
        case kVariantXorRol:
            //   xor eax, K            35 imm32
            rt.u8(0x35); rt.u32(loop_key);
            //   rol eax, rot          C1 C0 rot
            rt.u8(0xC1); rt.u8(0xC0); rt.u8(loop_rot);
            break;
        default:
            break;
    }
    //   dec ecx                       FF C9
    rt.u8(0xFF); rt.u8(0xC9);
    //   jnz .loop                     75 rel8
    {
        const size_t jnz_end = rt.size() + 2;
        const int32_t rel8 = static_cast<int32_t>(g6_loop_body_start) -
                             static_cast<int32_t>(jnz_end);
        rt.u8(0x75);
        rt.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    MbaTransitionGenerator mba_gen(Architecture::x64);
    auto chain = mba_gen.generate(
        loop_output, table_xor_key, mx::x86::Reg::rax, in.rng,
        /*state_preserved=*/true);
    rt.bytes(ByteView{chain.data(), chain.size()});

    // Handler-table integrity check.
    // lea rbx, [rip + rel32]    48 8D 1D rel32
    rt.u8(0x48); rt.u8(0x8D); rt.u8(0x1D);
    out.integrity_table_lea_patch = rt.size();
    rt.u32(0);
    table_patches.push_back({out.integrity_table_lea_patch, rt.size()});

    // mov ecx, total_handlers    B9 imm32
    rt.u8(0xB9);
    rt.u32(in.total_handlers);

    // xor edx, edx               31 D2
    rt.u8(0x31); rt.u8(0xD2);

    // .loop:
    const size_t loop_start = rt.size();
    rt.u8(0x33); rt.u8(0x13);              // xor edx, [rbx]
    rt.u8(0x48); rt.u8(0x83); rt.u8(0xC3); rt.u8(0x04);  // add rbx, 4
    rt.u8(0xFF); rt.u8(0xC9);              // dec ecx
    const size_t jnz_end = rt.size() + 2;
    const int32_t rel8 = static_cast<int32_t>(loop_start) -
                         static_cast<int32_t>(jnz_end);
    rt.u8(0x75); rt.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8))); // jnz

    // xor edx, <expected>        81 F2 imm32
    rt.u8(0x81); rt.u8(0xF2);
    out.integrity_expected_patch = rt.size();
    rt.u32(0);

    // xor eax, edx               31 D0
    rt.u8(0x31); rt.u8(0xD0);

    // mov [rsp + disp8], eax    89 44 24 disp8
    rt.u8(0x89); rt.u8(0x44); rt.u8(0x24);
    rt.u8(static_cast<uint8_t>(static_cast<int8_t>(imagebase_key_disp)));

    // Anti-emulation checks. Suppressed when the caller opted out
    // via `skip_anti_tamper_checks` — see VmGenOptions docs for why
    // S2c's inner VM needs this.
    if (!in.opts.skip_anti_tamper_checks) {
        static const anti_emulation::CheckRegistry registry;
        if (registry.size() > 0) {
            const size_t upper = std::min<size_t>(registry.size(), 2);
            const size_t count = in.rng.next_range(1, static_cast<uint32_t>(upper));
            const auto picks = registry.pick_random(count, in.rng);
            for (const auto* check : picks) {
                check->emit(rt, imagebase_key_disp, in.rng);
            }
        }
    }

    // G3 — Anti-tamper checks.
    //
    // These probe the running process for live debuggers, hardware
    // breakpoints, EDR hooks, and suspicious memory permissions.
    // The registry contains a mix of syscall-based checks
    // (hw_breakpoint_sweep, page_protection_sweep) and user-mode
    // checks (import_hook_detect, self_crc). We cap at one pick per
    // build: anti-tamper check bodies range from ~50 to ~150 bytes
    // each, and stacking several would bloat the entry stub without
    // proportional gain.
    //
    // The check's `required_syscall_name()` tells us whether we need
    // to emit a Hell's Gate resolver before the check runs, and which
    // function it should resolve. For non-syscall checks the name is
    // null and we skip the ~155-byte resolver block entirely — this
    // is what makes it cheap to add new user-mode checks without
    // touching the orchestration here. The backend folds a per-call
    // random salt into both the target-hash constant and the runtime
    // DJB2 seed, so the emitted resolver's `cmp eax, imm32` and
    // `mov eax, imm32` slots change from build to build.
    //
    // Suppressed when the caller opted out via
    // `skip_anti_tamper_checks`. Specifically, `page_protection_check`
    // reads its containing section's protection mask via
    // NtQueryVirtualMemory and expects the packer to have revoked
    // WRITE; S2c's inner VM lives in `.mxstr` which is intentionally
    // R+W+X (for the in-place XOR decrypt + sticky flag), so the
    // check would corrupt the handler-table key on roughly one build
    // in four.
    if (!in.opts.skip_anti_tamper_checks) {
        static const anti_tamper::CheckRegistry tamper_registry;
        if (tamper_registry.size() > 0) {
            const auto picks = tamper_registry.pick_random(1, in.rng);
            if (!picks.empty()) {
                const anti_tamper::ICheck* picked = picks[0];

                // Emit the Hell's Gate SSN resolver ONLY when the
                // picked check actually needs a syscall.
                const char* syscall_name = picked->required_syscall_name();
                if (syscall_name != nullptr && *syscall_name != '\0') {
                    const uint32_t salt = in.rng.next_u32();
                    const uint32_t target_hash =
                        anti_tamper::djb2_ascii_hash_salted(syscall_name, salt);
                    anti_tamper::emit_hells_gate_resolver(rt, target_hash, salt);
                }

                // Build the per-region context. Self-CRC reads
                // `entry_offset` from here to compute the rip-
                // relative rel32 back to the entry stub start, and
                // pushes into `self_crc_patches` so the backend can
                // finalise its expected-CRC imm32 after every other
                // post-hoc patch has landed.
                anti_tamper::CheckContext ctx{};
                ctx.entry_offset     = entry_offset;
                ctx.self_crc_patches = &self_crc_patches;
                picked->emit(rt, imagebase_key_disp, in.rng, ctx);
            }
        }
    }

    return out;
}

} // anonymous namespace

// ============================================================================
// Public entry point
// ============================================================================

EntryStubOutputs emit_entry_stub(
    RawEmitter&            rt,
    const EntryStubInputs& in,
    EntryStubSinks         sinks)
{
    EntryStubOutputs out{};
    out.entry_offset = rt.size();

    emit_pushfq(rt);

    // G7: extra padding slots between RFLAGS and the GPR area. After pushfq,
    // before the 16 reg pushes, emit `extra_pad_slots` × `push imm32` so the
    // GPR area still lands at [rsp + 0..120] but RFLAGS sits 8*N bytes higher.
    for (uint8_t p = 0; p < in.layout.extra_pad_slots; ++p) {
        rt.u8(0x68);
        rt.u32(in.rng.next_u32());
    }

    // 16 register pushes, permuted per-build. Push at position K lands at
    // offset (15-K)*8, so to put slot V at [rsp + V*8] we push it at K=15-V.
    // The junk slot (native RSP's would-be home) is filled with a dummy
    // `push rax` — its byte becomes the rolling-key scratch.
    for (int k = 0; k < 16; ++k) {
        const uint8_t v = static_cast<uint8_t>(15 - k);
        if (v == in.layout.junk_slot) {
            emit_push_reg(rt, 0);  // dummy push rax (value irrelevant)
        } else {
            emit_push_reg(rt, in.layout.slot_to_native[v]);
        }
    }

    // Seed the rolling key inside the junk slot. Displacement varies per-build.
    //   C6 44 24 disp8 ib     (disp ≤ 120 always)
    rt.u8(0xC6); rt.u8(0x44); rt.u8(0x24);
    rt.u8(static_cast<uint8_t>(in.rolling_key_disp));
    rt.u8(in.initial_key);

    // Transform the raw RFLAGS the entry's pushfq just wrote into the
    // scrambled form: slot = rol(real, vflags_rol) ^ vflags_key.
    if (in.vflags_key != 0 || in.vflags_rol != 0) {
        emit_vflags_inslot_scramble(rt, pick_inslot_variant(in.rng),
                                     in.vflags_key, in.vflags_rol, in.rflags_disp);
    }

    // Handler-table key derivation: if `opts.use_imagebase_key` is set,
    // compute the key at runtime from PEB.ImageBaseAddress and store it in
    // the upper 4 bytes of the junk slot ([rsp + rolling_key_disp + 4]).
    // Every tail dispatch then reads `xor eax, [rsp + disp8]` instead of
    // carrying an imm32 — the table key never appears as a literal.
    out.imagebase_key_disp =
        in.opts.use_imagebase_key ? (in.rolling_key_disp + 4) : -1;

    // Handler-table encryption key.
    out.table_xor_key = in.opts.use_imagebase_key
        ? in.rng.next_u32()
        : (in.rng.next_u32() | 1);  // legacy path wants non-zero

    out.integrity_table_lea_patch = 0;
    out.integrity_expected_patch  = 0;

    if (in.opts.use_imagebase_key) {
        const auto ib = emit_imagebase_key_block(
            rt, in,
            out.table_xor_key,
            out.imagebase_key_disp,
            out.entry_offset,
            sinks.table_patches,
            sinks.self_crc_patches);
        out.integrity_table_lea_patch = ib.integrity_table_lea_patch;
        out.integrity_expected_patch  = ib.integrity_expected_patch;
    }

    // lea r11, [rip + bytecode_rel32]
    out.entry_bc_patch     = emit_lea_r11_rip_rel32(rt);
    out.entry_bc_patch_end = rt.size();

    // Inline first dispatch. Polymorphism on: entry is a prime signature
    // target, so it gets a random table-base reg and dispatch shape just
    // like handler tails.
    const auto entry_tail = emit_tail_dispatch(
        rt, in.rolling_key_disp, in.rolling,
        /*save_rflags=*/false, sinks.table_key_patches,
        in.vflags_key, in.vflags_rol,
        in.rflags_disp, in.rng,
        out.imagebase_key_disp);
    sinks.table_patches.push_back({entry_tail.rel32_offset, entry_tail.instruction_end});

    return out;
}

} // namespace mx::vm::x64
