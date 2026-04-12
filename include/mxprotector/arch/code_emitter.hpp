/**
 * @file code_emitter.hpp
 * @brief Abstract code emitter for target-agnostic codegen.
 *
 * Today every piece of MxProtector that emits machine code does it the x64
 * way: push raw bytes into a `ByteBuffer`, ModRM by hand, rel32 patches
 * tracked by index. This file is the seam we want to grow into for arm64
 * and eventually Cortex-M.
 *
 * `ICodeEmitter` exposes the SMALLEST set of high-level operations that
 * every pass actually performs, rather than trying to cover every instruction
 * the ISA supports:
 *
 *   - move between registers / load an immediate
 *   - basic arithmetic (add, sub, xor)
 *   - load / store to [base + disp]
 *   - call / return / unconditional jump / conditional jump
 *   - labels and relocations (the emitter tracks them internally)
 *
 * This is the same "IR backend" approach LLVM uses — each architecture
 * implements the interface once, and every pass is written against the
 * interface. Arithmetic identity, mutation rules, CFG flattening, packer
 * stub assembly, VM runtime assembly all become target-agnostic.
 *
 * What this file is NOT
 * ---------------------
 * - Not yet implemented. Today's passes still emit raw x64 bytes and the
 *   existing x86_code_emitter.cpp is the unique x64 implementation. This
 *   header is Phase 5 scaffolding.
 * - Not a 1:1 LLVM MIR replacement. We keep the operation set small on
 *   purpose — we need exactly what the protector passes need, no more.
 * - Not a disassembler. Lifting is handled by the lifter (Zydis today,
 *   Capstone/LLVM for arm64 later).
 *
 * Register abstraction
 * --------------------
 * Architectures have wildly different register sets:
 *   - x64: 16 GPRs (rax..r15), each aliased in 64/32/16/8-bit forms
 *   - arm64: 31 GPRs (x0..x30) + SP + XZR, 64/32-bit aliasing
 *   - Cortex-M: 13 low GPRs + SP/LR/PC, Thumb-restricted encoding
 *
 * `Reg` here is an opaque u8 id in the target's canonical numbering. The
 * backend's `ICodeEmitter` is responsible for validating that a caller
 * didn't pass e.g. `Reg{31}` to a 16-GPR target. The pass side picks regs
 * by symbolic role (e.g. "state variable", "scratch A") via a future
 * `IRegAllocator` — not modelled here.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/arch/arch_info.hpp"

namespace mx::arch {

/// Opaque register handle. Meaning depends on the backend's register file.
struct Reg {
    uint8_t id = 0;
    uint8_t width = 8;   ///< operand width in bytes (1, 2, 4, 8, 16, …)
    [[nodiscard]] constexpr bool operator==(const Reg&) const noexcept = default;
};

/// Opaque label handle. Labels are defined by the backend when `create_label`
/// is called and bound when `bind_label` is called; code referencing them
/// (calls, jumps) patches the relocation table at `build()` time.
struct Label {
    uint32_t id = 0;
};

/// x86-style condition codes. arm64 backends translate these to the
/// equivalent A64 `cond` encoding.
enum class CondCode : uint8_t {
    overflow     = 0,   ///< OF == 1
    no_overflow  = 1,
    below        = 2,   ///< CF == 1    (unsigned <)
    above_equal  = 3,
    equal        = 4,   ///< ZF == 1
    not_equal    = 5,
    below_equal  = 6,
    above        = 7,
    sign         = 8,   ///< SF == 1    (signed negative)
    no_sign      = 9,
    parity_even  = 10,
    parity_odd   = 11,
    less         = 12,  ///< signed <
    greater_equal= 13,
    less_equal   = 14,
    greater      = 15,
};

/**
 * @brief Abstract code emitter.
 *
 * Each target architecture implements this once; every pass writes against
 * the interface and becomes automatically portable. The backend internally
 * maintains:
 *
 *   - a `ByteBuffer` under construction
 *   - a relocation table (label bindings, pending rel32/rel8/br sites)
 *   - any target-specific state (MOV-pair patching for arm64, Thumb mode
 *     for Cortex-M, etc.)
 *
 * Methods that return `MxStatus` report target-specific failures (e.g.
 * out-of-range immediate, unsupported opcode combination). Callers should
 * propagate errors rather than assume success.
 *
 * Thread-safety: one emitter per pass invocation, single-threaded use.
 */
class ICodeEmitter {
public:
    virtual ~ICodeEmitter() = default;

    /// @brief Target architecture this emitter produces code for.
    [[nodiscard]] virtual ArchInfo arch() const noexcept = 0;

    // ------------------------------------------------------------------------
    // Buffer management
    // ------------------------------------------------------------------------

    /// Current byte size of the produced code.
    [[nodiscard]] virtual size_t current_size() const noexcept = 0;

    /// Finalize and return the code. Applies all pending label fix-ups.
    /// Fails if a label is referenced but never bound.
    [[nodiscard]] virtual MxResult<ByteBuffer> build() = 0;

    /// Append raw bytes verbatim. Escape hatch for instructions the abstract
    /// interface doesn't cover. Relocations inside the raw block are the
    /// caller's responsibility.
    virtual MxStatus raw(ByteView bytes) = 0;

    // ------------------------------------------------------------------------
    // Labels and relocations
    // ------------------------------------------------------------------------

    /// Create an unbound forward label.
    [[nodiscard]] virtual Label create_label() = 0;

    /// Bind `label` to the current emission offset.
    virtual MxStatus bind_label(Label label) = 0;

    // ------------------------------------------------------------------------
    // Data movement
    // ------------------------------------------------------------------------

    /// `dst = src` (register-to-register move, preserving width).
    virtual MxStatus mov_rr(Reg dst, Reg src) = 0;

    /// `dst = imm` (load immediate). Backends widen as needed.
    virtual MxStatus mov_ri(Reg dst, uint64_t imm) = 0;

    /// `dst = [base + disp]`
    virtual MxStatus load(Reg dst, Reg base, int32_t disp) = 0;

    /// `[base + disp] = src`
    virtual MxStatus store(Reg base, int32_t disp, Reg src) = 0;

    // ------------------------------------------------------------------------
    // Arithmetic and logic (sets condition flags where applicable)
    // ------------------------------------------------------------------------

    virtual MxStatus add_rr(Reg dst, Reg src) = 0;
    virtual MxStatus sub_rr(Reg dst, Reg src) = 0;
    virtual MxStatus xor_rr(Reg dst, Reg src) = 0;
    virtual MxStatus and_rr(Reg dst, Reg src) = 0;
    virtual MxStatus or_rr (Reg dst, Reg src) = 0;

    virtual MxStatus add_ri(Reg dst, int32_t imm) = 0;
    virtual MxStatus sub_ri(Reg dst, int32_t imm) = 0;
    virtual MxStatus xor_ri(Reg dst, int32_t imm) = 0;
    virtual MxStatus cmp_ri(Reg lhs, int32_t imm) = 0;

    // ------------------------------------------------------------------------
    // Control flow
    // ------------------------------------------------------------------------

    /// Unconditional jump to `target`.
    virtual MxStatus jmp(Label target) = 0;

    /// Conditional jump based on last-set flags (or NZCV on arm64).
    virtual MxStatus jcc(CondCode cc, Label target) = 0;

    /// Direct call (label → rel32/bl).
    virtual MxStatus call(Label target) = 0;

    /// Function return.
    virtual MxStatus ret() = 0;
};

/**
 * @brief Factory that constructs the `ICodeEmitter` for a given target.
 *
 * Selected by the pipeline based on `ctx.target().arch` (and optionally the
 * detailed `ArchInfo` if the caller wants to pin a specific variant). The
 * factory encapsulates "which backend implements which arch" so passes
 * never do `if (is_x64) ... else if (is_arm64) ...` at their call site.
 */
class ICodeEmitterFactory {
public:
    virtual ~ICodeEmitterFactory() = default;

    /// Which architecture families this factory can produce emitters for.
    /// Used by the pipeline to pick the right factory.
    [[nodiscard]] virtual ArchFamily supported_family() const noexcept = 0;

    /// Construct a fresh emitter for `info`. `info.family` must match
    /// `supported_family()`; richer `info` allows the backend to pick
    /// instruction forms (e.g. LSE atomics on arm64 v8.1a+).
    [[nodiscard]] virtual std::unique_ptr<ICodeEmitter>
        create(ArchInfo info) = 0;
};

} // namespace mx::arch
