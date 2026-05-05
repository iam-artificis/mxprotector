/**
 * @file mba_rewriter_test.cpp
 * @brief [TESTS] MBA rewriter contract + per-family unit tests.
 *
 * The decoder (`decode_alu_imm32`) is the entry point every imm32
 * rewriter shares — its tests cover REX.B / REX.W / unsupported
 * /op extensions in one place. Each per-family rewriter then gets:
 *
 *   * a positive-match test (raw bytes for `<op> rax, K`),
 *   * a negative-match test (a foreign op that must be rejected),
 *   * a byte-shape test that decodes the emitted body via the
 *     local `MbaSimulator` and confirms the body computes
 *     `x <op> K` for a property-style sweep of `(x, K)` pairs.
 *
 * The simulator is intentionally tiny — it only handles the
 * instruction subset every shipped rewriter currently emits. New
 * MBA shapes that introduce new opcodes either extend the
 * simulator or land their own simulator in a sibling test file.
 *
 * Registry- and adapter-level tests live below the per-family
 * blocks.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"
#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace {

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build an `Instruction` from raw bytes for the test harness. Mirrors
/// the helper in `mutation_engine_test.cpp` so both files share the
/// same value-object surface.
mx::analysis::Instruction make_insn(
    mx::ByteBuffer raw_bytes,
    std::string    mnemonic,
    std::string    operands = "")
{
    const auto length = static_cast<std::uint8_t>(raw_bytes.size());
    return mx::analysis::Instruction(
        /*address=*/0x1000,
        length,
        std::move(raw_bytes),
        std::move(mnemonic),
        std::move(operands),
        /*is_branch=*/false,
        /*is_conditional_branch=*/false,
        /*is_call=*/false,
        /*is_return=*/false,
        /*is_unconditional_jump=*/false,
        /*branch_targets=*/{});
}

/// Encode `<op> rax, K` for the supported 5 group-1 ALU ops as
/// `48 81 /op id` (REX.W). Used to feed the rewriters realistic
/// bytes without depending on the Zydis bridge.
mx::ByteBuffer encode_alu_imm32_rax(
    mx::mutation::mba::AluImm32Op op,
    std::uint32_t                 imm)
{
    mx::ByteBuffer bytes;
    bytes.reserve(7);
    bytes.push_back(0x48);                                  // REX.W
    bytes.push_back(0x81);                                  // group-1
    bytes.push_back(static_cast<std::uint8_t>(
        0xC0 | (static_cast<std::uint8_t>(op) << 3)));      // mod=3, reg=op, rm=rax(0)
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::uint8_t>((imm >> (i * 8)) & 0xFF));
    }
    return bytes;
}

/// Encode `<op> EAX, imm32` short form (no REX) — 5 bytes:
/// opcode byte from `(reg << 3) | 0x05`, then 4 imm bytes.
mx::ByteBuffer encode_alu_imm32_short_eax(
    mx::mutation::mba::AluImm32Op op,
    std::uint32_t                 imm)
{
    mx::ByteBuffer bytes;
    bytes.reserve(5);
    bytes.push_back(static_cast<std::uint8_t>(
        (static_cast<std::uint8_t>(op) << 3) | 0x05));
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::uint8_t>((imm >> (i * 8)) & 0xFF));
    }
    return bytes;
}

/// Encode `<op> RAX, imm32` short form (REX.W) — 6 bytes.
mx::ByteBuffer encode_alu_imm32_short_rax(
    mx::mutation::mba::AluImm32Op op,
    std::uint32_t                 imm)
{
    mx::ByteBuffer bytes;
    bytes.reserve(6);
    bytes.push_back(0x48); // REX.W
    bytes.push_back(static_cast<std::uint8_t>(
        (static_cast<std::uint8_t>(op) << 3) | 0x05));
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::uint8_t>((imm >> (i * 8)) & 0xFF));
    }
    return bytes;
}

mx::ByteBuffer encode_mov_eax_imm32(std::uint32_t imm) {
    mx::ByteBuffer bytes;
    bytes.reserve(5);
    bytes.push_back(0xB8);
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::uint8_t>((imm >> (i * 8)) & 0xFF));
    }
    return bytes;
}

/// Encode `mov rax, imm64` 10-byte form (`48 B8+rd iq`) — REX.W
/// without REX.B (target = rax). Used by the 64-bit MOV-imm
/// rewriter tests.
mx::ByteBuffer encode_mov_rax_imm64(std::uint64_t imm) {
    mx::ByteBuffer bytes;
    bytes.reserve(10);
    bytes.push_back(0x48); // REX.W
    bytes.push_back(0xB8); // mov rax (B8 + 0)
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<std::uint8_t>((imm >> (i * 8)) & 0xFF));
    }
    return bytes;
}

// ---------------------------------------------------------------------------
// Tiny x86-64 simulator covering the instruction subset emitted by
// the shipped MBA rewriters. Handles 64-bit ALU + push/pop + mov-imm.
// Imm32 ALU instructions interpret the immediate as sign-extended to
// 64 bits, which mirrors the hardware behaviour for `81 /<op> id`.
// ---------------------------------------------------------------------------

class MbaSimulator {
public:
    void set_reg(mx::x86::Reg reg, std::uint64_t value) {
        regs_[static_cast<std::size_t>(reg)] = value;
    }

    [[nodiscard]] std::uint64_t get_reg(mx::x86::Reg reg) const {
        return regs_[static_cast<std::size_t>(reg)];
    }

    /// Return `false` if the simulator hits an unsupported encoding.
    [[nodiscard]] bool run(mx::ByteView bytes) {
        std::size_t cursor = 0;
        while (cursor < bytes.size()) {
            const auto consumed = step(bytes, cursor);
            if (consumed == 0) return false;
            cursor += consumed;
        }
        return cursor == bytes.size();
    }

private:
    std::array<std::uint64_t, 16> regs_{};
    std::vector<std::uint64_t>    stack_;

    [[nodiscard]] std::size_t step(mx::ByteView bytes, std::size_t pos);

    [[nodiscard]] static std::int64_t sign_extend_imm32(
        std::uint32_t imm) noexcept
    {
        return static_cast<std::int64_t>(static_cast<std::int32_t>(imm));
    }

    [[nodiscard]] static std::uint32_t read_imm32(
        mx::ByteView bytes, std::size_t at) noexcept
    {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v |= static_cast<std::uint32_t>(bytes[at + i]) << (i * 8);
        }
        return v;
    }
};

std::size_t MbaSimulator::step(mx::ByteView bytes, std::size_t pos) {
    bool rex_w = false;
    bool rex_r = false;
    bool rex_b = false;
    std::size_t off = pos;

    if (off < bytes.size() && mx::x86::is_rex(bytes[off])) {
        rex_w = mx::x86::rex_w(bytes[off]);
        rex_r = mx::x86::rex_r(bytes[off]);
        rex_b = mx::x86::rex_b(bytes[off]);
        ++off;
    }

    if (off >= bytes.size()) return 0;
    const std::uint8_t op = bytes[off];

    // PUSH r64 (50 + rd) / POP r64 (58 + rd)
    if (op >= 0x50 && op <= 0x57) {
        std::uint8_t reg_id = op - 0x50;
        if (rex_b) reg_id |= 0x08;
        stack_.push_back(regs_[reg_id]);
        return off - pos + 1;
    }
    if (op >= 0x58 && op <= 0x5F) {
        std::uint8_t reg_id = op - 0x58;
        if (rex_b) reg_id |= 0x08;
        if (stack_.empty()) return 0;
        regs_[reg_id] = stack_.back();
        stack_.pop_back();
        return off - pos + 1;
    }

    // MOV r32, imm32 / MOV r64, imm64 (B8+rd id|iq).
    // Without REX.W the immediate is 32-bit zero-extended; with
    // REX.W it is a full 64-bit immediate. The MBA family's
    // `mov scratch, sign-extended-K` emits the 64-bit form whenever
    // K's int64 representation exceeds 0xFFFFFFFF (i.e. K is
    // negative as int32), so the simulator must accept both.
    if (op >= 0xB8 && op <= 0xBF) {
        std::uint8_t reg_id = op - 0xB8;
        if (rex_b) reg_id |= 0x08;
        if (rex_w) {
            if (off + 9 > bytes.size()) return 0;
            std::uint64_t imm = 0;
            for (int i = 0; i < 8; ++i) {
                imm |= static_cast<std::uint64_t>(bytes[off + 1 + i]) << (i * 8);
            }
            regs_[reg_id] = imm;
            return off - pos + 9;
        }
        if (off + 5 > bytes.size()) return 0;
        const std::uint32_t imm = read_imm32(bytes, off + 1);
        regs_[reg_id] = static_cast<std::uint64_t>(imm);
        return off - pos + 5;
    }

    // group-1 ALU r/m64, imm32 (81 /op id) and r/m64, imm8 (83 /op ib).
    // The emitter picks `83 /op ib` whenever the immediate fits in
    // signed 8 bits, so the simulator must accept both forms.
    if (op == 0x81 || op == 0x83) {
        const std::size_t imm_size = (op == 0x81) ? 4 : 1;
        if (off + 2 + imm_size > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        std::uint8_t rm = mx::x86::modrm_rm(modrm);
        if (rex_b) rm |= 0x08;
        const std::uint8_t reg_field = mx::x86::modrm_reg(modrm);
        std::int64_t sx = 0;
        if (op == 0x81) {
            sx = sign_extend_imm32(read_imm32(bytes, off + 2));
        } else {
            sx = static_cast<std::int64_t>(
                static_cast<std::int8_t>(bytes[off + 2]));
        }
        std::uint64_t& dst = regs_[rm];
        switch (reg_field) {
            case 0: dst += static_cast<std::uint64_t>(sx); break; // ADD
            case 1: dst |= static_cast<std::uint64_t>(sx); break; // OR
            case 4: dst &= static_cast<std::uint64_t>(sx); break; // AND
            case 5: dst -= static_cast<std::uint64_t>(sx); break; // SUB
            case 6: dst ^= static_cast<std::uint64_t>(sx); break; // XOR
            default: return 0;
        }
        if (!rex_w) dst &= 0xFFFFFFFFu;
        return off - pos + 2 + imm_size;
    }

    // mov r/m32, imm32 (C7 /0 id) — emitted by ConstantUnfolder + by
    // the modular-inverse rewriter when destination is rax-rdi in
    // 32-bit operand-size mode. With REX.W, the immediate is
    // sign-extended to 64 bits per the Intel SDM.
    if (op == 0xC7) {
        if (off + 6 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        if (mx::x86::modrm_reg(modrm) != 0) return 0;
        std::uint8_t rm = mx::x86::modrm_rm(modrm);
        if (rex_b) rm |= 0x08;
        const std::uint32_t imm = read_imm32(bytes, off + 2);
        if (rex_w) {
            regs_[rm] = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(
                    static_cast<std::int32_t>(imm)));
        } else {
            regs_[rm] = static_cast<std::uint64_t>(imm); // zero-extend
            regs_[rm] &= 0xFFFFFFFFu;
        }
        return off - pos + 6;
    }

    // F7 /2 NOT r/m64 / /3 NEG r/m64
    if (op == 0xF7) {
        if (off + 2 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        std::uint8_t rm = mx::x86::modrm_rm(modrm);
        if (rex_b) rm |= 0x08;
        const std::uint8_t reg_field = mx::x86::modrm_reg(modrm);
        if (reg_field == 2) regs_[rm] = ~regs_[rm];
        else if (reg_field == 3) regs_[rm] = static_cast<std::uint64_t>(
            -static_cast<std::int64_t>(regs_[rm]));
        else return 0;
        if (!rex_w) regs_[rm] &= 0xFFFFFFFFu;
        return off - pos + 2;
    }

    // D1 /4 SHL r/m, 1 (count = 1)
    if (op == 0xD1) {
        if (off + 2 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        if (mx::x86::modrm_reg(modrm) != 4) return 0;
        std::uint8_t rm = mx::x86::modrm_rm(modrm);
        if (rex_b) rm |= 0x08;
        regs_[rm] <<= 1;
        if (!rex_w) regs_[rm] &= 0xFFFFFFFFu;
        return off - pos + 2;
    }

    // C1 /op ib — ROL/ROR/SHL/SHR r/m, imm8.
    // The shipped MBA shapes use only ROL (/0), but the simulator
    // covers the related shifts/rotates in case future shapes mix
    // them. Operand size is 32 unless REX.W is set; the rotate
    // count is masked to 5 bits per Intel SDM (32-bit op width).
    if (op == 0xC1) {
        if (off + 3 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        const std::uint8_t reg_field = mx::x86::modrm_reg(modrm);
        std::uint8_t rm = mx::x86::modrm_rm(modrm);
        if (rex_b) rm |= 0x08;
        const std::uint8_t imm8 = bytes[off + 2];
        const std::uint32_t width = rex_w ? 64u : 32u;
        const std::uint8_t  cnt = imm8 & (rex_w ? 0x3F : 0x1F);
        std::uint64_t v = regs_[rm];
        if (!rex_w) v &= 0xFFFFFFFFu;
        switch (reg_field) {
            case 0: { // ROL
                if (cnt != 0) {
                    if (rex_w) {
                        v = (v << cnt) | (v >> (width - cnt));
                    } else {
                        const std::uint32_t v32 = static_cast<std::uint32_t>(v);
                        const std::uint32_t r = (v32 << cnt) |
                                                (v32 >> (32u - cnt));
                        v = static_cast<std::uint64_t>(r);
                    }
                }
                break;
            }
            case 1: { // ROR
                if (cnt != 0) {
                    if (rex_w) {
                        v = (v >> cnt) | (v << (width - cnt));
                    } else {
                        const std::uint32_t v32 = static_cast<std::uint32_t>(v);
                        const std::uint32_t r = (v32 >> cnt) |
                                                (v32 << (32u - cnt));
                        v = static_cast<std::uint64_t>(r);
                    }
                }
                break;
            }
            case 4: v <<= cnt; break; // SHL
            case 5: v >>= cnt; break; // SHR (logical, 32-bit width below)
            default: return 0;
        }
        regs_[rm] = v;
        if (!rex_w) regs_[rm] &= 0xFFFFFFFFu;
        return off - pos + 3;
    }

    // ALU r/m, r reg-reg encodings (mod=3): 01 ADD, 09 OR, 21 AND,
    // 29 SUB, 31 XOR, 89 MOV. Two-byte instruction.
    auto is_alu_rmr = [](std::uint8_t b) {
        return b == 0x01 || b == 0x09 || b == 0x21 || b == 0x29 ||
               b == 0x31 || b == 0x89;
    };
    if (is_alu_rmr(op)) {
        if (off + 2 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        std::uint8_t rm  = mx::x86::modrm_rm(modrm);
        std::uint8_t reg = mx::x86::modrm_reg(modrm);
        if (rex_b) rm  |= 0x08;
        if (rex_r) reg |= 0x08;
        std::uint64_t& dst = regs_[rm];
        const std::uint64_t  src = regs_[reg];
        switch (op) {
            case 0x01: dst += src; break;
            case 0x09: dst |= src; break;
            case 0x21: dst &= src; break;
            case 0x29: dst -= src; break;
            case 0x31: dst ^= src; break;
            case 0x89: dst  = src; break;
        }
        if (!rex_w) dst &= 0xFFFFFFFFu;
        return off - pos + 2;
    }

    // 69 /r id — IMUL r32/r64, r/m, imm32. Hardware sign-extends
    // the imm32 to the operand width: in 64-bit mode the actual
    // multiplier is `sext64(imm32)`, which is what the 64-bit
    // modular-inverse rewriter relies on (it picks `K' = K *
    // inv(sext64(P32))` so the runtime product reduces to `K`).
    // In 32-bit mode the high bits are masked away anyway, so the
    // sign-extension is invisible.
    if (op == 0x69) {
        if (off + 6 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        std::uint8_t rm  = mx::x86::modrm_rm(modrm);
        std::uint8_t reg = mx::x86::modrm_reg(modrm);
        if (rex_b) rm  |= 0x08;
        if (rex_r) reg |= 0x08;
        const std::uint32_t imm = read_imm32(bytes, off + 2);
        const std::uint64_t multiplier = rex_w
            ? static_cast<std::uint64_t>(sign_extend_imm32(imm))
            : static_cast<std::uint64_t>(imm);
        regs_[reg] = regs_[rm] * multiplier;
        if (!rex_w) regs_[reg] &= 0xFFFFFFFFu;
        return off - pos + 6;
    }

    // 6B /r ib — IMUL r32/r64, r/m, imm8. Hardware sign-extends
    // the imm8 to the operand width unconditionally — this is the
    // form `imul reg, reg, c` collapses to whenever the affine
    // coefficient `c` fits in `[-128, 127]`. The rewriter picks
    // `t ∈ [2, 15]` so every coefficient lands in `[-16, 16]`,
    // which is solidly inside imm8 range.
    if (op == 0x6B) {
        if (off + 3 > bytes.size()) return 0;
        const std::uint8_t modrm = bytes[off + 1];
        if (mx::x86::modrm_mod(modrm) != 3) return 0;
        std::uint8_t rm  = mx::x86::modrm_rm(modrm);
        std::uint8_t reg = mx::x86::modrm_reg(modrm);
        if (rex_b) rm  |= 0x08;
        if (rex_r) reg |= 0x08;
        const std::int64_t imm_se = static_cast<std::int64_t>(
            static_cast<std::int8_t>(bytes[off + 2]));
        const std::uint64_t multiplier =
            static_cast<std::uint64_t>(imm_se);
        regs_[reg] = regs_[rm] * multiplier;
        if (!rex_w) regs_[reg] &= 0xFFFFFFFFu;
        return off - pos + 3;
    }

    return 0; // unsupported
}

// ---------------------------------------------------------------------------
// Decoder tests
// ---------------------------------------------------------------------------

TEST(MbaAluImm32Decoder, AcceptsAddRax) {
    auto insn = make_insn(
        encode_alu_imm32_rax(mx::mutation::mba::AluImm32Op::add, 0x11223344),
        "add", "rax, 0x11223344");
    auto view = mx::mutation::mba::decode_alu_imm32(insn);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->op, mx::mutation::mba::AluImm32Op::add);
    EXPECT_EQ(view->dst, mx::x86::Reg::rax);
    EXPECT_EQ(view->imm, 0x11223344u);
    EXPECT_TRUE(view->is_64bit);
}

TEST(MbaAluImm32Decoder, RejectsForeignOps) {
    // CMP r/m64, imm32 (`81 /7 id`) — not in the supported set.
    mx::ByteBuffer bytes{0x48, 0x81, 0xF8, 0x00, 0x00, 0x00, 0x00};
    auto insn = make_insn(std::move(bytes), "cmp", "rax, 0");
    EXPECT_FALSE(mx::mutation::mba::decode_alu_imm32(insn).has_value());
}

TEST(MbaAluImm32Decoder, RejectsExpectedOpMismatch) {
    auto insn = make_insn(
        encode_alu_imm32_rax(mx::mutation::mba::AluImm32Op::add, 0x100),
        "add", "rax, 0x100");
    EXPECT_FALSE(mx::mutation::mba::decode_alu_imm32(
        insn, mx::mutation::mba::AluImm32Op::sub).has_value());
}

TEST(MbaAluImm32Decoder, RejectsShortImm8Form) {
    // ADD r/m64, imm8 (`83 /0 ib`) — out of scope.
    mx::ByteBuffer bytes{0x48, 0x83, 0xC0, 0x05};
    auto insn = make_insn(std::move(bytes), "add", "rax, 5");
    EXPECT_FALSE(mx::mutation::mba::decode_alu_imm32(insn).has_value());
}

TEST(MbaAluImm32Decoder, ParsesRexBExtendedRegister) {
    // ADD r11, imm32 → REX.W|REX.B 81 /0 id
    mx::ByteBuffer bytes{0x49, 0x81, 0xC3, 0x78, 0x56, 0x34, 0x12};
    auto insn = make_insn(std::move(bytes), "add", "r11, 0x12345678");
    auto view = mx::mutation::mba::decode_alu_imm32(insn);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->dst, mx::x86::Reg::r11);
}

TEST(MbaAluImm32Decoder, ParsesShortFormAddEax) {
    // ADD EAX, imm32 short form: 05 id (5 bytes, no REX).
    auto insn = make_insn(
        encode_alu_imm32_short_eax(
            mx::mutation::mba::AluImm32Op::add, 0xDEADBEEF),
        "add", "eax, 0xDEADBEEF");
    auto view = mx::mutation::mba::decode_alu_imm32(insn);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->op, mx::mutation::mba::AluImm32Op::add);
    EXPECT_EQ(view->dst, mx::x86::Reg::rax);
    EXPECT_EQ(view->imm, 0xDEADBEEFu);
    EXPECT_FALSE(view->is_64bit);
}

TEST(MbaAluImm32Decoder, ParsesShortFormSubRax) {
    // SUB RAX, imm32 short form: 48 2D id (6 bytes, REX.W).
    auto insn = make_insn(
        encode_alu_imm32_short_rax(
            mx::mutation::mba::AluImm32Op::sub, 0x12345678),
        "sub", "rax, 0x12345678");
    auto view = mx::mutation::mba::decode_alu_imm32(insn);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->op, mx::mutation::mba::AluImm32Op::sub);
    EXPECT_EQ(view->dst, mx::x86::Reg::rax);
    EXPECT_TRUE(view->is_64bit);
}

TEST(MbaAluImm32Decoder, RejectsForeignShortFormOps) {
    // CMP EAX, imm32 short form: 0x3D id — not in the supported set.
    mx::ByteBuffer bytes{0x3D, 0x00, 0x00, 0x00, 0x00};
    auto insn = make_insn(std::move(bytes), "cmp", "eax, 0");
    EXPECT_FALSE(mx::mutation::mba::decode_alu_imm32(insn).has_value());
    // ADC EAX (0x15) and SBB EAX (0x1D) match the (x<<3)|0x05 shape
    // but encode unsupported ops; both must be rejected too.
    mx::ByteBuffer adc_bytes{0x15, 0, 0, 0, 0};
    EXPECT_FALSE(mx::mutation::mba::decode_alu_imm32(
        make_insn(std::move(adc_bytes), "adc", "eax, 0")).has_value());
    mx::ByteBuffer sbb_bytes{0x1D, 0, 0, 0, 0};
    EXPECT_FALSE(mx::mutation::mba::decode_alu_imm32(
        make_insn(std::move(sbb_bytes), "sbb", "eax, 0")).has_value());
}

// ---------------------------------------------------------------------------
// `decode_mov_r64_imm64` decoder tests — covers the 10-byte
// `[REX.W (.B)] B8+rd iq` form with extended-register and
// negative-shape rejection cases.
// ---------------------------------------------------------------------------

TEST(MbaMovR64Imm64Decoder, AcceptsRaxImm64) {
    auto insn = make_insn(
        encode_mov_rax_imm64(0x0123456789ABCDEFULL),
        "mov", "rax, 0x0123456789ABCDEF");
    auto view = mx::mutation::mba::decode_mov_r64_imm64(insn);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->dst, mx::x86::Reg::rax);
    EXPECT_EQ(view->imm, 0x0123456789ABCDEFULL);
}

TEST(MbaMovR64Imm64Decoder, ParsesRexBExtendedRegister) {
    // mov r11, imm64 → REX.W|REX.B B8+rd iq.
    mx::ByteBuffer bytes{
        0x49,                                  // REX.W | REX.B
        0xBB,                                  // mov r11 (B8 + 3)
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
    };
    auto insn = make_insn(std::move(bytes), "mov", "r11, ...");
    auto view = mx::mutation::mba::decode_mov_r64_imm64(insn);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->dst, mx::x86::Reg::r11);
    EXPECT_EQ(view->imm, 0x0123456789ABCDEFULL);
}

TEST(MbaMovR64Imm64Decoder, RejectsImm32Form) {
    // 5-byte `B8 id` belongs to the imm32 decoder, not this one.
    auto insn = make_insn(
        encode_mov_eax_imm32(0xDEADBEEFu), "mov", "eax, 0xDEADBEEF");
    EXPECT_FALSE(mx::mutation::mba::decode_mov_r64_imm64(insn).has_value());
}

TEST(MbaMovR64Imm64Decoder, RejectsRexWC7SignExtendedForm) {
    // `48 C7 C0 id` is `mov r64, sext(imm32)` — out of scope (the
    // shipped 64-bit MOV-imm rewriters only target the 10-byte
    // `B8+rd iq` form so the encoded value survives as a full
    // 64-bit constant).
    mx::ByteBuffer bytes{0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00};
    auto insn = make_insn(std::move(bytes), "mov", "rax, 1");
    EXPECT_FALSE(mx::mutation::mba::decode_mov_r64_imm64(insn).has_value());
}

TEST(MbaMovR64Imm64Decoder, RejectsZeroImmediate) {
    auto insn = make_insn(
        encode_mov_rax_imm64(0ULL), "mov", "rax, 0");
    EXPECT_FALSE(mx::mutation::mba::decode_mov_r64_imm64(insn).has_value());
}

// ---------------------------------------------------------------------------
// Per-family rewriter tests (matches + semantic equivalence)
// ---------------------------------------------------------------------------

struct AluCase {
    mx::mutation::mba::AluImm32Op op;
    std::string_view              rewriter_name;
    std::string                   mnemonic;
};

constexpr std::array<std::uint64_t, 5> kSampleX = {
    0x0000000000000000ULL,
    0x000000007FFFFFFFULL,
    0x00000000FFFFFFFFULL,
    0x0123456789ABCDEFULL,
    0xDEADBEEFCAFEBABEULL,
};

constexpr std::array<std::uint32_t, 5> kSampleK = {
    0x00000001u, 0x12345678u, 0x80000000u, 0xFFFFFFFFu, 0xCAFEBABEu,
};

[[nodiscard]] std::uint64_t apply_alu64(
    mx::mutation::mba::AluImm32Op op,
    std::uint64_t                 x,
    std::uint32_t                 k_raw)
{
    const auto k = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(static_cast<std::int32_t>(k_raw)));
    using Op = mx::mutation::mba::AluImm32Op;
    switch (op) {
        case Op::add:  return x + k;
        case Op::sub:  return x - k;
        case Op::xor_: return x ^ k;
        case Op::or_:  return x | k;
        case Op::and_: return x & k;
    }
    return 0;
}

void check_rewriter_semantics(const AluCase& c) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find(c.rewriter_name);
    ASSERT_NE(rewriter, nullptr) << c.rewriter_name;

    mx::Randomizer rng(0xA5A5);

    for (auto x : kSampleX) {
        for (auto k : kSampleK) {
            auto insn = make_insn(
                encode_alu_imm32_rax(c.op, k), c.mnemonic, "rax, K");

            ASSERT_TRUE(rewriter->matches(insn));

            auto emitted = rewriter->rewrite(insn, rng);
            ASSERT_TRUE(emitted.has_value())
                << c.rewriter_name << " emit failed";

            MbaSimulator sim;
            sim.set_reg(mx::x86::Reg::rax, x);
            // Pre-fill the scratch register with a poison value so a
            // missed pop would observably corrupt the simulator.
            sim.set_reg(mx::x86::Reg::r11, 0xDEADBEEF11223344ULL);
            const auto pre_scratch = sim.get_reg(mx::x86::Reg::r11);

            ASSERT_TRUE(sim.run(mx::ByteView{
                emitted->bytes.data(), emitted->bytes.size()}))
                << c.rewriter_name << " simulator stalled on emitted bytes";

            const auto expected = apply_alu64(c.op, x, k);
            EXPECT_EQ(sim.get_reg(mx::x86::Reg::rax), expected)
                << c.rewriter_name
                << " mismatch for x=" << std::hex << x
                << " k=" << k;
            EXPECT_EQ(sim.get_reg(mx::x86::Reg::r11), pre_scratch)
                << c.rewriter_name << " did not restore scratch";
        }
    }
}

TEST(MbaRewriter, AddImmXorAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::add, "add-imm-xor-and", "add"});
}

TEST(MbaRewriter, AddImmOrAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::add, "add-imm-or-and", "add"});
}

TEST(MbaRewriter, AddImmShiftOrXorPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::add, "add-imm-shift-or-xor", "add"});
}

TEST(MbaRewriter, SubImmXorAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::sub, "sub-imm-xor-and", "sub"});
}

TEST(MbaRewriter, SubImmNegAddPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::sub, "sub-imm-neg-add", "sub"});
}

TEST(MbaRewriter, SubImmOffsetPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::sub, "sub-imm-offset", "sub"});
}

TEST(MbaRewriter, XorImmOrAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::xor_, "xor-imm-or-and", "xor"});
}

TEST(MbaRewriter, XorImmOrXorAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::xor_, "xor-imm-or-xor-and", "xor"});
}

TEST(MbaRewriter, XorImmAddMinusAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::xor_, "xor-imm-add-minus-and", "xor"});
}

TEST(MbaRewriter, OrImmXorAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::or_, "or-imm-xor-and", "or"});
}

TEST(MbaRewriter, OrImmAddMinusAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::or_, "or-imm-add-minus-and", "or"});
}

TEST(MbaRewriter, OrImmXorOrAndPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::or_, "or-imm-xor-or-and", "or"});
}

TEST(MbaRewriter, AndImmOrXorPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::and_, "and-imm-or-xor", "and"});
}

TEST(MbaRewriter, AndImmAddMinusOrPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::and_, "and-imm-add-minus-or", "and"});
}

TEST(MbaRewriter, AndImmDeMorganPreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::and_, "and-imm-demorgan", "and"});
}

TEST(MbaRewriter, AddImmAffinePreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::add, "add-imm-affine", "add"});
}

TEST(MbaRewriter, SubImmAffinePreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::sub, "sub-imm-affine", "sub"});
}

TEST(MbaRewriter, XorImmAffinePreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::xor_, "xor-imm-affine", "xor"});
}

TEST(MbaRewriter, OrImmAffinePreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::or_, "or-imm-affine", "or"});
}

TEST(MbaRewriter, AndImmAffinePreservesSemantics) {
    check_rewriter_semantics({
        mx::mutation::mba::AluImm32Op::and_, "and-imm-affine", "and"});
}

TEST(MbaRewriter, ModularInversePreservesMovImmSemantics) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find("mov-imm-modular-inverse");
    ASSERT_NE(rewriter, nullptr);

    mx::Randomizer rng(0x1234);
    for (auto k : kSampleK) {
        auto insn = make_insn(
            encode_mov_eax_imm32(k), "mov", "eax, K");
        ASSERT_TRUE(rewriter->matches(insn));

        auto emitted = rewriter->rewrite(insn, rng);
        ASSERT_TRUE(emitted.has_value());

        MbaSimulator sim;
        sim.set_reg(mx::x86::Reg::rax, 0xCCCCCCCCCCCCCCCCULL);
        ASSERT_TRUE(sim.run(mx::ByteView{
            emitted->bytes.data(), emitted->bytes.size()}));

        // `mov eax, imm32` zero-extends to rax — verify both halves.
        EXPECT_EQ(sim.get_reg(mx::x86::Reg::rax),
                  static_cast<std::uint64_t>(k));
    }
}

TEST(MbaRewriter, MovImmXorBlindPreservesSemantics) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find("mov-imm-xor-blind");
    ASSERT_NE(rewriter, nullptr);

    mx::Randomizer rng(0xBEEF);
    for (auto k : kSampleK) {
        auto insn = make_insn(
            encode_mov_eax_imm32(k), "mov", "eax, K");
        ASSERT_TRUE(rewriter->matches(insn));
        auto emitted = rewriter->rewrite(insn, rng);
        ASSERT_TRUE(emitted.has_value());

        MbaSimulator sim;
        sim.set_reg(mx::x86::Reg::rax, 0xCCCCCCCCCCCCCCCCULL);
        ASSERT_TRUE(sim.run(mx::ByteView{
            emitted->bytes.data(), emitted->bytes.size()}));
        EXPECT_EQ(sim.get_reg(mx::x86::Reg::rax),
                  static_cast<std::uint64_t>(k));
    }
}

TEST(MbaRewriter, MovImmRotateBlindPreservesSemantics) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find("mov-imm-rotate-blind");
    ASSERT_NE(rewriter, nullptr);

    mx::Randomizer rng(0xC0DE);
    for (auto k : kSampleK) {
        auto insn = make_insn(
            encode_mov_eax_imm32(k), "mov", "eax, K");
        ASSERT_TRUE(rewriter->matches(insn));
        auto emitted = rewriter->rewrite(insn, rng);
        ASSERT_TRUE(emitted.has_value());

        MbaSimulator sim;
        sim.set_reg(mx::x86::Reg::rax, 0xCCCCCCCCCCCCCCCCULL);
        ASSERT_TRUE(sim.run(mx::ByteView{
            emitted->bytes.data(), emitted->bytes.size()}));
        EXPECT_EQ(sim.get_reg(mx::x86::Reg::rax),
                  static_cast<std::uint64_t>(k));
    }
}

TEST(MbaRewriter, ModularInverseRejectsZeroImmediate) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find("mov-imm-modular-inverse");
    ASSERT_NE(rewriter, nullptr);

    auto insn = make_insn(encode_mov_eax_imm32(0), "mov", "eax, 0");
    EXPECT_FALSE(rewriter->matches(insn));
}

// ---------------------------------------------------------------------------
// 64-bit MOV-imm rewriter semantic tests. A small property-style
// sweep across `kSampleK64` reuses the same simulator harness as the
// 32-bit MOV-imm tests; each shape must round-trip every sample K
// regardless of which bits are set.
// ---------------------------------------------------------------------------

constexpr std::array<std::uint64_t, 6> kSampleK64 = {
    0x0000000000000001ULL,
    0x0000000080000000ULL, // bit-31 set, high half clear — sign-extension trap
    0x00000000FFFFFFFFULL,
    0x0123456789ABCDEFULL,
    0xDEADBEEFCAFEBABEULL,
    0xFFFFFFFFFFFFFFFFULL,
};

void check_mov_imm64_rewriter(std::string_view name) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find(name);
    ASSERT_NE(rewriter, nullptr) << name;

    mx::Randomizer rng(0x64640042);
    for (auto k : kSampleK64) {
        auto insn = make_insn(
            encode_mov_rax_imm64(k), "mov", "rax, K64");
        ASSERT_TRUE(rewriter->matches(insn)) << name;

        auto emitted = rewriter->rewrite(insn, rng);
        ASSERT_TRUE(emitted.has_value()) << name << " emit failed";

        MbaSimulator sim;
        sim.set_reg(mx::x86::Reg::rax, 0xCCCCCCCCCCCCCCCCULL);
        ASSERT_TRUE(sim.run(mx::ByteView{
            emitted->bytes.data(), emitted->bytes.size()}))
            << name << " simulator stalled on emitted bytes";
        EXPECT_EQ(sim.get_reg(mx::x86::Reg::rax), k)
            << name << " mismatch for k=" << std::hex << k;
    }
}

TEST(MbaRewriter, MovImm64ModularInversePreservesSemantics) {
    check_mov_imm64_rewriter("mov-imm64-modular-inverse");
}

TEST(MbaRewriter, MovImm64XorBlindPreservesSemantics) {
    check_mov_imm64_rewriter("mov-imm64-xor-blind");
}

TEST(MbaRewriter, MovImm64RotateBlindPreservesSemantics) {
    check_mov_imm64_rewriter("mov-imm64-rotate-blind");
}

TEST(MbaRewriter, MovImm64ModularInverseRejectsZeroImmediate) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    const auto* rewriter = registry.find("mov-imm64-modular-inverse");
    ASSERT_NE(rewriter, nullptr);
    auto insn = make_insn(
        encode_mov_rax_imm64(0ULL), "mov", "rax, 0");
    EXPECT_FALSE(rewriter->matches(insn));
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

TEST(MbaRewriterRegistry, DefaultPopulationContainsAllShippedFamilies) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    EXPECT_EQ(registry.size(), 26u);
    EXPECT_NE(registry.find("add-imm-xor-and"), nullptr);
    EXPECT_NE(registry.find("add-imm-or-and"), nullptr);
    EXPECT_NE(registry.find("add-imm-shift-or-xor"), nullptr);
    EXPECT_NE(registry.find("sub-imm-xor-and"), nullptr);
    EXPECT_NE(registry.find("sub-imm-neg-add"), nullptr);
    EXPECT_NE(registry.find("sub-imm-offset"), nullptr);
    EXPECT_NE(registry.find("xor-imm-or-and"), nullptr);
    EXPECT_NE(registry.find("xor-imm-or-xor-and"), nullptr);
    EXPECT_NE(registry.find("xor-imm-add-minus-and"), nullptr);
    EXPECT_NE(registry.find("or-imm-xor-and"), nullptr);
    EXPECT_NE(registry.find("or-imm-add-minus-and"), nullptr);
    EXPECT_NE(registry.find("or-imm-xor-or-and"), nullptr);
    EXPECT_NE(registry.find("and-imm-or-xor"), nullptr);
    EXPECT_NE(registry.find("and-imm-add-minus-or"), nullptr);
    EXPECT_NE(registry.find("and-imm-demorgan"), nullptr);
    EXPECT_NE(registry.find("mov-imm-modular-inverse"), nullptr);
    EXPECT_NE(registry.find("mov-imm-xor-blind"), nullptr);
    EXPECT_NE(registry.find("mov-imm-rotate-blind"), nullptr);
    EXPECT_NE(registry.find("mov-imm64-modular-inverse"), nullptr);
    EXPECT_NE(registry.find("mov-imm64-xor-blind"), nullptr);
    EXPECT_NE(registry.find("mov-imm64-rotate-blind"), nullptr);
    EXPECT_NE(registry.find("add-imm-affine"), nullptr);
    EXPECT_NE(registry.find("sub-imm-affine"), nullptr);
    EXPECT_NE(registry.find("xor-imm-affine"), nullptr);
    EXPECT_NE(registry.find("or-imm-affine"), nullptr);
    EXPECT_NE(registry.find("and-imm-affine"), nullptr);
}

TEST(MbaRewriterRegistry, MovImm64SiteMatchesAllImm64Shapes) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    auto insn = make_insn(
        encode_mov_rax_imm64(0xDEADBEEFCAFEBABEULL),
        "mov", "rax, ...");
    auto matching = registry.find_matching(insn);
    EXPECT_EQ(matching.size(), 3u)
        << "every MOV-imm64 shape must accept the 10-byte "
        << "`REX.W B8+rd iq` form";
    // The 32-bit MOV-imm shapes must NOT match a 10-byte site —
    // their decoder rejects REX.W. Verify by name.
    for (const auto* r : matching) {
        EXPECT_TRUE(r->name() == "mov-imm64-modular-inverse" ||
                    r->name() == "mov-imm64-xor-blind"      ||
                    r->name() == "mov-imm64-rotate-blind")
            << "unexpected matcher: " << r->name();
    }
}

TEST(MbaRewriterRegistry, MovImm32SiteDoesNotMatchImm64Shapes) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    auto insn = make_insn(
        encode_mov_eax_imm32(0xDEADBEEFu), "mov", "eax, 0xDEADBEEF");
    auto matching = registry.find_matching(insn);
    for (const auto* r : matching) {
        EXPECT_FALSE(r->name() == "mov-imm64-modular-inverse" ||
                     r->name() == "mov-imm64-xor-blind"      ||
                     r->name() == "mov-imm64-rotate-blind")
            << "MOV-imm64 shape leaked onto a 5-byte mov r32, imm32 "
            << "site: " << r->name();
    }
}

TEST(MbaRewriterRegistry, ShortFormAddEaxMatchesAllAddShapes) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    auto insn = make_insn(
        encode_alu_imm32_short_eax(
            mx::mutation::mba::AluImm32Op::add, 0xDEADBEEF),
        "add", "eax, 0xDEADBEEF");
    auto matching = registry.find_matching(insn);
    EXPECT_EQ(matching.size(), 4u)
        << "every ADD-imm shape (3 fixed + 1 affine) must accept the "
        << "5-byte EAX,imm32 short form (`05 id`) — same coverage as "
        << "`81 /0 id`";
}

TEST(MbaRewriterRegistry, ShortFormSubRaxMatchesAllSubShapes) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    auto insn = make_insn(
        encode_alu_imm32_short_rax(
            mx::mutation::mba::AluImm32Op::sub, 0x12345678),
        "sub", "rax, 0x12345678");
    auto matching = registry.find_matching(insn);
    EXPECT_EQ(matching.size(), 4u)
        << "every SUB-imm shape (3 fixed + 1 affine) must accept the "
        << "6-byte RAX,imm32 short form (`REX.W 2D id`)";
}

TEST(MbaRewriterRegistry, FindMatchingReturnsAllAddShapesForAddSite) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    auto insn = make_insn(
        encode_alu_imm32_rax(mx::mutation::mba::AluImm32Op::add, 0xDEADBEEF),
        "add", "rax, 0xDEADBEEF");
    auto matching = registry.find_matching(insn);
    EXPECT_EQ(matching.size(), 4u)
        << "every ADD-imm shape (3 fixed + 1 affine) must match an "
        << "`add r,K` site so the adapter can pick one uniformly at "
        << "random per call";
}

TEST(MbaRewriterRegistry, FindMatchingDispatchesByOp) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    auto insn = make_insn(
        encode_alu_imm32_rax(mx::mutation::mba::AluImm32Op::xor_, 0x1234),
        "xor", "rax, 0x1234");
    auto matching = registry.find_matching(insn);
    EXPECT_EQ(matching.size(), 4u)
        << "every XOR-imm shape (3 fixed + 1 affine) must match an "
        << "`xor r,K` site";
    bool seen_baseline = false;
    bool seen_affine   = false;
    for (const auto* r : matching) {
        if (r->name() == "xor-imm-or-and") seen_baseline = true;
        if (r->name() == "xor-imm-affine") seen_affine   = true;
    }
    EXPECT_TRUE(seen_baseline)
        << "the baseline shape must remain in the matching set";
    EXPECT_TRUE(seen_affine)
        << "the new affine shape must also match";
}

TEST(MbaRewriterRegistry, FindReturnsNullForUnknownName) {
    auto registry = mx::mutation::mba::MbaRewriterRegistry::create_default();
    EXPECT_EQ(registry.find("non-existent"), nullptr);
}

// ---------------------------------------------------------------------------
// Adapter rule tests (`register_mba_rules` plugged into a substitution
// registry on demand — `SubstitutionRuleRegistry::create_default()` does
// NOT include MBA: the rewrites change OF/AF and need flag-insensitive
// sites, so `MutationPass` registers them only when
// `ProtectionConfig::enable_mba_substitution` is set).
// ---------------------------------------------------------------------------

TEST(MbaSubstitutionRule, AbsentFromUnconfiguredDefaultRegistry) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();

    auto insn = make_insn(
        encode_alu_imm32_rax(mx::mutation::mba::AluImm32Op::add, 0x100),
        "add", "rax, 0x100");
    for (const auto* rule : registry.find_matching(insn)) {
        EXPECT_NE(rule->name(), "mba-substitution")
            << "create_default() must not register MBA — "
            << "MutationPass opts in via config";
    }
}

TEST(MbaSubstitutionRule, RegisteredAfterExplicitRegisterCall) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::mutation::rules::register_mba_rules(registry);

    auto insn = make_insn(
        encode_alu_imm32_rax(mx::mutation::mba::AluImm32Op::add, 0x100),
        "add", "rax, 0x100");
    bool found_mba = false;
    for (const auto* rule : registry.find_matching(insn)) {
        if (rule->name() == "mba-substitution") {
            found_mba = true;
            break;
        }
    }
    EXPECT_TRUE(found_mba);
}

TEST(MbaSubstitutionRule, DoesNotMatchInstructionsWithoutMbaCoverage) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::mutation::rules::register_mba_rules(registry);

    // CMP rax, 0 — supported by the imm8-negation/semantic rules,
    // not by any MBA family. The MBA adapter must NOT match.
    mx::ByteBuffer bytes{0x48, 0x83, 0xF8, 0x00};
    auto insn = make_insn(std::move(bytes), "cmp", "rax, 0");

    auto matches = registry.find_matching(insn);
    for (const auto* rule : matches) {
        EXPECT_NE(rule->name(), "mba-substitution");
    }
}

TEST(MbaSubstitutionRule, ReportsAffectingObservableFlags) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::mutation::rules::register_mba_rules(registry);

    const mx::ISubstitutionRule* mba_rule = nullptr;
    for (const auto& r : registry.rules()) {
        if (r->name() == "mba-substitution") {
            mba_rule = r.get();
            break;
        }
    }
    ASSERT_NE(mba_rule, nullptr);
    EXPECT_TRUE(mba_rule->affects_observable_flags())
        << "MBA rewrites change OF/AF/CF — engine relies on this "
        << "flag to skip MBA at flag-consuming sites";
}

TEST(MbaSubstitutionRule, ApplyEmitsLongerThanOriginalForAdd) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::mutation::rules::register_mba_rules(registry);
    mx::Randomizer rng(7);

    auto raw = encode_alu_imm32_rax(
        mx::mutation::mba::AluImm32Op::add, 0xDEADBEEF);
    const auto original_size = raw.size();
    auto insn = make_insn(std::move(raw), "add", "rax, 0xDEADBEEF");

    for (const auto* rule : registry.find_matching(insn)) {
        if (rule->name() != "mba-substitution") continue;
        auto emitted = rule->apply(insn, rng);
        EXPECT_GT(emitted.size(), original_size)
            << "MBA replacement must be larger than the original site"
            << " — engine routes it via the expansion sink";
    }
}

} // namespace
