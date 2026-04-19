/**
 * @file semantic_transform_rules.cpp
 * @brief Rewrites where the output opcode differs from the input.
 *
 * Each rule here replaces its source instruction with a shorter,
 * semantically equivalent sequence and pads the remainder with NOPs
 * so the overall instruction length stays intact:
 *
 *   * `cmp reg, 0` → `test reg, reg` (ZF/SF/PF match under zero).
 *   * `mov reg, 0` → `xor reg, reg` (both zero the destination).
 *   * `not reg`    → `xor reg, -1`   (bitwise inversion via XOR).
 *
 * Length-preservation matters because these rules run as part of
 * in-place byte mutation — upstream code still expects the same byte
 * count at every instruction offset.
 *
 * Three classes; no table because each has its own encoding shape.
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <memory>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

/// Pad `buf` with NOPs until its size reaches `target_length`.
/// Returns the original buffer unchanged when the rewrite already
/// overshot (which the caller treats as "give up on this rule").
[[nodiscard]] ByteBuffer finalize_with_nop_padding(
    const analysis::Instruction& original, ByteBuffer result)
{
    while (result.size() < original.length()) {
        auto nop = x86::make_nop(
            static_cast<uint8_t>(original.length() - result.size()));
        result.insert(result.end(), nop.begin(), nop.end());
    }
    if (result.size() > original.length()) {
        return ByteBuffer(original.raw_bytes().begin(),
                          original.raw_bytes().end());
    }
    return result;
}

/// `cmp r/m, 0` (encoded `83 /7 00`) → `test reg, reg` (encoded `85 reg,reg`).
class CmpZeroToTestRule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "cmp_zero_to_test";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "cmp") return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 3) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 2 >= bytes.size()) return false;
        if (bytes[op_off] != 0x83) return false;
        const uint8_t modrm = bytes[op_off + 1];
        if (x86::modrm_reg(modrm) != 7) return false;
        if (x86::modrm_mod(modrm) != 3) return false;
        return bytes[op_off + 2] == 0x00;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        const auto    bytes     = insn.raw_bytes();
        const uint8_t op_off    = x86::find_opcode_offset(bytes);
        const uint8_t old_modrm = bytes[op_off + 1];
        const uint8_t rm        = x86::modrm_rm(old_modrm);

        ByteBuffer result;
        result.reserve(insn.length());
        for (uint8_t i = 0; i < op_off; ++i) {
            result.push_back(bytes[i]);
        }
        result.push_back(0x85);
        result.push_back(x86::make_modrm(3, rm, rm));
        return finalize_with_nop_padding(insn, std::move(result));
    }
};

/// `mov reg, 0` → `xor reg, reg`. Handles both 32-bit (`B8+r imm32`)
/// and `MOV r/m, imm32` (`C7 /0 imm32`) source encodings.
///
/// Caveat: `xor` clobbers CF/OF/ZF/SF/PF while `mov` doesn't. The
/// substitution is scheduled only inside marked regions where flag
/// clobbering is known to be safe; this class doesn't re-check.
class MovZeroToXorRule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov_zero_to_xor";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "mov") return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 5) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        const uint8_t op = bytes[op_off];

        // Form 1: B8..BF imm32 (MOV r32, imm32).
        if (op >= 0xB8 && op <= 0xBF) {
            for (uint8_t i = op_off + 1; i < bytes.size(); ++i) {
                if (bytes[i] != 0x00) return false;
            }
            return true;
        }
        // Form 2: C7 /0 imm32 (MOV r/m32, imm32).
        if (op == 0xC7 && op_off + 2 < bytes.size()) {
            const uint8_t modrm = bytes[op_off + 1];
            if (x86::modrm_mod(modrm) != 3) return false;
            if (x86::modrm_reg(modrm) != 0) return false;
            for (uint8_t i = op_off + 2; i < bytes.size(); ++i) {
                if (bytes[i] != 0x00) return false;
            }
            return true;
        }
        return false;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        const auto    bytes  = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t op     = bytes[op_off];
        const uint8_t rex    = x86::find_rex(bytes);

        uint8_t reg_3bit = 0;
        if (op >= 0xB8 && op <= 0xBF) {
            reg_3bit = op - 0xB8;
        } else if (op == 0xC7) {
            reg_3bit = x86::modrm_rm(bytes[op_off + 1]);
        }

        ByteBuffer result;
        result.reserve(insn.length());

        // Copy legacy prefixes but drop the old REX — we rebuild one
        // below because the XOR encoding needs a different REX.R/REX.B
        // combination (both bits cover the same register for the
        // `reg, reg` mod=3 shape).
        for (uint8_t i = 0; i < op_off; ++i) {
            if (x86::is_rex(bytes[i])) continue;
            result.push_back(bytes[i]);
        }

        if (rex != 0) {
            uint8_t new_rex = 0x40;
            if (x86::rex_w(rex)) new_rex |= 0x08;
            if (x86::rex_b(rex))  new_rex |= 0x04 | 0x01;
            result.push_back(new_rex);
        } else if (op >= 0xB8 && op <= 0xBF && x86::rex_b(rex)) {
            // Without an original REX, synthesize one when the dst is
            // an extended register (R8..R15).
            result.push_back(0x44 | 0x01);
        }

        result.push_back(0x31);
        result.push_back(x86::make_modrm(3, reg_3bit, reg_3bit));
        return finalize_with_nop_padding(insn, std::move(result));
    }
};

/// `not r/m` (encoded `F7 /2`) → `xor r/m, -1` (encoded `83 /6 FF`).
/// Limits itself to originals ≤ 3 bytes so the 3-byte XOR encoding
/// fits without upscaling to the imm32 form.
class NotToXorMinusOneRule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "not_to_xor_ff";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "not") return false;
        if (insn.length() > 3) return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        if (bytes[op_off] != 0xF7) return false;
        const uint8_t modrm = bytes[op_off + 1];
        return x86::modrm_mod(modrm) == 3 && x86::modrm_reg(modrm) == 2;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        const auto    bytes  = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t rm     = x86::modrm_rm(bytes[op_off + 1]);

        ByteBuffer result;
        result.reserve(insn.length());
        for (uint8_t i = 0; i < op_off; ++i) {
            result.push_back(bytes[i]);
        }
        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 6, rm));
        result.push_back(0xFF);
        return finalize_with_nop_padding(insn, std::move(result));
    }
};

} // namespace

void register_semantic_transform_rules(SubstitutionRuleRegistry& registry) {
    registry.add_rule(std::make_unique<CmpZeroToTestRule>());
    registry.add_rule(std::make_unique<MovZeroToXorRule>());
    registry.add_rule(std::make_unique<NotToXorMinusOneRule>());
}

} // namespace mx::mutation::rules
