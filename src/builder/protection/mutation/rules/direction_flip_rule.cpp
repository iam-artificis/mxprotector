/**
 * @file direction_flip_rule.cpp
 * @brief Re-encode `OP r/m, r` as `OP r, r/m` and vice versa.
 *
 * For mod=3 (reg, reg) operands the two forms are bitwise identical
 * in effect but carry different opcode bytes and swapped reg/rm
 * positions in ModR/M. The same applies to REX.R / REX.B — swapping
 * the direction bit needs them flipped in lockstep.
 *
 * Nine instructions have both encodings exposed: add, sub, xor, and,
 * or, cmp, mov, adc, sbb. One table row per mnemonic.
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <array>
#include <memory>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

class DirectionFlipRule final : public ISubstitutionRule {
public:
    DirectionFlipRule(std::string_view name,
                      std::string_view mnemonic,
                      uint8_t          opcode_rm_r,
                      uint8_t          opcode_r_rm) noexcept
        : name_(name)
        , mnemonic_(mnemonic)
        , opcode_rm_r_(opcode_rm_r)
        , opcode_r_rm_(opcode_r_rm)
    {}

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != mnemonic_) return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        const uint8_t op = bytes[op_off];
        if (op != opcode_rm_r_ && op != opcode_r_rm_) return false;
        return x86::is_modrm_reg_reg(bytes);
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        ByteBuffer    result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off    = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;

        // Flip the opcode's direction bit (encoded here via the paired
        // opcode from the table instead of bit manipulation — safer).
        result[op_off] =
            result[op_off] == opcode_rm_r_ ? opcode_r_rm_ : opcode_rm_r_;

        // Swap ModR/M reg ↔ rm fields (mod stays 3 throughout).
        const uint8_t old_modrm = result[modrm_off];
        const uint8_t old_reg   = x86::modrm_reg(old_modrm);
        const uint8_t old_rm    = x86::modrm_rm(old_modrm);
        result[modrm_off]       = x86::make_modrm(3, old_rm, old_reg);

        // Swap REX.R and REX.B in lockstep with the ModR/M swap.
        uint8_t prefix_off = 0;
        while (prefix_off < op_off && x86::is_legacy_prefix(result[prefix_off])) {
            ++prefix_off;
        }
        if (prefix_off < op_off && x86::is_rex(result[prefix_off])) {
            result[prefix_off] = x86::swap_rex_rb(result[prefix_off]);
        }
        return result;
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t          opcode_rm_r_;
    uint8_t          opcode_r_rm_;
};

struct Row {
    std::string_view name;
    std::string_view mnemonic;
    uint8_t          opcode_rm_r;
    uint8_t          opcode_r_rm;
};

constexpr std::array<Row, 9> kTable = {{
    {"add_direction_flip", "add", 0x01, 0x03},
    {"sub_direction_flip", "sub", 0x29, 0x2B},
    {"xor_direction_flip", "xor", 0x31, 0x33},
    {"and_direction_flip", "and", 0x21, 0x23},
    {"or_direction_flip",  "or",  0x09, 0x0B},
    {"cmp_direction_flip", "cmp", 0x39, 0x3B},
    {"mov_direction_flip", "mov", 0x89, 0x8B},
    {"adc_direction_flip", "adc", 0x11, 0x13},
    {"sbb_direction_flip", "sbb", 0x19, 0x1B},
}};

} // namespace

void register_direction_flip_rules(SubstitutionRuleRegistry& registry) {
    for (const auto& row : kTable) {
        registry.add_rule(std::make_unique<DirectionFlipRule>(
            row.name, row.mnemonic, row.opcode_rm_r, row.opcode_r_rm));
    }
}

} // namespace mx::mutation::rules
