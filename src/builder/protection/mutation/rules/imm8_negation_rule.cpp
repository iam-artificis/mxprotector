/**
 * @file imm8_negation_rule.cpp
 * @brief `ADD r/m, imm8` ↔ `SUB r/m, -imm8` byte rewrite.
 *
 * `83 /0 imm8` encodes `ADD r/m, imm8`; `83 /5 imm8` encodes
 * `SUB r/m, imm8`. Swapping the `reg` field inside the ModR/M byte
 * and negating `imm8` produces an equivalent arithmetic result.
 *
 * Skips `imm == 0` (the transform is a no-op) and `imm == -128` (no
 * positive 8-bit negation exists — `+128` overflows `int8_t`).
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <array>
#include <memory>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

class Imm8NegationRule final : public ISubstitutionRule {
public:
    Imm8NegationRule(std::string_view name,
                     std::string_view mnemonic,
                     uint8_t          from_reg_field,
                     uint8_t          to_reg_field) noexcept
        : name_(name)
        , mnemonic_(mnemonic)
        , from_reg_field_(from_reg_field)
        , to_reg_field_(to_reg_field)
    {}

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != mnemonic_) return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 3) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 2 >= bytes.size()) return false;
        if (bytes[op_off] != 0x83) return false;
        const uint8_t modrm = bytes[op_off + 1];
        if (x86::modrm_reg(modrm) != from_reg_field_) return false;
        if (x86::modrm_mod(modrm) != 3) return false;
        const auto imm = static_cast<int8_t>(bytes[op_off + 2]);
        return imm != 0 && imm != -128;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        ByteBuffer    result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off    = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;
        const uint8_t imm_off   = op_off + 2;

        const uint8_t old_modrm = result[modrm_off];
        const uint8_t rm        = x86::modrm_rm(old_modrm);
        result[modrm_off]       = x86::make_modrm(3, to_reg_field_, rm);

        const auto old_imm = static_cast<int8_t>(result[imm_off]);
        result[imm_off]    = static_cast<uint8_t>(-old_imm);

        return result;
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t          from_reg_field_;
    uint8_t          to_reg_field_;
};

struct Row {
    std::string_view name;
    std::string_view mnemonic;
    uint8_t          from_reg_field; ///< ModR/M `reg` in the source encoding
    uint8_t          to_reg_field;   ///< ModR/M `reg` in the rewritten encoding
};

// `83 /0` = ADD, `83 /5` = SUB.
constexpr std::array<Row, 2> kTable = {{
    {"add_imm8_to_sub_neg", "add", 0, 5},
    {"sub_imm8_to_add_neg", "sub", 5, 0},
}};

} // namespace

void register_imm8_negation_rules(SubstitutionRuleRegistry& registry) {
    for (const auto& row : kTable) {
        registry.add_rule(std::make_unique<Imm8NegationRule>(
            row.name, row.mnemonic, row.from_reg_field, row.to_reg_field));
    }
}

} // namespace mx::mutation::rules
