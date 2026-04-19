/**
 * @file shift_add_rules.cpp
 * @brief `shl reg, 1` ↔ `add reg, reg` bidirectional rewrites.
 *
 * Both instructions double the register's value. `shl` sets CF from
 * bit 63 (or bit 31 / bit 7 depending on operand size); `add reg,
 * reg` sets CF from an integer overflow. The two CF values agree for
 * every input, so the substitution is a true drop-in.
 *
 * Two classes because `matches` / `apply` logic diverges between
 * directions — the encoding shapes aren't quite symmetric and
 * shoehorning them into a shared base would hide more than it saves.
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <memory>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

/// `shl reg, 1` (encoded as `D1 /4`) → `add reg, reg` (encoded as `01 reg,reg`).
class Shl1ToAddSelfRule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "shl1_to_add_self";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "shl") return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 1 >= bytes.size()) return false;
        if (bytes[op_off] != 0xD1) return false;
        const uint8_t modrm = bytes[op_off + 1];
        return x86::modrm_mod(modrm) == 3 && x86::modrm_reg(modrm) == 4;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        ByteBuffer    result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off    = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;
        const uint8_t rm        = x86::modrm_rm(result[modrm_off]);

        result[op_off]    = 0x01;
        result[modrm_off] = x86::make_modrm(3, rm, rm);
        return result;
    }
};

/// `add reg, reg` → `shl reg, 1`. Handles both `01` (reg, r/m) and
/// `03` (r/m, reg) opcode forms when both operands name the same
/// register.
class AddSelfToShl1Rule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add_self_to_shl1";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "add") return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 1 >= bytes.size()) return false;
        if (bytes[op_off] != 0x01 && bytes[op_off] != 0x03) return false;
        return x86::is_same_reg_operands(bytes);
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        ByteBuffer    result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off    = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;
        const uint8_t rm        = x86::get_full_rm(ByteView{result}) & 0x07;

        result[op_off]    = 0xD1;
        result[modrm_off] = x86::make_modrm(3, 4, rm);
        return result;
    }
};

} // namespace

void register_shift_add_rules(SubstitutionRuleRegistry& registry) {
    registry.add_rule(std::make_unique<Shl1ToAddSelfRule>());
    registry.add_rule(std::make_unique<AddSelfToShl1Rule>());
}

} // namespace mx::mutation::rules
