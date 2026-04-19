/**
 * @file inc_dec_rules.cpp
 * @brief `inc reg` → `add reg, 1` / `dec reg` → `sub reg, 1` rewrites.
 *
 * Only applies when the original is ≥ 3 bytes long — the `ADD r/m, 1`
 * / `SUB r/m, 1` form encodes as `83 /r 01` (3 bytes), and the
 * rewrite must preserve the original instruction length. Sources
 * produced with a REX prefix are 3 bytes already and pass the gate;
 * the equivalent ADD/SUB form would be 4 bytes, which doesn't fit.
 *
 * CF diverges slightly between `inc` (doesn't touch CF) and `add`
 * (sets CF from overflow). The rule is scheduled only inside marked
 * regions where that's acceptable — same policy as the other
 * flag-clobbering substitutions.
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <memory>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

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

/// Rule covering both `inc` → `add reg, 1` and `dec` → `sub reg, 1`
/// substitutions. Parameterised by the mnemonic, the `reg` field in
/// the source encoding (`0` for INC, `1` for DEC), and the `reg`
/// field in the rewritten ADD/SUB form (`0` for ADD, `5` for SUB).
class IncDecRule final : public ISubstitutionRule {
public:
    IncDecRule(std::string_view name,
               std::string_view mnemonic,
               uint8_t          source_reg_field,
               uint8_t          target_reg_field) noexcept
        : name_(name)
        , mnemonic_(mnemonic)
        , source_reg_field_(source_reg_field)
        , target_reg_field_(target_reg_field)
    {}

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != mnemonic_) return false;
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 1 >= bytes.size()) return false;
        if (bytes[op_off] != 0xFF) return false;
        const uint8_t modrm = bytes[op_off + 1];
        if (x86::modrm_mod(modrm) != 3) return false;
        if (x86::modrm_reg(modrm) != source_reg_field_) return false;
        return insn.length() >= 3;
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
        result.push_back(x86::make_modrm(3, target_reg_field_, rm));
        result.push_back(0x01);
        return finalize_with_nop_padding(insn, std::move(result));
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t          source_reg_field_;
    uint8_t          target_reg_field_;
};

} // namespace

void register_inc_dec_rules(SubstitutionRuleRegistry& registry) {
    registry.add_rule(std::make_unique<IncDecRule>(
        "inc_to_add_one", "inc",
        /*source_reg_field=*/uint8_t{0},
        /*target_reg_field=*/uint8_t{0}));
    registry.add_rule(std::make_unique<IncDecRule>(
        "dec_to_sub_one", "dec",
        /*source_reg_field=*/uint8_t{1},
        /*target_reg_field=*/uint8_t{5}));
}

} // namespace mx::mutation::rules
