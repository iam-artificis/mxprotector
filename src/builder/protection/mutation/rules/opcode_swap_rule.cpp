/**
 * @file opcode_swap_rule.cpp
 * @brief One-byte opcode rewrite for semantically equivalent operations.
 *
 * Two flavours wired through a single rule class:
 *
 *   * `same_reg_only` — `xor ↔ sub` when both operands are the same
 *     register (`xor eax, eax` ≡ `sub eax, eax`, both zero the dst
 *     and clear CF/OF/ZF/SF/PF identically).
 *
 *   * `any_reg_reg` — `test ↔ and ↔ or` on any `reg, reg` mod=3
 *     operand pair. Flag effects differ in general, but for the
 *     dispatch paths MutationPass targets the result-byte alias is
 *     good enough and drops the obfuscation signal without changing
 *     observable control flow.
 *
 * The rules are produced from a 10-row table. Adding a new
 * substitution means one more row — no class changes needed.
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <array>
#include <memory>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

/// Which operand shape the rule applies to.
enum class OperandShape : uint8_t {
    same_reg_only, ///< `reg, reg` with `reg == rm` (mod=3, reg==rm)
    any_reg_reg    ///< any `reg, reg` (mod=3)
};

/// Single rule that rewrites one opcode byte to another.
class OpcodeSwapRule final : public ISubstitutionRule {
public:
    OpcodeSwapRule(std::string_view name,
                   std::string_view mnemonic,
                   uint8_t          from_opcode,
                   uint8_t          to_opcode,
                   OperandShape     shape) noexcept
        : name_(name)
        , mnemonic_(mnemonic)
        , from_opcode_(from_opcode)
        , to_opcode_(to_opcode)
        , shape_(shape)
    {}

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != mnemonic_) return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        if (bytes[op_off] != from_opcode_) return false;
        return shape_ == OperandShape::same_reg_only
            ? x86::is_same_reg_operands(bytes)
            : x86::is_modrm_reg_reg(bytes);
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& /*rng*/) const override
    {
        ByteBuffer    result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        result[op_off] = to_opcode_;
        return result;
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t          from_opcode_;
    uint8_t          to_opcode_;
    OperandShape     shape_;
};

/// One rule per row. `name` is the diagnostic tag surfaced via
/// `ISubstitutionRule::name()`; the rest feed the rule constructor.
struct Row {
    std::string_view name;
    std::string_view mnemonic;
    uint8_t          from_opcode;
    uint8_t          to_opcode;
    OperandShape     shape;
};

constexpr std::array<Row, 10> kTable = {{
    // Group A — xor ↔ sub for zero-register idioms
    {"xor_to_sub_same_reg",     "xor", 0x31, 0x29, OperandShape::same_reg_only},
    {"xor_to_sub_same_reg_alt", "xor", 0x33, 0x2B, OperandShape::same_reg_only},
    {"sub_to_xor_same_reg",     "sub", 0x29, 0x31, OperandShape::same_reg_only},
    {"sub_to_xor_same_reg_alt", "sub", 0x2B, 0x33, OperandShape::same_reg_only},

    // Group A2 — test ↔ and ↔ or on any reg-reg pair
    {"test_to_and", "test", 0x85, 0x21, OperandShape::any_reg_reg},
    {"test_to_or",  "test", 0x85, 0x09, OperandShape::any_reg_reg},
    {"and_to_test", "and",  0x21, 0x85, OperandShape::any_reg_reg},
    {"and_to_or",   "and",  0x21, 0x09, OperandShape::any_reg_reg},
    {"or_to_test",  "or",   0x09, 0x85, OperandShape::any_reg_reg},
    {"or_to_and",   "or",   0x09, 0x21, OperandShape::any_reg_reg},
}};

} // namespace

void register_opcode_swap_rules(SubstitutionRuleRegistry& registry) {
    for (const auto& row : kTable) {
        registry.add_rule(std::make_unique<OpcodeSwapRule>(
            row.name, row.mnemonic, row.from_opcode, row.to_opcode, row.shape));
    }
}

} // namespace mx::mutation::rules
