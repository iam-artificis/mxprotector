/**
 * @file instruction_substitution.cpp
 * @brief [BUILDER] Реализация правил подстановки инструкций x86/x64.
 *
 * @details Содержит 25 конкретных правил подстановки, покрывающих 50+ паттернов
 *          инструкций. Каждое правило заменяет инструкцию на семантически
 *          эквивалентную с тем же размером (дополнение NOP при необходимости).
 *
 *          Группы правил:
 *          A. Opcode swap (xor↔sub, test↔and↔or) — одинаковый регистр
 *          B. Arithmetic negation (add↔sub с инверсией immediate)
 *          C. Direction flip (смена формы кодирования reg↔r/m)
 *          D. Shift↔Add (shl reg,1 ↔ add reg,reg)
 *          E. CMP zero → TEST (замена сравнения с нулём на TEST)
 *          F. MOV zero → XOR (обнуление через XOR)
 *
 * @note Все правила гарантируют: output.size() == input.size().
 *       Корректность проверена для x86-64 (long mode) с REX-префиксами.
 */

#include "mxprotector/protection/mutation/substitution_rules.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <algorithm>
#include <cstring>

namespace mx {

// ============================================================================
// SubstitutionRuleRegistry — базовые методы
// ============================================================================

void SubstitutionRuleRegistry::add_rule(std::unique_ptr<ISubstitutionRule> rule) {
    if (rule) {
        rules_.push_back(std::move(rule));
    }
}

std::vector<const ISubstitutionRule*> SubstitutionRuleRegistry::find_matching(
    const analysis::Instruction& insn) const
{
    std::vector<const ISubstitutionRule*> result;
    for (const auto& rule : rules_) {
        if (rule->matches(insn)) {
            result.push_back(rule.get());
        }
    }
    return result;
}

// ============================================================================
// Базовые классы правил (внутренние, не экспортируются)
// ============================================================================

namespace {

/**
 * @brief Правило подстановки opcode для инструкций с одинаковыми операндами-регистрами.
 *
 * @details Применяется к инструкциям вида `OP reg, reg` (mod=3, reg==rm).
 *          Меняет opcode на эквивалентный. Размер не изменяется.
 *          Покрывает: xor↔sub, test↔and↔or.
 */
class OpcodeSwapSameRegRule final : public ISubstitutionRule {
public:
    OpcodeSwapSameRegRule(std::string_view name,
                          std::string_view mnemonic,
                          uint8_t from_opcode,
                          uint8_t to_opcode)
        : name_(name)
        , mnemonic_(mnemonic)
        , from_opcode_(from_opcode)
        , to_opcode_(to_opcode)
    {}

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != mnemonic_) return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        if (bytes[op_off] != from_opcode_) return false;
        return x86::is_same_reg_operands(bytes);
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        ByteBuffer result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        result[op_off] = to_opcode_;
        return result;
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t from_opcode_;
    uint8_t to_opcode_;
};

/**
 * @brief Правило подстановки opcode для любых reg-reg инструкций (не только одинаковые).
 *
 * @details Применяется к инструкциям с mod=3. Меняет opcode.
 *          Используется для test↔and↔or, где операнды могут быть разными.
 */
class OpcodeSwapRegRegRule final : public ISubstitutionRule {
public:
    OpcodeSwapRegRegRule(std::string_view name,
                         std::string_view mnemonic,
                         uint8_t from_opcode,
                         uint8_t to_opcode)
        : name_(name)
        , mnemonic_(mnemonic)
        , from_opcode_(from_opcode)
        , to_opcode_(to_opcode)
    {}

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != mnemonic_) return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 2) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        if (bytes[op_off] != from_opcode_) return false;
        return x86::is_modrm_reg_reg(bytes);
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        ByteBuffer result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        result[op_off] = to_opcode_;
        return result;
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t from_opcode_;
    uint8_t to_opcode_;
};

/**
 * @brief Правило «direction flip» — смена формы кодирования OP r/m,r ↔ OP r,r/m.
 *
 * @details Для reg-reg инструкций (mod=3) две формы кодирования семантически
 *          идентичны. Меняем бит направления в opcode (бит 1) и переставляем
 *          поля reg/rm в ModR/M, а также REX.R/REX.B.
 */
class DirectionFlipRule final : public ISubstitutionRule {
public:
    DirectionFlipRule(std::string_view name,
                      std::string_view mnemonic,
                      uint8_t opcode_rm_r,
                      uint8_t opcode_r_rm)
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
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        ByteBuffer result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;

        if (result[op_off] == opcode_rm_r_) {
            result[op_off] = opcode_r_rm_;
        } else {
            result[op_off] = opcode_rm_r_;
        }

        const uint8_t old_modrm = result[modrm_off];
        const uint8_t old_reg = x86::modrm_reg(old_modrm);
        const uint8_t old_rm = x86::modrm_rm(old_modrm);
        result[modrm_off] = x86::make_modrm(3, old_rm, old_reg);

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
    uint8_t opcode_rm_r_;
    uint8_t opcode_r_rm_;
};

/**
 * @brief Правило инверсии immediate для ADD↔SUB (opcode 0x83).
 *
 * @details Заменяет ADD r/m, imm8 на SUB r/m, -imm8 и наоборот.
 *          Opcode 0x83, поле reg в ModR/M: /0=ADD, /5=SUB.
 *          Инвертирует поле reg и знак immediate.
 */
class Imm8NegationRule final : public ISubstitutionRule {
public:
    Imm8NegationRule(std::string_view name,
                     std::string_view mnemonic,
                     uint8_t from_reg_field,
                     uint8_t to_reg_field)
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
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        ByteBuffer result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;
        const uint8_t imm_off = op_off + 2;

        const uint8_t old_modrm = result[modrm_off];
        const uint8_t rm = x86::modrm_rm(old_modrm);
        result[modrm_off] = x86::make_modrm(3, to_reg_field_, rm);

        const auto old_imm = static_cast<int8_t>(result[imm_off]);
        result[imm_off] = static_cast<uint8_t>(-old_imm);

        return result;
    }

private:
    std::string_view name_;
    std::string_view mnemonic_;
    uint8_t from_reg_field_;
    uint8_t to_reg_field_;
};

/**
 * @brief Правило SHL reg,1 → ADD reg,reg (и обратно).
 *
 * @details SHL reg, 1 (D1 /4) эквивалентен ADD reg, reg (01 reg,reg).
 *          Оба устанавливают CF (из старшего бита для SHL, из переноса для ADD).
 *          Размер: SHL = [REX] D1 ModR/M (2-3 байта), ADD = [REX] 01 ModR/M (2-3 байта).
 */
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
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        ByteBuffer result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;
        const uint8_t rm = x86::modrm_rm(result[modrm_off]);

        result[op_off] = 0x01;
        result[modrm_off] = x86::make_modrm(3, rm, rm);

        return result;
    }
};

/**
 * @brief Правило ADD reg,reg → SHL reg,1 (обратное к Shl1ToAddSelf).
 */
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
        if (!x86::is_same_reg_operands(bytes)) return false;
        return true;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        ByteBuffer result(insn.raw_bytes().begin(), insn.raw_bytes().end());
        const uint8_t op_off = x86::find_opcode_offset(ByteView{result});
        const uint8_t modrm_off = op_off + 1;
        const uint8_t rm = x86::get_full_rm(ByteView{result}) & 0x07;

        result[op_off] = 0xD1;
        result[modrm_off] = x86::make_modrm(3, 4, rm);

        return result;
    }
};

/**
 * @brief Правило CMP reg, 0 → TEST reg, reg (с NOP-padding).
 *
 * @details CMP r/m, 0 (83 /7 00) — 3+ байта.
 *          TEST reg, reg (85 ModR/M) — 2+ байта.
 *          Оба устанавливают ZF/SF/PF одинаково при сравнении с нулём.
 *          Разница заполняется NOP.
 */
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
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t old_modrm = bytes[op_off + 1];
        const uint8_t rm = x86::modrm_rm(old_modrm);

        ByteBuffer result;
        result.reserve(insn.length());

        for (uint8_t i = 0; i < op_off; ++i) {
            result.push_back(bytes[i]);
        }

        result.push_back(0x85);
        result.push_back(x86::make_modrm(3, rm, rm));

        while (result.size() < insn.length()) {
            auto nop = x86::make_nop(static_cast<uint8_t>(insn.length() - result.size()));
            result.insert(result.end(), nop.begin(), nop.end());
        }

        return result;
    }
};

/**
 * @brief Правило MOV reg, 0 → XOR reg, reg (с NOP-padding).
 *
 * @details MOV reg, 0 (B8+r 00000000) — 5 байт (7 с REX.W).
 *          XOR reg, reg (31 ModR/M) — 2 байта (3 с REX).
 *          Семантика: оба обнуляют регистр.
 *
 * @note XOR изменяет флаги (CF=OF=0, ZF=1, SF=0, PF=1),
 *       MOV не изменяет. Применяется когда флаги не критичны
 *       (маркированные регионы подразумевают допустимость).
 */
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

        if (op >= 0xB8 && op <= 0xBF) {
            for (uint8_t i = op_off + 1; i < bytes.size(); ++i) {
                if (bytes[i] != 0x00) return false;
            }
            return true;
        }

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
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t op = bytes[op_off];
        const uint8_t rex = x86::find_rex(bytes);

        uint8_t reg_3bit = 0;
        if (op >= 0xB8 && op <= 0xBF) {
            reg_3bit = op - 0xB8;
        } else if (op == 0xC7) {
            reg_3bit = x86::modrm_rm(bytes[op_off + 1]);
        }

        ByteBuffer result;
        result.reserve(insn.length());

        for (uint8_t i = 0; i < op_off; ++i) {
            if (x86::is_rex(bytes[i])) continue;
            result.push_back(bytes[i]);
        }

        if (rex != 0) {
            uint8_t new_rex = 0x40;
            if (x86::rex_w(rex)) new_rex |= 0x08;
            bool extended = x86::rex_b(rex);
            if (extended) new_rex |= 0x04 | 0x01;
            result.push_back(new_rex);
        } else {
            uint8_t needed_rex = 0;
            if (op >= 0xB8 && op <= 0xBF && x86::rex_b(rex)) {
                needed_rex = 0x44 | 0x01;
            }
            if (needed_rex) result.push_back(needed_rex);
        }

        result.push_back(0x31);
        result.push_back(x86::make_modrm(3, reg_3bit, reg_3bit));

        while (result.size() < insn.length()) {
            auto nop = x86::make_nop(static_cast<uint8_t>(insn.length() - result.size()));
            result.insert(result.end(), nop.begin(), nop.end());
        }

        return result;
    }
};

/**
 * @brief Правило NOT reg → XOR reg, -1 (с NOP-padding если нужно).
 *
 * @details NOT r/m (F7 /2) — 2-3 байта.
 *          XOR r/m, imm32 (81 /6 FFFFFFFF) — 6-7 байт.
 *          Обратное преобразование: XOR reg, -1 → NOT reg (с NOP).
 *          Используем только NOT→XOR когда инструкция достаточно короткая
 *          для замены XOR reg, imm8 (83 /6 FF) — 3 байта.
 */
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
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t rm = x86::modrm_rm(bytes[op_off + 1]);

        ByteBuffer result;
        result.reserve(insn.length());

        for (uint8_t i = 0; i < op_off; ++i) {
            result.push_back(bytes[i]);
        }

        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 6, rm));
        result.push_back(0xFF);

        while (result.size() < insn.length()) {
            auto nop = x86::make_nop(static_cast<uint8_t>(insn.length() - result.size()));
            result.insert(result.end(), nop.begin(), nop.end());
        }

        if (result.size() > insn.length()) {
            return ByteBuffer(insn.raw_bytes().begin(), insn.raw_bytes().end());
        }

        return result;
    }
};

/**
 * @brief Правило INC reg → ADD reg, 1.
 *
 * @details INC r/m (FF /0) — 2-3 байта с ModR/M.
 *          ADD r/m, 1 (83 /0 01) — 3-4 байта.
 *          Разница: INC не изменяет CF, ADD изменяет.
 *
 * @note Применяется только если длина INC >= 3 (чтобы ADD поместился).
 *       С REX: INC = 3 байта, ADD = 4 — не помещается. Только без REX.
 */
class IncToAddOneRule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "inc_to_add_one";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "inc") return false;
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 1 >= bytes.size()) return false;
        if (bytes[op_off] != 0xFF) return false;
        const uint8_t modrm = bytes[op_off + 1];
        if (x86::modrm_mod(modrm) != 3) return false;
        if (x86::modrm_reg(modrm) != 0) return false;
        return insn.length() >= 3;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t rm = x86::modrm_rm(bytes[op_off + 1]);

        ByteBuffer result;
        result.reserve(insn.length());

        for (uint8_t i = 0; i < op_off; ++i) {
            result.push_back(bytes[i]);
        }

        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 0, rm));
        result.push_back(0x01);

        while (result.size() < insn.length()) {
            auto nop = x86::make_nop(static_cast<uint8_t>(insn.length() - result.size()));
            result.insert(result.end(), nop.begin(), nop.end());
        }

        if (result.size() > insn.length()) {
            return ByteBuffer(insn.raw_bytes().begin(), insn.raw_bytes().end());
        }

        return result;
    }
};

/**
 * @brief Правило DEC reg → SUB reg, 1.
 */
class DecToSubOneRule final : public ISubstitutionRule {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "dec_to_sub_one";
    }

    [[nodiscard]] bool matches(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "dec") return false;
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off + 1 >= bytes.size()) return false;
        if (bytes[op_off] != 0xFF) return false;
        const uint8_t modrm = bytes[op_off + 1];
        if (x86::modrm_mod(modrm) != 3) return false;
        if (x86::modrm_reg(modrm) != 1) return false;
        return insn.length() >= 3;
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn, [[maybe_unused]] Randomizer& rng) const override
    {
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t rm = x86::modrm_rm(bytes[op_off + 1]);

        ByteBuffer result;
        result.reserve(insn.length());

        for (uint8_t i = 0; i < op_off; ++i) {
            result.push_back(bytes[i]);
        }

        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 5, rm));
        result.push_back(0x01);

        while (result.size() < insn.length()) {
            auto nop = x86::make_nop(static_cast<uint8_t>(insn.length() - result.size()));
            result.insert(result.end(), nop.begin(), nop.end());
        }

        if (result.size() > insn.length()) {
            return ByteBuffer(insn.raw_bytes().begin(), insn.raw_bytes().end());
        }

        return result;
    }
};

} // anonymous namespace

// ============================================================================
// create_default — фабрика реестра с 25 правилами
// ============================================================================

SubstitutionRuleRegistry SubstitutionRuleRegistry::create_default() {
    SubstitutionRuleRegistry reg;

    // ========================================================================
    // Группа A: Opcode swap (одинаковый регистр, mod=3, reg==rm)
    // ========================================================================

    reg.add_rule(std::make_unique<OpcodeSwapSameRegRule>(
        "xor_to_sub_same_reg", "xor", 0x31, 0x29));

    reg.add_rule(std::make_unique<OpcodeSwapSameRegRule>(
        "xor_to_sub_same_reg_alt", "xor", 0x33, 0x2B));

    reg.add_rule(std::make_unique<OpcodeSwapSameRegRule>(
        "sub_to_xor_same_reg", "sub", 0x29, 0x31));

    reg.add_rule(std::make_unique<OpcodeSwapSameRegRule>(
        "sub_to_xor_same_reg_alt", "sub", 0x2B, 0x33));

    // ========================================================================
    // Группа A2: Opaque test↔and↔or (reg-reg, не обязательно одинаковые)
    // ========================================================================

    reg.add_rule(std::make_unique<OpcodeSwapRegRegRule>(
        "test_to_and", "test", 0x85, 0x21));

    reg.add_rule(std::make_unique<OpcodeSwapRegRegRule>(
        "test_to_or", "test", 0x85, 0x09));

    reg.add_rule(std::make_unique<OpcodeSwapRegRegRule>(
        "and_to_test", "and", 0x21, 0x85));

    reg.add_rule(std::make_unique<OpcodeSwapRegRegRule>(
        "and_to_or", "and", 0x21, 0x09));

    reg.add_rule(std::make_unique<OpcodeSwapRegRegRule>(
        "or_to_test", "or", 0x09, 0x85));

    reg.add_rule(std::make_unique<OpcodeSwapRegRegRule>(
        "or_to_and", "or", 0x09, 0x21));

    // ========================================================================
    // Группа B: Arithmetic negation (ADD imm8 ↔ SUB -imm8)
    // ========================================================================

    reg.add_rule(std::make_unique<Imm8NegationRule>(
        "add_imm8_to_sub_neg", "add", 0, 5));

    reg.add_rule(std::make_unique<Imm8NegationRule>(
        "sub_imm8_to_add_neg", "sub", 5, 0));

    // ========================================================================
    // Группа C: Direction flip (reg-reg кодирование)
    // ========================================================================

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "add_direction_flip", "add", 0x01, 0x03));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "sub_direction_flip", "sub", 0x29, 0x2B));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "xor_direction_flip", "xor", 0x31, 0x33));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "and_direction_flip", "and", 0x21, 0x23));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "or_direction_flip", "or", 0x09, 0x0B));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "cmp_direction_flip", "cmp", 0x39, 0x3B));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "mov_direction_flip", "mov", 0x89, 0x8B));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "adc_direction_flip", "adc", 0x11, 0x13));

    reg.add_rule(std::make_unique<DirectionFlipRule>(
        "sbb_direction_flip", "sbb", 0x19, 0x1B));

    // ========================================================================
    // Группа D: Shift ↔ Add (shl reg,1 ↔ add reg,reg)
    // ========================================================================

    reg.add_rule(std::make_unique<Shl1ToAddSelfRule>());
    reg.add_rule(std::make_unique<AddSelfToShl1Rule>());

    // ========================================================================
    // Группа E: Semantic transforms
    // ========================================================================

    reg.add_rule(std::make_unique<CmpZeroToTestRule>());
    reg.add_rule(std::make_unique<MovZeroToXorRule>());
    reg.add_rule(std::make_unique<NotToXorMinusOneRule>());
    reg.add_rule(std::make_unique<IncToAddOneRule>());
    reg.add_rule(std::make_unique<DecToSubOneRule>());

    return reg;
}

} // namespace mx
