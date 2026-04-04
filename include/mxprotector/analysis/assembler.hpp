/**
 * @file assembler.hpp
 * @brief [BUILDER] Абстрактный интерфейс ассемблера и структурированный кодогенератор x86/x64.
 *
 * @details Определяет два уровня абстракции для генерации машинного кода:
 *
 *          1. IAssembler — строковый ассемблер (для интеграции с Keystone и пр.).
 *             Принимает текст мнемоник и возвращает машинный код.
 *
 *          2. X86CodeEmitter — структурированный кодогенератор, не зависящий от
 *             внешних библиотек. Предоставляет fluent API для генерации x86/x64
 *             инструкций из типизированных параметров (Reg, Imm, Mem).
 *             Используется CFF, MBA, InstructionSplitter и другими модулями.
 *
 *          SOLID (DIP): все модули зависят от IAssembler/X86CodeEmitter,
 *          а не от конкретного Keystone. Keystone подключается через IAssembler.
 *          SOLID (ISP): IAssembler — минимальный интерфейс (только assemble).
 *          X86CodeEmitter — конкретный утилитарный класс (не абстрактный).
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx::analysis {

/**
 * @brief Абстрактный интерфейс строкового ассемблера.
 *
 * @details Принимает текст ассемблерных инструкций и возвращает
 *          машинный код. Конкретные реализации: KeystoneAssembler (Phase 3+),
 *          или любой другой бекенд (NASM, FASM wrapper и т.д.).
 *
 *          SOLID (LSP): любая реализация может быть подставлена.
 */
class IAssembler {
public:
    virtual ~IAssembler() = default;

    /**
     * @brief Ассемблирует текст инструкций в машинный код.
     * @param code Текст ассемблерных инструкций (AT&T или Intel синтаксис).
     * @param address Виртуальный адрес, по которому будет размещён код.
     * @return Буфер машинного кода или ошибка.
     */
    [[nodiscard]] virtual MxResult<ByteBuffer> assemble(
        std::string_view code, Va address = 0) = 0;

    /**
     * @brief Архитектура, для которой генерируется код.
     * @return Architecture::x86 или Architecture::x64.
     */
    [[nodiscard]] virtual Architecture architecture() const noexcept = 0;
};

/**
 * @brief Описание условного перехода (condition code для JCC).
 *
 * @details Значения соответствуют младшему ниблу opcode-байта JCC (0x70+cc / 0x0F 0x80+cc).
 */
enum class ConditionCode : uint8_t {
    overflow         = 0x0,  ///< JO
    not_overflow     = 0x1,  ///< JNO
    below            = 0x2,  ///< JB / JC / JNAE
    above_or_equal   = 0x3,  ///< JAE / JNC / JNB
    equal            = 0x4,  ///< JE / JZ
    not_equal        = 0x5,  ///< JNE / JNZ
    below_or_equal   = 0x6,  ///< JBE / JNA
    above            = 0x7,  ///< JA / JNBE
    sign             = 0x8,  ///< JS
    not_sign         = 0x9,  ///< JNS
    parity           = 0xA,  ///< JP / JPE
    not_parity       = 0xB,  ///< JNP / JPO
    less             = 0xC,  ///< JL / JNGE
    greater_or_equal = 0xD,  ///< JGE / JNL
    less_or_equal    = 0xE,  ///< JLE / JNG
    greater          = 0xF   ///< JG / JNLE
};

/**
 * @brief Описание косвенной адресации [base + index*scale + disp].
 */
struct MemOperand {
    x86::Reg base  = x86::Reg::rax;
    int32_t  disp  = 0;
    bool     has_base = true;

    static MemOperand reg_indirect(x86::Reg base, int32_t disp = 0) {
        return {base, disp, true};
    }
};

/**
 * @brief Маркер (label) для отложенного разрешения адресов переходов.
 */
struct Label {
    uint32_t id = 0;

    [[nodiscard]] bool operator==(const Label& other) const noexcept { return id == other.id; }
};

/**
 * @brief Запись о неразрешённой ссылке на label (для патчинга).
 */
struct LabelFixup {
    Label   label;
    size_t  patch_offset;
    size_t  instruction_end;
    bool    is_rel8 = false;
};

/**
 * @brief Структурированный кодогенератор x86/x64 (Keystone-compatible abstraction).
 *
 * @details Генерирует машинный код x86/x64 из типизированных параметров.
 *          Поддерживает label'ы для автоматического разрешения переходов.
 *          Все методы возвращают ссылку на this для цепочки вызовов (fluent API).
 *
 *          Покрытие: MOV, ADD, SUB, XOR, AND, OR, NOT, NEG, CMP, TEST,
 *                    SHL, SHR, IMUL, JMP, JCC, PUSH, POP, RET, NOP, CALL, LEA.
 *
 *          Не является абстрактным — конкретная реализация без внешних зависимостей.
 *          При наличии Keystone можно использовать IAssembler вместо X86CodeEmitter
 *          для полного покрытия всех инструкций.
 */
class X86CodeEmitter final {
public:
    /**
     * @brief Конструктор.
     * @param is_64bit true для x64 (REX.W), false для x86/32-bit.
     */
    explicit X86CodeEmitter(bool is_64bit = true);
    ~X86CodeEmitter() = default;

    X86CodeEmitter(const X86CodeEmitter&) = delete;
    X86CodeEmitter& operator=(const X86CodeEmitter&) = delete;
    X86CodeEmitter(X86CodeEmitter&&) noexcept = default;
    X86CodeEmitter& operator=(X86CodeEmitter&&) noexcept = default;

    // ====================================================================
    // Labels
    // ====================================================================

    [[nodiscard]] Label create_label();
    X86CodeEmitter& bind_label(Label label);

    // ====================================================================
    // Data Movement
    // ====================================================================

    X86CodeEmitter& mov(x86::Reg dst, uint64_t imm);
    X86CodeEmitter& mov(x86::Reg dst, x86::Reg src);
    X86CodeEmitter& mov(x86::Reg dst, MemOperand src);
    X86CodeEmitter& mov(MemOperand dst, x86::Reg src);
    X86CodeEmitter& mov(MemOperand dst, uint32_t imm);
    X86CodeEmitter& lea(x86::Reg dst, MemOperand src);

    // ====================================================================
    // Arithmetic
    // ====================================================================

    X86CodeEmitter& add(x86::Reg dst, int32_t imm);
    X86CodeEmitter& add(x86::Reg dst, x86::Reg src);
    X86CodeEmitter& sub(x86::Reg dst, int32_t imm);
    X86CodeEmitter& sub(x86::Reg dst, x86::Reg src);
    X86CodeEmitter& imul(x86::Reg dst, x86::Reg src, int32_t imm);

    // ====================================================================
    // Bitwise
    // ====================================================================

    X86CodeEmitter& xor_(x86::Reg dst, int32_t imm);
    X86CodeEmitter& xor_(x86::Reg dst, x86::Reg src);
    X86CodeEmitter& and_(x86::Reg dst, int32_t imm);
    X86CodeEmitter& and_(x86::Reg dst, x86::Reg src);
    X86CodeEmitter& or_(x86::Reg dst, int32_t imm);
    X86CodeEmitter& or_(x86::Reg dst, x86::Reg src);
    X86CodeEmitter& not_(x86::Reg operand);
    X86CodeEmitter& neg(x86::Reg operand);
    X86CodeEmitter& shl(x86::Reg dst, uint8_t count);
    X86CodeEmitter& shr(x86::Reg dst, uint8_t count);

    // ====================================================================
    // Comparison / Test
    // ====================================================================

    X86CodeEmitter& cmp(x86::Reg lhs, int32_t imm);
    X86CodeEmitter& cmp(x86::Reg lhs, x86::Reg rhs);
    X86CodeEmitter& cmp(MemOperand lhs, int32_t imm);
    X86CodeEmitter& test(x86::Reg lhs, x86::Reg rhs);

    // ====================================================================
    // Control Flow
    // ====================================================================

    X86CodeEmitter& jmp(Label target);
    X86CodeEmitter& jmp(int32_t rel32);
    X86CodeEmitter& jcc(ConditionCode cc, Label target);
    X86CodeEmitter& jcc(ConditionCode cc, int32_t rel32);
    X86CodeEmitter& call(int32_t rel32);
    X86CodeEmitter& ret();

    // ====================================================================
    // Stack
    // ====================================================================

    X86CodeEmitter& push(x86::Reg reg);
    X86CodeEmitter& pop(x86::Reg reg);
    X86CodeEmitter& push_imm(int32_t imm);

    // ====================================================================
    // Misc
    // ====================================================================

    X86CodeEmitter& nop(uint8_t count = 1);
    X86CodeEmitter& int3();

    /// @brief Вставляет произвольные сырые байты.
    X86CodeEmitter& raw(ByteView bytes);

    // ====================================================================
    // Finalization
    // ====================================================================

    /**
     * @brief Финализирует код: разрешает все label'ы и возвращает буфер.
     * @return Машинный код или ошибка (неразрешённые label'ы).
     */
    [[nodiscard]] MxResult<ByteBuffer> build();

    /// @brief Текущий размер сгенерированного кода (до финализации).
    [[nodiscard]] size_t current_size() const noexcept { return code_.size(); }

    /// @brief Сбрасывает состояние генератора.
    void clear();

    /// @brief Возвращает режим адресации (64-бит или нет).
    [[nodiscard]] bool is_64bit() const noexcept { return is_64bit_; }

private:
    ByteBuffer code_;
    bool is_64bit_;

    uint32_t next_label_id_ = 1;
    std::vector<std::pair<Label, size_t>> label_bindings_;
    std::vector<LabelFixup> fixups_;

    void emit_byte(uint8_t b);
    void emit_word(uint16_t w);
    void emit_dword(uint32_t d);
    void emit_qword(uint64_t q);

    void emit_rex(bool w, bool r, bool x, bool b);
    void emit_rex_if_needed(bool force_w, x86::Reg reg, x86::Reg rm);
    void emit_modrm_reg_reg(uint8_t reg_field, x86::Reg rm);

    void emit_alu_reg_imm(uint8_t alu_op, x86::Reg dst, int32_t imm);
    void emit_alu_reg_reg(uint8_t opcode_rm_r, x86::Reg dst, x86::Reg src);
    void emit_unary_reg(uint8_t reg_field, x86::Reg operand);
    void emit_mem_operand(uint8_t reg_field, MemOperand mem);
};

} // namespace mx::analysis
