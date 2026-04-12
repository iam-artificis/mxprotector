/**
 * @file mba_transition_gen.hpp
 * @brief [BUILDER] Генератор MBA-обфусцированных state-переходов для CFF.
 *
 * @details MbaTransitionGenerator заменяет простой `mov r10, NEXT_STATE` на цепочку
 *          из 5–10 арифметико-логических операций, вычисляющих следующее состояние
 *          на основе текущего значения state-регистра.
 *
 *          Алгоритм (backward synthesis):
 *          1. Начать с target = next_state.
 *          2. Применить N обратных операций (инвертировать случайные ADD/SUB/XOR/NOT/ROL/ROR).
 *          3. Получить required_input.
 *          4. Первая операция цепочки: XOR reg, (current_state ^ required_input).
 *          5. Далее N прямых операций: reg → next_state.
 *
 *          Все операции выполняются в 32-битном режиме (без REX.W), что обеспечивает
 *          автоматическое zero-extension до 64-бит. State IDs ограничены 31 битом.
 *
 *          SOLID (SRP): отвечает только за генерацию MBA-цепочек state transitions.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx {

/**
 * @brief Генератор MBA-обфусцированных state-переходов.
 *
 * @details Создаёт цепочку инструкций, трансформирующую state-регистр
 *          из current_state в next_state через серию непрозрачных операций.
 */
class MbaTransitionGenerator final {
public:
    explicit MbaTransitionGenerator(Architecture arch);
    ~MbaTransitionGenerator() = default;

    MbaTransitionGenerator(const MbaTransitionGenerator&) = delete;
    MbaTransitionGenerator& operator=(const MbaTransitionGenerator&) = delete;

    /**
     * @brief Генерирует MBA-цепочку для перехода current_state → next_state.
     *
     * @param current_state Текущий state ID в регистре.
     * @param next_state Целевой state ID.
     * @param state_reg Регистр state-переменной.
     * @param rng Генератор случайных чисел.
     * @param state_preserved Если true, state_reg гарантированно содержит
     *        current_state на входе в цепочку (блок не клобберит его) —
     *        цепочка применяется непосредственно к state_reg, создавая
     *        жёсткую зависимость следующего состояния от предыдущего.
     *        Если false, цепочка сначала загружает required_input через
     *        `mov reg, imm32` (fallback для блоков с CALL'ами).
     * @return Буфер машинного кода с цепочкой операций.
     */
    [[nodiscard]] ByteBuffer generate(
        uint32_t current_state,
        uint32_t next_state,
        x86::Reg state_reg,
        Randomizer& rng,
        bool state_preserved = true);

    /**
     * @brief Ограничивает state ID до 31 бита (совместимость с sign-extension CMP).
     */
    [[nodiscard]] static uint32_t sanitize_state_id(uint32_t raw_id) noexcept {
        return raw_id & 0x7FFFFFFF;
    }

private:
    Architecture arch_;

    enum class OpType : uint8_t {
        add_imm, sub_imm, xor_imm, not_op, rol_imm, ror_imm
    };

    struct ChainOp {
        OpType   type;
        uint32_t constant = 0;
    };

    void emit_op_32bit(ByteBuffer& out, OpType type, uint32_t constant,
                       x86::Reg reg) const;

    [[nodiscard]] static uint32_t rotl32(uint32_t value, uint32_t count) noexcept;
    [[nodiscard]] static uint32_t rotr32(uint32_t value, uint32_t count) noexcept;
};

} // namespace mx
