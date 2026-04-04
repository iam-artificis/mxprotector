/**
 * @file dispatcher_gen.hpp
 * @brief [BUILDER] Генератор диспетчера для Control Flow Flattening (CFF).
 *
 * @details DispatcherGenerator создаёт машинный код диспетчера — центрального
 *          switch-блока, управляющего выполнением расплющенных базовых блоков.
 *          State variable определяет, какой блок выполнить следующим.
 *
 *          Архитектура диспетчера:
 *          ```
 *          dispatcher:
 *              cmp [state_var], BLOCK_0_ID  → je block_0
 *              cmp [state_var], BLOCK_1_ID  → je block_1
 *              ...
 *              jmp exit
 *          block_0:
 *              <original instructions>
 *              mov [state_var], NEXT_STATE  ← MBA-зашифрованный переход
 *              jmp dispatcher
 *          block_1:
 *              ...
 *          ```
 *
 *          State variable обфусцируется: каждый блок вычисляет следующий state
 *          через MBA-трансформацию, что делает невозможным восстановление CFG
 *          статическим анализом.
 *
 * @note Диспетчер можно генерировать как linear-scan (O(n) сравнений)
 *       или binary-search (O(log n)) для больших функций.
 */

#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/basic_block.hpp"

namespace mx {

/**
 * @brief Описание одного блока в расплющенной функции.
 */
struct FlattenedBlock {
    uint32_t   original_block_id;
    uint32_t   state_id;
    ByteBuffer code;
    std::vector<uint32_t> successor_states;
    Va         original_va = 0;
    analysis::ConditionCode branch_cc = analysis::ConditionCode::not_equal;
};

/**
 * @brief Позиция блока в сгенерированном выходном буфере.
 */
struct BlockPlacement {
    uint32_t output_offset;
    uint32_t code_size;
    Va       original_va;
};

/**
 * @brief Результат генерации диспетчера.
 */
struct DispatcherResult {
    ByteBuffer dispatcher_code;
    std::vector<FlattenedBlock> blocks;
    ByteBuffer full_function;
    uint32_t   state_var_offset = 0;
    uint32_t   total_size       = 0;
    std::vector<BlockPlacement> block_placements;
};

/**
 * @brief Генератор диспетчера CFF (Control Flow Flattening).
 *
 * @details Принимает CFG функции и генерирует расплющенную версию:
 *          все блоки размещаются линейно, управление осуществляется
 *          через state variable и центральный диспетчер.
 *
 *          SOLID (SRP): отвечает только за генерацию dispatcher-кода.
 *          SOLID (DIP): использует X86CodeEmitter для генерации (не зависит от Keystone).
 */
class DispatcherGenerator final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура.
     */
    explicit DispatcherGenerator(Architecture arch);
    ~DispatcherGenerator() = default;

    DispatcherGenerator(const DispatcherGenerator&) = delete;
    DispatcherGenerator& operator=(const DispatcherGenerator&) = delete;

    /**
     * @brief Генерирует код диспетчера для набора блоков.
     *
     * @param blocks Расплющенные блоки с назначенными state_id.
     * @param entry_state_id State ID входного блока.
     * @param state_var_reg Регистр, хранящий state variable.
     * @param rng Генератор случайных чисел.
     * @return Полный код функции (диспетчер + все блоки) или ошибка.
     */
    [[nodiscard]] MxResult<DispatcherResult> generate(
        std::vector<FlattenedBlock>& blocks,
        uint32_t entry_state_id,
        x86::Reg state_var_reg,
        Randomizer& rng);

    /**
     * @brief Назначает случайные state ID для блоков.
     * @param block_count Количество блоков.
     * @param rng Генератор случайных чисел.
     * @return Маппинг: original_block_id → state_id.
     */
    [[nodiscard]] std::unordered_map<uint32_t, uint32_t> assign_state_ids(
        const std::vector<uint32_t>& block_ids,
        Randomizer& rng);

    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_;

    [[nodiscard]] bool is_64bit() const noexcept { return arch_ == Architecture::x64; }
};

} // namespace mx
