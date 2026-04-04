/**
 * @file bogus_flow.hpp
 * @brief [BUILDER] Генератор ложного потока управления (Bogus Control Flow).
 *
 * @details BogusFlowGenerator вставляет ложные пути исполнения с opaque predicates.
 *          Граф разрастается экспоненциально: для каждого блока добавляются
 *          1–2 ложных перехода, защищённых always-true/always-false предикатами.
 *
 *          Принцип работы:
 *          1. Перед каждым блоком вставляется opaque predicate (always-true).
 *          2. True-ветвь ведёт к оригинальному коду.
 *          3. False-ветвь ведёт к мусорному блоку (junk code).
 *          4. Мусорный блок содержит реалистичный, но бессмысленный код.
 *
 *          Hex-Rays/IDA видит оба пути как реальные → нечитаемая декомпиляция.
 *
 *          SOLID (SRP): отвечает только за генерацию bogus flow.
 *          SOLID (OCP): стратегии bogus flow расширяемы.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/mutation/junk_generator.hpp"

namespace mx {

/**
 * @brief Сгенерированный bogus-блок.
 */
struct BogusBlock {
    ByteBuffer predicate_code;
    ByteBuffer junk_code;
    uint32_t   total_size = 0;
};

/**
 * @brief Генератор ложного потока управления.
 *
 * @details Создаёт bogus-блоки: пара [opaque_predicate + junk_block],
 *          которые оборачивают реальный код. Статический анализатор не может
 *          определить, что false-ветвь никогда не выполняется.
 */
class BogusFlowGenerator final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура.
     */
    explicit BogusFlowGenerator(Architecture arch);
    ~BogusFlowGenerator() = default;

    BogusFlowGenerator(const BogusFlowGenerator&) = delete;
    BogusFlowGenerator& operator=(const BogusFlowGenerator&) = delete;

    /**
     * @brief Генерирует bogus-блок для вставки перед реальным блоком.
     *
     * @param junk_size Желаемый размер мусорного кода в байтах.
     * @param rng Генератор случайных чисел.
     * @return BogusBlock с предикатом и мусорным кодом.
     */
    [[nodiscard]] BogusBlock generate(uint32_t junk_size, Randomizer& rng);

    /**
     * @brief Генерирует серию bogus-блоков для всех блоков функции.
     *
     * @param block_count Количество блоков функции.
     * @param bogus_probability Вероятность вставки bogus для каждого блока [0.0, 1.0].
     * @param rng Генератор случайных чисел.
     * @return Вектор BogusBlock (пустые записи для блоков без bogus).
     */
    [[nodiscard]] std::vector<BogusBlock> generate_for_function(
        uint32_t block_count,
        double bogus_probability,
        Randomizer& rng);

    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_;
    OpaquePredicateGenerator pred_gen_;
    JunkGenerator junk_gen_;
};

} // namespace mx
