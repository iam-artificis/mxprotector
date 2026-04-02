/**
 * @file randomizer.hpp
 * @brief [BUILDER] Генератор псевдослучайных чисел для нужд протектора.
 *
 * @details Обёртка над std::mt19937_64, предоставляющая удобные методы
 *          генерации случайных значений различных типов. Используется
 *          во всех модулях, требующих рандомизации: мутация, обфускация,
 *          генерация junk-кода, opaque predicates и т.д.
 *
 * @note В будущих фазах может быть заменён на ChaCha20-based CSPRNG
 *       для криптографической стойкости (Phase 3+).
 */

#pragma once

#include <cstdint>
#include <random>

namespace mx {

/**
 * @brief Генератор псевдослучайных чисел на базе Mersenne Twister (64-bit).
 *
 * @details Инкапсулирует std::mt19937_64 с автоматическим посевом из
 *          std::random_device при создании по умолчанию. Поддерживает
 *          генерацию целых чисел, булевых значений с заданной вероятностью
 *          и значений из диапазона [min, max].
 *
 *          SOLID (SRP): отвечает только за генерацию случайных чисел.
 */
class Randomizer final {
public:
    /// @brief Конструктор с автоматическим посевом из аппаратного источника.
    Randomizer() : engine_(std::random_device{}()) {}

    /**
     * @brief Конструктор с фиксированным seed (для детерминированного тестирования).
     * @param seed Начальное значение генератора.
     */
    explicit Randomizer(uint64_t seed) : engine_(seed) {}

    ~Randomizer() = default;

    Randomizer(const Randomizer&) = delete;
    Randomizer& operator=(const Randomizer&) = delete;
    Randomizer(Randomizer&&) noexcept = default;
    Randomizer& operator=(Randomizer&&) noexcept = default;

    /// @brief Генерирует случайное 64-битное значение.
    [[nodiscard]] uint64_t next_u64() { return dist64_(engine_); }

    /// @brief Генерирует случайное 32-битное значение.
    [[nodiscard]] uint32_t next_u32() { return static_cast<uint32_t>(dist64_(engine_)); }

    /// @brief Генерирует случайное 16-битное значение.
    [[nodiscard]] uint16_t next_u16() { return static_cast<uint16_t>(dist64_(engine_)); }

    /// @brief Генерирует случайное 8-битное значение.
    [[nodiscard]] uint8_t next_u8() { return static_cast<uint8_t>(dist64_(engine_)); }

    /**
     * @brief Генерирует случайное значение в замкнутом диапазоне [min, max].
     * @param min Минимальное значение (включительно).
     * @param max Максимальное значение (включительно).
     * @return Случайное значение ∈ [min, max].
     */
    [[nodiscard]] uint32_t next_range(uint32_t min, uint32_t max) {
        std::uniform_int_distribution<uint32_t> dist(min, max);
        return dist(engine_);
    }

    /// @copydoc next_range(uint32_t, uint32_t)
    [[nodiscard]] uint64_t next_range64(uint64_t min, uint64_t max) {
        std::uniform_int_distribution<uint64_t> dist(min, max);
        return dist(engine_);
    }

    /**
     * @brief Генерирует случайное булево значение с заданной вероятностью.
     * @param probability Вероятность true ∈ [0.0, 1.0].
     * @return true с вероятностью probability.
     */
    [[nodiscard]] bool next_bool(double probability = 0.5) {
        std::bernoulli_distribution dist(probability);
        return dist(engine_);
    }

    /// @brief Доступ к базовому движку для алгоритмов STL (std::shuffle и т.д.).
    [[nodiscard]] std::mt19937_64& engine() noexcept { return engine_; }

private:
    std::mt19937_64 engine_;                        ///< Генератор Mersenne Twister 64-bit
    std::uniform_int_distribution<uint64_t> dist64_; ///< Равномерное распределение [0, UINT64_MAX]
};

} // namespace mx
