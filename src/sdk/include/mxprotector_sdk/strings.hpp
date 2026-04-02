/**
 * @file strings.hpp
 * @brief [SDK] Compile-time шифрование строк (consteval/constexpr).
 *
 * @details Реализует шифрование строковых литералов на этапе компиляции,
 *          так что в бинарнике отсутствуют открытые строки. Расшифровка
 *          происходит в runtime при первом обращении.
 *
 *          Алгоритм: побайтовый XOR с ключом, сгенерированным из __LINE__
 *          и seed'а на основе __TIME__. Ключ вычисляется через consteval
 *          LCG (Linear Congruential Generator).
 *
 * @par Пример использования:
 * @code
 * const char* msg = MX_STRING("Секретное сообщение");
 * printf("%s\n", msg); // Расшифровывается в runtime
 * @endcode
 *
 * @note Каждый вызов MX_STRING генерирует уникальный ключ на основе __LINE__.
 *       Строки расшифровываются в стековый буфер (без heap-аллокаций).
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <utility>

namespace mx::sdk {

/**
 * @brief Consteval seed из __TIME__ для генерации уникальных ключей.
 * @details Вычисляет числовое значение из строки времени компиляции.
 *          Разное для каждой единицы трансляции, скомпилированной в разное время.
 */
consteval uint32_t compile_time_seed() {
    const char time[] = __TIME__;  // "HH:MM:SS"
    return static_cast<uint32_t>(time[0]) * 100000u +
           static_cast<uint32_t>(time[1]) * 10000u +
           static_cast<uint32_t>(time[3]) * 1000u +
           static_cast<uint32_t>(time[4]) * 100u +
           static_cast<uint32_t>(time[6]) * 10u +
           static_cast<uint32_t>(time[7]);
}

/**
 * @brief Consteval LCG для генерации псевдослучайных ключей.
 * @param seed Начальное значение.
 * @param round Номер итерации.
 * @return Псевдослучайное 32-битное значение.
 */
consteval uint32_t lcg(uint32_t seed, uint32_t round) {
    uint32_t state = seed;
    for (uint32_t i = 0; i < round + 1; ++i) {
        state = state * 1664525u + 1013904223u;
    }
    return state;
}

/**
 * @brief Зашифрованная строка — хранится в compile-time, расшифровывается в runtime.
 *
 * @tparam N Длина строки (включая терминирующий нуль).
 * @tparam Key 32-битный ключ шифрования (уникален для каждого вызова).
 *
 * @details Конструктор (consteval) шифрует строку XOR'ом с потоком ключей,
 *          генерируемым из Key через LCG. Метод decrypt() расшифровывает
 *          в runtime и возвращает указатель на стековый буфер.
 *
 *          Безопасность: строка в бинарнике зашифрована. Без знания Key
 *          (который не хранится явно) статический анализ не восстановит строку.
 */
template <size_t N, uint32_t Key>
class EncryptedString {
public:
    /**
     * @brief Шифрует строку на этапе компиляции.
     * @param str Строковый литерал.
     */
    consteval EncryptedString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i) {
            const uint8_t key_byte = static_cast<uint8_t>(lcg(Key, static_cast<uint32_t>(i)) >> 16);
            data_[i] = static_cast<char>(str[i] ^ key_byte);
        }
    }

    /**
     * @brief Расшифровывает строку в runtime.
     * @return Указатель на расшифрованный стековый буфер (thread-local).
     *
     * @note Буфер thread_local — безопасен для многопоточного использования.
     *       Каждый вызов перезаписывает предыдущий результат (один буфер на тип).
     */
    const char* decrypt() const {
        thread_local char buffer[N];
        for (size_t i = 0; i < N; ++i) {
            const uint8_t key_byte = static_cast<uint8_t>(lcg(Key, static_cast<uint32_t>(i)) >> 16);
            buffer[i] = static_cast<char>(data_[i] ^ key_byte);
        }
        return buffer;
    }

    /// @brief Оператор вызова — синоним decrypt().
    const char* operator()() const { return decrypt(); }

private:
    char data_[N]{}; ///< Зашифрованные данные
};

} // namespace mx::sdk

/**
 * @brief Макрос для compile-time шифрования строкового литерала.
 *
 * @param str Строковый литерал (например, "Hello World").
 * @return const char* — расшифрованная строка (в стековом буфере).
 *
 * @details Генерирует уникальный ключ на основе __LINE__ и compile_time_seed().
 *          Каждое использование MX_STRING создаёт уникальный шифрованный экземпляр.
 *
 * @par Пример:
 * @code
 * printf("%s\n", MX_STRING("Скрытая строка"));
 * @endcode
 */
#define MX_STRING(str) \
    ([]() -> const char* { \
        constexpr auto encrypted = ::mx::sdk::EncryptedString< \
            sizeof(str), \
            ::mx::sdk::lcg(::mx::sdk::compile_time_seed(), __LINE__)>(str); \
        return encrypted.decrypt(); \
    }())
