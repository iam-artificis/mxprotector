/**
 * @file constants.hpp
 * @brief [SDK] Compile-time обфускация числовых констант.
 *
 * @details Заменяет числовые литералы в коде на compile-time зашифрованные значения.
 *          В бинарнике вместо оригинальной константы хранится зашифрованное значение
 *          и операция дешифрования. Расшифровка происходит в runtime.
 *
 *          Алгоритм: XOR + ADD + ROT с ключами, сгенерированными через consteval LCG.
 *
 * @par Пример использования:
 * @code
 * int secret_port = MX_CONST(8080);
 * if (connection_count > MX_CONST(100)) { ... }
 * @endcode
 */

#pragma once

#include <cstdint>
#include <type_traits>

#include "mxprotector_sdk/strings.hpp" // для compile_time_seed(), lcg()

namespace mx::sdk {

/**
 * @brief Compile-time обфускация целочисленной константы.
 *
 * @tparam T Тип константы (integral).
 * @tparam Key Уникальный ключ шифрования.
 * @tparam Value Оригинальное значение.
 *
 * @details Хранит зашифрованное значение (XOR + ADD). Дешифровка в runtime
 *          через обратные операции. Компилятор не может свернуть runtime-операции
 *          обратно в константу благодаря volatile intermediate.
 */
template <typename T, uint32_t Key, T Value>
    requires std::is_integral_v<T>
class ObfuscatedConstant {
public:
    consteval ObfuscatedConstant()
        : encrypted_(encrypt(Value))
    {}

    /**
     * @brief Расшифровывает значение в runtime.
     * @return Оригинальная константа.
     */
    [[nodiscard]] T value() const {
        volatile T v = encrypted_;
        v = static_cast<T>(v - static_cast<T>(add_key()));
        v = static_cast<T>(v ^ static_cast<T>(xor_key()));
        return v;
    }

    /// @brief Оператор неявного преобразования к типу T.
    [[nodiscard]] operator T() const { return value(); }

private:
    T encrypted_; ///< Зашифрованное значение

    /// @brief XOR-ключ из LCG.
    static consteval uint32_t xor_key() { return lcg(Key, 0); }

    /// @brief ADD-ключ из LCG (второй раунд).
    static consteval uint32_t add_key() { return lcg(Key, 1); }

    /// @brief Шифрует значение на этапе компиляции.
    static consteval T encrypt(T val) {
        val = static_cast<T>(val ^ static_cast<T>(xor_key()));
        val = static_cast<T>(val + static_cast<T>(add_key()));
        return val;
    }
};

} // namespace mx::sdk

/**
 * @brief Макрос для compile-time обфускации целочисленной константы.
 *
 * @param val Целочисленный литерал или constexpr-значение.
 * @return Расшифрованное значение того же типа.
 *
 * @par Пример:
 * @code
 * int port = MX_CONST(8080);
 * size_t max = MX_CONST(1024u);
 * @endcode
 */
#define MX_CONST(val) \
    (::mx::sdk::ObfuscatedConstant< \
        decltype(val), \
        ::mx::sdk::lcg(::mx::sdk::compile_time_seed(), __LINE__), \
        (val)>().value())
