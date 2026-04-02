/**
 * @file interfaces.hpp
 * @brief [BUILDER] Центральное место для объявления абстрактных интерфейсов проекта.
 *
 * @details Собирает все ключевые интерфейсы, используемые в пайплайне защиты.
 *          IDisassembler определён в analysis/disassembler.hpp (здесь forward-declare).
 *          IEncryptor определяет контракт для симметричного шифрования/дешифрования
 *          блоков данных с ключом и вектором инициализации.
 *
 * @note Принцип DIP (SOLID): все модули зависят от абстракций, определённых здесь,
 *       а не от конкретных реализаций.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"

namespace mx::analysis {
class IDisassembler;
} // namespace mx::analysis

namespace mx {

/**
 * @brief Абстрактный интерфейс для симметричного шифрования/дешифрования.
 *
 * @details Определяет контракт для блочного шифрования с ключом и IV.
 *          Конкретные реализации (ChaCha20, AES-256-CBC и т.д.) должны
 *          наследовать этот интерфейс.
 *
 *          SOLID (ISP): интерфейс содержит ТОЛЬКО операции шифрования.
 *          Генерация ключей, HMAC и т.д. — отдельные интерфейсы.
 */
class IEncryptor {
public:
    virtual ~IEncryptor() = default;

    /**
     * @brief Шифрует блок данных.
     * @param data Открытый текст для шифрования.
     * @param key Ключ шифрования (размер должен совпадать с key_size()).
     * @param iv Вектор инициализации (размер должен совпадать с iv_size()).
     * @return Зашифрованный буфер или ошибка.
     */
    [[nodiscard]] virtual MxResult<ByteBuffer> encrypt(
        ByteView data, ByteView key, ByteView iv) = 0;

    /**
     * @brief Расшифровывает блок данных.
     * @param data Шифротекст для расшифровки.
     * @param key Ключ шифрования (размер должен совпадать с key_size()).
     * @param iv Вектор инициализации (размер должен совпадать с iv_size()).
     * @return Расшифрованный буфер или ошибка.
     */
    [[nodiscard]] virtual MxResult<ByteBuffer> decrypt(
        ByteView data, ByteView key, ByteView iv) = 0;

    /**
     * @brief Требуемый размер ключа в байтах.
     * @return Размер ключа.
     */
    [[nodiscard]] virtual size_t key_size() const noexcept = 0;

    /**
     * @brief Требуемый размер вектора инициализации в байтах.
     * @return Размер IV.
     */
    [[nodiscard]] virtual size_t iv_size() const noexcept = 0;

    /**
     * @brief Название алгоритма шифрования (для логирования).
     * @return Строковое представление (например, "ChaCha20", "AES-256-CBC").
     */
    [[nodiscard]] virtual std::string_view algorithm_name() const noexcept = 0;
};

} // namespace mx
