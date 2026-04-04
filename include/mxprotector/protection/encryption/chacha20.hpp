/**
 * @file chacha20.hpp
 * @brief [BUILDER] Реализация шифрования ChaCha20 (RFC 7539).
 *
 * @details ChaCha20Encryptor — основной алгоритм шифрования Builder-side.
 *          Реализует интерфейс IEncryptor. Потоковый шифр с 256-битным ключом
 *          и 96-битным nonce. Быстрый, не зависит от AES-NI, портируемый.
 *
 *          Спецификация: RFC 7539 (ChaCha20 и Poly1305 для IETF Protocols).
 *          В данной реализации используется только ChaCha20 без Poly1305 —
 *          аутентификация обеспечивается CRC32 в EncryptedSectionEntry.
 *
 * @note Принцип LSP (SOLID): ChaCha20Encryptor взаимозаменяем с AesEncryptor
 *       через IEncryptor. Выбор алгоритма определяется конфигурацией.
 */

#pragma once

#include <array>
#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/interfaces.hpp"

namespace mx {

/**
 * @brief Реализация потокового шифра ChaCha20 (RFC 7539).
 *
 * @details Шифрует/расшифровывает данные с помощью 256-битного ключа и
 *          96-битного nonce. Шифрование и расшифровка идентичны (XOR).
 *          Внутренние состояния — 512-битная матрица (16 × uint32_t).
 *
 *          SOLID (SRP): отвечает только за шифрование/расшифровку ChaCha20.
 */
class ChaCha20Encryptor final : public IEncryptor {
public:
    /// @brief Размер ключа: 32 байта (256 бит).
    static constexpr size_t KEY_BYTES = 32;

    /// @brief Размер nonce: 12 байт (96 бит, IETF variant).
    static constexpr size_t NONCE_BYTES = 12;

    /// @brief Размер блока: 64 байта (512 бит).
    static constexpr size_t BLOCK_BYTES = 64;

    ChaCha20Encryptor() = default;
    ~ChaCha20Encryptor() override = default;

    /**
     * @brief Шифрует данные алгоритмом ChaCha20.
     * @param data Открытый текст.
     * @param key Ключ (32 байта).
     * @param iv Nonce (12 байт).
     * @return Зашифрованный буфер или ошибка.
     */
    [[nodiscard]] MxResult<ByteBuffer> encrypt(
        ByteView data, ByteView key, ByteView iv) override;

    /**
     * @brief Расшифровывает данные (идентично encrypt для потокового шифра).
     * @param data Шифротекст.
     * @param key Ключ (32 байта).
     * @param iv Nonce (12 байт).
     * @return Расшифрованный буфер или ошибка.
     */
    [[nodiscard]] MxResult<ByteBuffer> decrypt(
        ByteView data, ByteView key, ByteView iv) override;

    [[nodiscard]] size_t key_size() const noexcept override { return KEY_BYTES; }
    [[nodiscard]] size_t iv_size() const noexcept override { return NONCE_BYTES; }
    [[nodiscard]] std::string_view algorithm_name() const noexcept override { return "ChaCha20"; }

    /**
     * @brief Генерирует криптографически случайный ключ.
     * @return 32-байтный ключ.
     */
    [[nodiscard]] static std::array<uint8_t, KEY_BYTES> generate_key();

    /**
     * @brief Генерирует криптографически случайный nonce.
     * @return 12-байтный nonce.
     */
    [[nodiscard]] static std::array<uint8_t, NONCE_BYTES> generate_nonce();

private:
    /// @brief Тип состояния ChaCha20: 16 × 32-битных слов.
    using State = std::array<uint32_t, 16>;

    /**
     * @brief Инициализирует состояние ChaCha20 из ключа, nonce и счётчика блока.
     * @param key Ключ (32 байта).
     * @param nonce Nonce (12 байт).
     * @param counter Номер блока.
     * @return Инициализированное состояние.
     */
    [[nodiscard]] static State init_state(
        ByteView key, ByteView nonce, uint32_t counter) noexcept;

    /**
     * @brief Выполняет 20 раундов ChaCha20 (10 double-rounds).
     * @param state Состояние (модифицируется in-place).
     */
    static void chacha20_block(State& state) noexcept;

    /**
     * @brief Quarter-round — базовая операция ChaCha20 (ARX: add-rotate-xor).
     * @param a, b, c, d Индексы в матрице состояния.
     * @param state Состояние (модифицируется).
     */
    static void quarter_round(
        uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept;

    /**
     * @brief Применяет keystream к данным (XOR).
     * @param data Входные данные.
     * @param key Ключ (32 байта).
     * @param nonce Nonce (12 байт).
     * @return Результат XOR с keystream.
     */
    [[nodiscard]] ByteBuffer apply_keystream(
        ByteView data, ByteView key, ByteView nonce) const;

    /**
     * @brief Валидирует размеры ключа и nonce.
     * @param key Ключ.
     * @param iv Nonce.
     * @return Успех или ошибка валидации.
     */
    [[nodiscard]] static MxStatus validate_params(ByteView key, ByteView iv);
};

} // namespace mx
