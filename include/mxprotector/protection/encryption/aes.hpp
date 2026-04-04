/**
 * @file aes.hpp
 * @brief [BUILDER] Реализация AES-256-CTR шифрования (с AES-NI + software fallback).
 *
 * @details AesEncryptor реализует AES-256 в режиме CTR (Counter Mode).
 *          Основной путь исполнения — AES-NI интринсики (аппаратное ускорение).
 *          Софтверный fallback на основе T-tables для CPU без AES-NI.
 *
 *          CTR-режим превращает блочный шифр в потоковый: для каждого блока
 *          шифруется counter, а результат XOR-ится с открытым текстом.
 *          Шифрование и расшифровка идентичны.
 *
 * @note AES-NI доступность проверяется через CPUID при первом использовании.
 *       Принцип LSP: AesEncryptor полностью взаимозаменяем с ChaCha20Encryptor
 *       через IEncryptor.
 */

#pragma once

#include <array>
#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/interfaces.hpp"

namespace mx {

/**
 * @brief Реализация AES-256 в режиме CTR.
 *
 * @details Поддерживает два пути исполнения:
 *          - AES-NI (hardware): используется при наличии поддержки CPU
 *          - Software T-tables: fallback для совместимости
 *
 *          SOLID (SRP): отвечает только за AES-256-CTR шифрование/расшифровку.
 */
class AesEncryptor final : public IEncryptor {
public:
    /// @brief Размер ключа: 32 байта (256 бит).
    static constexpr size_t KEY_BYTES = 32;

    /// @brief Размер IV: 16 байт (128 бит — CTR initial counter block).
    static constexpr size_t IV_BYTES = 16;

    /// @brief Размер блока AES: 16 байт (128 бит).
    static constexpr size_t BLOCK_BYTES = 16;

    /// @brief Количество раундов AES-256.
    static constexpr int NUM_ROUNDS = 14;

    /// @brief Размер расширенного ключа (round keys).
    static constexpr size_t EXPANDED_KEY_WORDS = 4 * (NUM_ROUNDS + 1);

    AesEncryptor();
    ~AesEncryptor() override = default;

    /**
     * @brief Шифрует данные в режиме AES-256-CTR.
     * @param data Открытый текст.
     * @param key Ключ (32 байта).
     * @param iv Начальное значение счётчика (16 байт).
     * @return Зашифрованный буфер или ошибка.
     */
    [[nodiscard]] MxResult<ByteBuffer> encrypt(
        ByteView data, ByteView key, ByteView iv) override;

    /**
     * @brief Расшифровывает данные (идентично encrypt для CTR-режима).
     * @param data Шифротекст.
     * @param key Ключ (32 байта).
     * @param iv Начальное значение счётчика (16 байт).
     * @return Расшифрованный буфер или ошибка.
     */
    [[nodiscard]] MxResult<ByteBuffer> decrypt(
        ByteView data, ByteView key, ByteView iv) override;

    [[nodiscard]] size_t key_size() const noexcept override { return KEY_BYTES; }
    [[nodiscard]] size_t iv_size() const noexcept override { return IV_BYTES; }
    [[nodiscard]] std::string_view algorithm_name() const noexcept override { return "AES-256-CTR"; }

    /// @brief Проверяет поддержку AES-NI процессором.
    [[nodiscard]] static bool is_aesni_supported() noexcept;

    /// @brief Возвращает true, если используется аппаратное ускорение.
    [[nodiscard]] bool using_hardware() const noexcept { return use_aesni_; }

    /**
     * @brief Генерирует криптографически случайный ключ.
     * @return 32-байтный ключ.
     */
    [[nodiscard]] static std::array<uint8_t, KEY_BYTES> generate_key();

    /**
     * @brief Генерирует криптографически случайный IV.
     * @return 16-байтный IV.
     */
    [[nodiscard]] static std::array<uint8_t, IV_BYTES> generate_iv();

private:
    bool use_aesni_ = false; ///< Использовать AES-NI

    /// @brief Расширенные раундовые ключи.
    using RoundKeys = std::array<uint32_t, EXPANDED_KEY_WORDS>;

    /**
     * @brief Выполняет Key Expansion (расширение ключа AES-256).
     * @param key Ключ (32 байта).
     * @return Массив раундовых ключей.
     */
    [[nodiscard]] static RoundKeys key_expansion(ByteView key) noexcept;

    /**
     * @brief Шифрует один блок AES-256 (software путь, T-tables).
     * @param block 16-байтный блок (модифицируется in-place).
     * @param round_keys Расширенные раундовые ключи.
     */
    static void encrypt_block_sw(uint8_t* block, const RoundKeys& round_keys) noexcept;

    /**
     * @brief Применяет AES-256-CTR к данным.
     * @param data Входные данные.
     * @param key Ключ (32 байта).
     * @param iv Начальный counter block (16 байт).
     * @return Результат шифрования.
     */
    [[nodiscard]] ByteBuffer apply_ctr(ByteView data, ByteView key, ByteView iv) const;

    /**
     * @brief CTR: инкрементирует 128-битный счётчик (big-endian, последние 4 байта).
     * @param counter_block 16-байтный блок счётчика (модифицируется).
     */
    static void increment_counter(uint8_t* counter_block) noexcept;

    /**
     * @brief Валидирует размеры ключа и IV.
     * @param key Ключ.
     * @param iv IV.
     * @return Успех или ошибка.
     */
    [[nodiscard]] static MxStatus validate_params(ByteView key, ByteView iv);
};

} // namespace mx
