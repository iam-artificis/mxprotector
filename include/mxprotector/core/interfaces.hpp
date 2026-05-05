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

/**
 * @brief Stateful stream-cipher interface.
 *
 * @details `IEncryptor` is a one-shot block-cipher contract — every
 *          call is independent. Stream ciphers (RC4, ChaCha20,
 *          Salsa20) carry continuous state across calls so the
 *          packer can encrypt N back-to-back sections with a single
 *          monotonic keystream. This interface captures that
 *          pattern:
 *
 *            1. `init(key, bias)` — load the key, optionally with a
 *               build-time bias byte that perturbs the key schedule.
 *               Always called once per logical layer, before the
 *               first `process` call of that layer.
 *            2. `process(data)` — XOR-encrypt @p data in place using
 *               the current keystream position. Each call advances
 *               the state by `data.size()` bytes; the caller may
 *               invoke it any number of times before the next
 *               `init`.
 *
 *          For RC4 the bias byte feeds the KSA's `j` register
 *          (mirroring the runtime stub's anti-debug probe). Other
 *          ciphers ignore the bias and treat it as 0.
 *
 *          SOLID (ISP): the interface contains ONLY stream-cipher
 *          operations. Block ciphers belong in `IEncryptor`. Hashing
 *          belongs in `mx::hash::IHash` (R5 future).
 */
class IStreamCipher {
public:
    virtual ~IStreamCipher() = default;

    /**
     * @brief Initialize / re-initialize the cipher state with the
     *        given key.
     *
     * @param key   Cipher key. Implementations document their
     *              accepted key sizes via `key_size()`; a key of a
     *              different size is implementation-defined behaviour
     *              (typically truncated or modular-indexed).
     * @param bias  Build-time bias byte. RC4 stamps it into the KSA's
     *              `j` register; other ciphers ignore it. Defaults
     *              to 0 for cipher-agnostic call sites.
     */
    virtual void init(ByteView key, std::uint8_t bias = 0) noexcept = 0;

    /**
     * @brief XOR @p data with the next `data.size()` bytes of the
     *        keystream, advancing internal state.
     *
     * Stream ciphers are self-inverse through XOR — passing the same
     * ciphertext through `process` with the same post-init state
     * yields back the plaintext.
     */
    virtual void process(MutableByteView data) noexcept = 0;

    /**
     * @brief Recommended key size in bytes.
     *
     * Implementations are typically tolerant of off-size keys (RC4
     * doesn't even have a fixed key size), but the build pipeline
     * uses this value to size key buffers consistently across
     * build-side and stub-side.
     */
    [[nodiscard]] virtual std::size_t key_size() const noexcept = 0;

    /// Human-readable algorithm name for logs / diagnostics.
    [[nodiscard]] virtual std::string_view algorithm_name() const noexcept = 0;
};

} // namespace mx
