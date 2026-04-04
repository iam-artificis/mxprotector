/**
 * @file chacha20_encryptor.cpp
 * @brief [BUILDER] Реализация ChaCha20 (RFC 7539).
 *
 * @details Полная реализация ChaCha20 потокового шифра. Алгоритм:
 *          1. Инициализация 512-битного состояния из константы, ключа, счётчика и nonce
 *          2. 20 раундов ARX (Add-Rotate-XOR) по Quarter-Round схеме
 *          3. Суммирование результата с начальным состоянием
 *          4. Сериализация в 64-байтный keystream-блок
 *          5. XOR keystream с данными (потоковое шифрование)
 *
 *          Шифрование и расшифровка идентичны (XOR — обратимая операция).
 *          Генерация ключей и nonce использует std::random_device (аппаратный CSPRNG).
 *
 * @note Реализация не зависит от платформенных API — чистый C++.
 *       Безопасна для использования в любом контексте Builder.
 */

#include "mxprotector/protection/encryption/chacha20.hpp"

#include <algorithm>
#include <cstring>
#include <random>

namespace mx {

namespace {

/// @brief Циклический сдвиг влево для 32-битного целого.
[[nodiscard]] constexpr uint32_t rotl32(uint32_t value, unsigned int shift) noexcept {
    return (value << shift) | (value >> (32 - shift));
}

/// @brief Сериализует uint32_t в little-endian байты.
constexpr void u32_to_le(uint8_t* out, uint32_t value) noexcept {
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
    out[2] = static_cast<uint8_t>(value >> 16);
    out[3] = static_cast<uint8_t>(value >> 24);
}

/// @brief Десериализует 4 байта little-endian в uint32_t.
[[nodiscard]] constexpr uint32_t le_to_u32(const uint8_t* in) noexcept {
    return static_cast<uint32_t>(in[0])
         | (static_cast<uint32_t>(in[1]) << 8)
         | (static_cast<uint32_t>(in[2]) << 16)
         | (static_cast<uint32_t>(in[3]) << 24);
}

/// @brief ChaCha20 "expand 32-byte k" — ASCII-константа для инициализации.
constexpr uint32_t CHACHA_CONST_0 = 0x61707865; // "expa"
constexpr uint32_t CHACHA_CONST_1 = 0x3320646E; // "nd 3"
constexpr uint32_t CHACHA_CONST_2 = 0x79622D32; // "2-by"
constexpr uint32_t CHACHA_CONST_3 = 0x6B206574; // "te k"

} // anonymous namespace

// ============================================================================
// Quarter-Round: базовая ARX-операция (RFC 7539 §2.1)
// ============================================================================

void ChaCha20Encryptor::quarter_round(
    uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept
{
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// ============================================================================
// Инициализация состояния (RFC 7539 §2.3)
// ============================================================================

ChaCha20Encryptor::State ChaCha20Encryptor::init_state(
    ByteView key, ByteView nonce, uint32_t counter) noexcept
{
    State state{};

    state[0] = CHACHA_CONST_0;
    state[1] = CHACHA_CONST_1;
    state[2] = CHACHA_CONST_2;
    state[3] = CHACHA_CONST_3;

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = le_to_u32(key.data() + i * 4);
    }

    state[12] = counter;

    for (int i = 0; i < 3; ++i) {
        state[13 + i] = le_to_u32(nonce.data() + i * 4);
    }

    return state;
}

// ============================================================================
// ChaCha20 Block Function (RFC 7539 §2.3)
// ============================================================================

void ChaCha20Encryptor::chacha20_block(State& state) noexcept {
    State working = state;

    for (int i = 0; i < 10; ++i) {
        quarter_round(working[0], working[4], working[8],  working[12]);
        quarter_round(working[1], working[5], working[9],  working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);

        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8],  working[13]);
        quarter_round(working[3], working[4], working[9],  working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        working[i] += state[i];
    }

    state = working;
}

// ============================================================================
// Валидация параметров
// ============================================================================

MxStatus ChaCha20Encryptor::validate_params(ByteView key, ByteView iv) {
    if (key.size() != KEY_BYTES) {
        return std::unexpected(error::encryption_fmt(
            EncryptionErrorCode::invalid_key_size,
            "ChaCha20: размер ключа {} байт, ожидается {} байт",
            key.size(), KEY_BYTES));
    }
    if (iv.size() != NONCE_BYTES) {
        return std::unexpected(error::encryption_fmt(
            EncryptionErrorCode::invalid_iv_size,
            "ChaCha20: размер nonce {} байт, ожидается {} байт",
            iv.size(), NONCE_BYTES));
    }
    return {};
}

// ============================================================================
// Применение keystream (XOR)
// ============================================================================

ByteBuffer ChaCha20Encryptor::apply_keystream(
    ByteView data, ByteView key, ByteView nonce) const
{
    ByteBuffer output(data.size());
    const size_t full_blocks = data.size() / BLOCK_BYTES;
    const size_t remainder = data.size() % BLOCK_BYTES;

    for (size_t block_idx = 0; block_idx <= full_blocks; ++block_idx) {
        const size_t offset = block_idx * BLOCK_BYTES;
        const size_t chunk_size = (block_idx < full_blocks) ? BLOCK_BYTES : remainder;

        if (chunk_size == 0) break;

        auto state = init_state(key, nonce, static_cast<uint32_t>(block_idx + 1));
        State initial_state = state;
        chacha20_block(state);

        uint8_t keystream[BLOCK_BYTES];
        for (int i = 0; i < 16; ++i) {
            u32_to_le(keystream + i * 4, state[i]);
        }

        for (size_t i = 0; i < chunk_size; ++i) {
            output[offset + i] = data[offset + i] ^ keystream[i];
        }
    }

    return output;
}

// ============================================================================
// IEncryptor: encrypt / decrypt
// ============================================================================

MxResult<ByteBuffer> ChaCha20Encryptor::encrypt(
    ByteView data, ByteView key, ByteView iv)
{
    auto validation = validate_params(key, iv);
    if (!validation) {
        return std::unexpected(validation.error());
    }

    if (data.empty()) {
        return ByteBuffer{};
    }

    return apply_keystream(data, key, iv);
}

MxResult<ByteBuffer> ChaCha20Encryptor::decrypt(
    ByteView data, ByteView key, ByteView iv)
{
    return encrypt(data, key, iv);
}

// ============================================================================
// Генерация ключа и nonce
// ============================================================================

std::array<uint8_t, ChaCha20Encryptor::KEY_BYTES> ChaCha20Encryptor::generate_key() {
    std::array<uint8_t, KEY_BYTES> key{};
    std::random_device rd;

    for (size_t i = 0; i < KEY_BYTES; i += 4) {
        const uint32_t val = rd();
        std::memcpy(key.data() + i, &val, sizeof(val));
    }

    return key;
}

std::array<uint8_t, ChaCha20Encryptor::NONCE_BYTES> ChaCha20Encryptor::generate_nonce() {
    std::array<uint8_t, NONCE_BYTES> nonce{};
    std::random_device rd;

    for (size_t i = 0; i < NONCE_BYTES; i += 4) {
        const uint32_t val = rd();
        const size_t to_copy = std::min(static_cast<size_t>(4), NONCE_BYTES - i);
        std::memcpy(nonce.data() + i, &val, to_copy);
    }

    return nonce;
}

} // namespace mx
