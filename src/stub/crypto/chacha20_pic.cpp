/**
 * @file chacha20_pic.cpp
 * @brief [STUB] PIC-реализация ChaCha20 (RFC 7539) без CRT/STL.
 *
 * @details Полная позиционно-независимая реализация ChaCha20 для STUB.
 *          Идентична по алгоритму builder-side реализации, но:
 *          - Нет зависимостей от CRT/STL
 *          - Все функции inline для PIC-совместимости
 *          - Работает с сырыми указателями вместо std::span/vector
 *          - Нет аллокаций (расшифровка in-place)
 *
 * @note Этот код компилируется с /GS- /NODEFAULTLIB и линкуется
 *       как часть STUB shellcode. Никаких глобальных переменных.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"

namespace mx::stub::pic {

namespace {

/// @brief Циклический сдвиг влево 32-бит.
[[nodiscard]] constexpr uint32_t rotl32(uint32_t v, unsigned int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

/// @brief Little-endian чтение uint32_t.
[[nodiscard]] constexpr uint32_t le_to_u32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

/// @brief Little-endian запись uint32_t.
constexpr void u32_to_le(uint8_t* out, uint32_t v) noexcept {
    out[0] = static_cast<uint8_t>(v);
    out[1] = static_cast<uint8_t>(v >> 8);
    out[2] = static_cast<uint8_t>(v >> 16);
    out[3] = static_cast<uint8_t>(v >> 24);
}

/// @brief Quarter-round: ARX-операция ChaCha20.
constexpr void quarter_round(
    uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept
{
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

} // anonymous namespace

/**
 * @brief Расшифровывает буфер in-place алгоритмом ChaCha20.
 *
 * @param data      Указатель на зашифрованные данные (модифицируется).
 * @param data_size Размер данных в байтах.
 * @param key       Ключ (32 байта).
 * @param nonce     Nonce (12 байт).
 *
 * @note In-place расшифровка: XOR с keystream. Не требует дополнительной памяти.
 *       Полностью PIC — нет глобальных данных, нет CRT-вызовов.
 */
void chacha20_decrypt_inplace(
    uint8_t*       data,
    uint32_t       data_size,
    const uint8_t* key,
    const uint8_t* nonce) noexcept
{
    constexpr uint32_t BLOCK_SIZE = 64;

    constexpr uint32_t CONST_0 = 0x61707865;
    constexpr uint32_t CONST_1 = 0x3320646E;
    constexpr uint32_t CONST_2 = 0x79622D32;
    constexpr uint32_t CONST_3 = 0x6B206574;

    uint32_t key_words[8];
    for (int i = 0; i < 8; ++i) {
        key_words[i] = le_to_u32(key + i * 4);
    }

    uint32_t nonce_words[3];
    for (int i = 0; i < 3; ++i) {
        nonce_words[i] = le_to_u32(nonce + i * 4);
    }

    const uint32_t total_blocks = (data_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint32_t block_idx = 0; block_idx < total_blocks; ++block_idx) {
        uint32_t state[16] = {
            CONST_0,        CONST_1,        CONST_2,        CONST_3,
            key_words[0],   key_words[1],   key_words[2],   key_words[3],
            key_words[4],   key_words[5],   key_words[6],   key_words[7],
            block_idx + 1,  nonce_words[0], nonce_words[1], nonce_words[2]
        };

        uint32_t working[16];
        for (int i = 0; i < 16; ++i) working[i] = state[i];

        for (int round = 0; round < 10; ++round) {
            quarter_round(working[0], working[4], working[8],  working[12]);
            quarter_round(working[1], working[5], working[9],  working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);

            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8],  working[13]);
            quarter_round(working[3], working[4], working[9],  working[14]);
        }

        for (int i = 0; i < 16; ++i) working[i] += state[i];

        uint8_t keystream[BLOCK_SIZE];
        for (int i = 0; i < 16; ++i) {
            u32_to_le(keystream + i * 4, working[i]);
        }

        const uint32_t offset = block_idx * BLOCK_SIZE;
        uint32_t chunk_size = BLOCK_SIZE;
        if (offset + chunk_size > data_size) {
            chunk_size = data_size - offset;
        }

        for (uint32_t i = 0; i < chunk_size; ++i) {
            data[offset + i] ^= keystream[i];
        }
    }
}

} // namespace mx::stub::pic
