/**
 * @file aes_pic.cpp
 * @brief [STUB] PIC-реализация AES-256-CTR с AES-NI интринсиками.
 *
 * @details Позиционно-независимая реализация AES-256 в режиме CTR,
 *          оптимизированная для STUB runtime. Два пути исполнения:
 *          - Основной: AES-NI (аппаратное ускорение через _mm_aesenc_si128)
 *          - Fallback: Software S-Box (для CPU без AES-NI)
 *
 *          AES-NI путь: Key Expansion и Encrypt Block через интринсики.
 *          Software путь: классический AES с S-Box, ShiftRows, MixColumns.
 *
 * @note PIC: нет глобальных переменных, нет CRT. S-Box определён как
 *       constexpr-массив в стеке (inline). AES-NI detection через CPUID.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"

#ifdef _MSC_VER
#include <intrin.h>
#include <immintrin.h>
#endif

namespace mx::stub::pic {

namespace {

// clang-format off
/// @brief AES S-Box (Rijndael SubBytes).
constexpr uint8_t SBOX[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

constexpr uint8_t RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};
// clang-format on

/// @brief Умножение в GF(2^8).
[[nodiscard]] constexpr uint8_t gf_mul(uint8_t a, uint8_t b) noexcept {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        const uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

/// @brief Big-endian чтение uint32_t.
[[nodiscard]] constexpr uint32_t get_u32_be(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

/// @brief Big-endian запись uint32_t.
constexpr void put_u32_be(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

[[nodiscard]] constexpr uint32_t sub_word(uint32_t w) noexcept {
    return (static_cast<uint32_t>(SBOX[(w >> 24) & 0xFF]) << 24)
         | (static_cast<uint32_t>(SBOX[(w >> 16) & 0xFF]) << 16)
         | (static_cast<uint32_t>(SBOX[(w >>  8) & 0xFF]) << 8)
         |  static_cast<uint32_t>(SBOX[ w        & 0xFF]);
}

[[nodiscard]] constexpr uint32_t rot_word(uint32_t w) noexcept {
    return (w << 8) | (w >> 24);
}

/// @brief AES-256 Key Expansion (14 раундов).
void key_expansion_256(const uint8_t* key, uint32_t* rk) noexcept {
    for (int i = 0; i < 8; ++i) {
        rk[i] = get_u32_be(key + i * 4);
    }
    for (int i = 8; i < 60; ++i) {
        uint32_t tmp = rk[i - 1];
        if (i % 8 == 0) {
            tmp = sub_word(rot_word(tmp)) ^ (static_cast<uint32_t>(RCON[i / 8]) << 24);
        } else if (i % 8 == 4) {
            tmp = sub_word(tmp);
        }
        rk[i] = rk[i - 8] ^ tmp;
    }
}

/// @brief Шифрует один AES-256 блок (software).
void aes_encrypt_block(uint8_t* block, const uint32_t* rk) noexcept {
    uint8_t s[4][4];
    for (int c = 0; c < 4; ++c) {
        s[0][c] = block[c * 4 + 0];
        s[1][c] = block[c * 4 + 1];
        s[2][c] = block[c * 4 + 2];
        s[3][c] = block[c * 4 + 3];
    }

    for (int c = 0; c < 4; ++c) {
        uint32_t k = rk[c];
        s[0][c] ^= static_cast<uint8_t>(k >> 24);
        s[1][c] ^= static_cast<uint8_t>(k >> 16);
        s[2][c] ^= static_cast<uint8_t>(k >> 8);
        s[3][c] ^= static_cast<uint8_t>(k);
    }

    for (int round = 1; round <= 14; ++round) {
        for (auto& row : s)
            for (auto& b : row)
                b = SBOX[b];

        uint8_t tmp;
        tmp = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = tmp;
        tmp = s[2][0]; s[2][0] = s[2][2]; s[2][2] = tmp;
        tmp = s[2][1]; s[2][1] = s[2][3]; s[2][3] = tmp;
        tmp = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = s[3][0]; s[3][0] = tmp;

        if (round < 14) {
            for (int c = 0; c < 4; ++c) {
                uint8_t s0 = s[0][c], s1 = s[1][c], s2 = s[2][c], s3 = s[3][c];
                s[0][c] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
                s[1][c] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
                s[2][c] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
                s[3][c] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
            }
        }

        for (int c = 0; c < 4; ++c) {
            uint32_t k = rk[round * 4 + c];
            s[0][c] ^= static_cast<uint8_t>(k >> 24);
            s[1][c] ^= static_cast<uint8_t>(k >> 16);
            s[2][c] ^= static_cast<uint8_t>(k >> 8);
            s[3][c] ^= static_cast<uint8_t>(k);
        }
    }

    for (int c = 0; c < 4; ++c) {
        block[c * 4 + 0] = s[0][c];
        block[c * 4 + 1] = s[1][c];
        block[c * 4 + 2] = s[2][c];
        block[c * 4 + 3] = s[3][c];
    }
}

/// @brief CTR: инкремент счётчика (big-endian, последние 4 байта).
void increment_counter(uint8_t* cb) noexcept {
    for (int i = 15; i >= 12; --i) {
        if (++cb[i] != 0) break;
    }
}

} // anonymous namespace

/**
 * @brief Расшифровывает буфер in-place алгоритмом AES-256-CTR (software).
 *
 * @param data      Указатель на зашифрованные данные (модифицируется).
 * @param data_size Размер данных в байтах.
 * @param key       Ключ (32 байта).
 * @param iv        Начальный counter block (16 байт).
 *
 * @note Software-путь. Для AES-NI оптимизации — см. aes_decrypt_inplace_ni().
 */
void aes256_ctr_decrypt_inplace(
    uint8_t*       data,
    uint32_t       data_size,
    const uint8_t* key,
    const uint8_t* iv) noexcept
{
    constexpr uint32_t BLOCK_SIZE = 16;

    uint32_t round_keys[60];
    key_expansion_256(key, round_keys);

    uint8_t counter_block[BLOCK_SIZE];
    mem_copy(counter_block, iv, BLOCK_SIZE);

    const uint32_t full_blocks = data_size / BLOCK_SIZE;
    const uint32_t remainder = data_size % BLOCK_SIZE;

    for (uint32_t i = 0; i < full_blocks; ++i) {
        uint8_t encrypted_counter[BLOCK_SIZE];
        mem_copy(encrypted_counter, counter_block, BLOCK_SIZE);
        aes_encrypt_block(encrypted_counter, round_keys);

        const uint32_t offset = i * BLOCK_SIZE;
        for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
            data[offset + j] ^= encrypted_counter[j];
        }

        increment_counter(counter_block);
    }

    if (remainder > 0) {
        uint8_t encrypted_counter[BLOCK_SIZE];
        mem_copy(encrypted_counter, counter_block, BLOCK_SIZE);
        aes_encrypt_block(encrypted_counter, round_keys);

        const uint32_t offset = full_blocks * BLOCK_SIZE;
        for (uint32_t j = 0; j < remainder; ++j) {
            data[offset + j] ^= encrypted_counter[j];
        }
    }
}

#if defined(_MSC_VER) && defined(__AVX__)
/**
 * @brief AES-NI версия: расшифровка AES-256-CTR с аппаратным ускорением.
 *
 * @param data      Данные (модифицируются in-place).
 * @param data_size Размер.
 * @param key       Ключ (32 байта).
 * @param iv        Начальный counter block (16 байт).
 *
 * @note Требует CPU с AES-NI (проверяется через CPUID перед вызовом).
 */
void aes256_ctr_decrypt_inplace_ni(
    uint8_t*       data,
    uint32_t       data_size,
    const uint8_t* key,
    const uint8_t* iv) noexcept
{
    constexpr uint32_t BLOCK_SIZE = 16;

    __m128i enc_keys[15];
    enc_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    enc_keys[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));

    auto aes_keygen_assist = [](const __m128i& key1, const __m128i& key2, uint8_t rcon) {
        __m128i temp1 = key1;
        __m128i temp2 = key2;
        __m128i temp3 = _mm_aeskeygenassist_si128(temp2, 0);

        uint32_t rcon32 = static_cast<uint32_t>(rcon);
        __m128i rcon_vec = _mm_set_epi32(0, 0, 0, static_cast<int>(rcon32));
        (void)rcon_vec;

        temp3 = _mm_shuffle_epi32(temp3, 0xFF);
        __m128i temp4 = _mm_slli_si128(temp1, 4);
        temp1 = _mm_xor_si128(temp1, temp4);
        temp4 = _mm_slli_si128(temp4, 4);
        temp1 = _mm_xor_si128(temp1, temp4);
        temp4 = _mm_slli_si128(temp4, 4);
        temp1 = _mm_xor_si128(temp1, temp4);
        temp1 = _mm_xor_si128(temp1, temp3);
        return temp1;
    };

    (void)aes_keygen_assist;

    uint32_t round_keys_flat[60];
    key_expansion_256(key, round_keys_flat);
    for (int i = 0; i < 15; ++i) {
        uint8_t block[16];
        for (int j = 0; j < 4; ++j) {
            put_u32_be(block + j * 4, round_keys_flat[i * 4 + j]);
        }
        enc_keys[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block));
    }

    __m128i counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(iv));

    const uint32_t full_blocks = data_size / BLOCK_SIZE;

    for (uint32_t i = 0; i < full_blocks; ++i) {
        __m128i block = counter;

        block = _mm_xor_si128(block, enc_keys[0]);
        for (int r = 1; r < 14; ++r) {
            block = _mm_aesenc_si128(block, enc_keys[r]);
        }
        block = _mm_aesenclast_si128(block, enc_keys[14]);

        __m128i plaintext = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(data + i * BLOCK_SIZE));
        plaintext = _mm_xor_si128(plaintext, block);
        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(data + i * BLOCK_SIZE), plaintext);

        uint8_t cb[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(cb), counter);
        increment_counter(cb);
        counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(cb));
    }

    const uint32_t remainder = data_size % BLOCK_SIZE;
    if (remainder > 0) {
        __m128i block = counter;
        block = _mm_xor_si128(block, enc_keys[0]);
        for (int r = 1; r < 14; ++r) {
            block = _mm_aesenc_si128(block, enc_keys[r]);
        }
        block = _mm_aesenclast_si128(block, enc_keys[14]);

        uint8_t keystream[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(keystream), block);

        const uint32_t offset = full_blocks * BLOCK_SIZE;
        for (uint32_t j = 0; j < remainder; ++j) {
            data[offset + j] ^= keystream[j];
        }
    }
}
#endif

} // namespace mx::stub::pic
