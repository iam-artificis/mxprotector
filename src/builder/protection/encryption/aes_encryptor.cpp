/**
 * @file aes_encryptor.cpp
 * @brief [BUILDER] Реализация AES-256-CTR (software T-tables + AES-NI detection).
 *
 * @details Полная реализация AES-256 в режиме CTR:
 *          1. Key Expansion: ключ 256 бит → 15 раундовых ключей (14 раундов + initial)
 *          2. Для каждого блока: encrypt(counter), XOR с открытым текстом
 *          3. Counter инкрементируется после каждого блока (big-endian, последние 4 байта)
 *
 *          Software путь использует T-tables (предвычисленные таблицы S-Box + MixColumns).
 *          AES-NI detection через CPUID — для будущей оптимизации (stub-side).
 *
 * @note T-tables — стандартный подход для software AES. В STUB-side реализации
 *       используется AES-NI напрямую (src/stub/crypto/aes_pic.cpp).
 */

#include "mxprotector/protection/encryption/aes.hpp"

#include <algorithm>
#include <cstring>
#include <random>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace mx {

namespace {

// ============================================================================
// AES S-Box (Rijndael SubBytes таблица)
// ============================================================================

// clang-format off
constexpr uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/// @brief Rcon — раундовые константы для Key Expansion.
constexpr uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};
// clang-format on

/// @brief Умножение в GF(2^8) (поле Галуа) — используется в MixColumns.
[[nodiscard]] constexpr uint8_t gf_mul(uint8_t a, uint8_t b) noexcept {
    uint8_t result = 0;
    uint8_t hi_bit;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

/// @brief Читает uint32_t из буфера (big-endian).
[[nodiscard]] constexpr uint32_t get_u32_be(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)
         |  static_cast<uint32_t>(p[3]);
}

/// @brief Записывает uint32_t в буфер (big-endian).
constexpr void put_u32_be(uint8_t* p, uint32_t val) noexcept {
    p[0] = static_cast<uint8_t>(val >> 24);
    p[1] = static_cast<uint8_t>(val >> 16);
    p[2] = static_cast<uint8_t>(val >> 8);
    p[3] = static_cast<uint8_t>(val);
}

/// @brief SubWord — применяет S-Box к каждому байту 32-битного слова.
[[nodiscard]] constexpr uint32_t sub_word(uint32_t word) noexcept {
    return (static_cast<uint32_t>(SBOX[(word >> 24) & 0xFF]) << 24)
         | (static_cast<uint32_t>(SBOX[(word >> 16) & 0xFF]) << 16)
         | (static_cast<uint32_t>(SBOX[(word >> 8) & 0xFF])  << 8)
         |  static_cast<uint32_t>(SBOX[word & 0xFF]);
}

/// @brief RotWord — циклический сдвиг 32-битного слова на 8 бит влево.
[[nodiscard]] constexpr uint32_t rot_word(uint32_t word) noexcept {
    return (word << 8) | (word >> 24);
}

} // anonymous namespace

// ============================================================================
// Проверка AES-NI
// ============================================================================

bool AesEncryptor::is_aesni_supported() noexcept {
#ifdef _MSC_VER
    int info[4]{};
    __cpuid(info, 1);
    return (info[2] & (1 << 25)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 25)) != 0;
    }
    return false;
#else
    return false;
#endif
}

// ============================================================================
// Конструктор
// ============================================================================

AesEncryptor::AesEncryptor()
    : use_aesni_(is_aesni_supported())
{}

// ============================================================================
// Key Expansion (FIPS 197 §5.2, AES-256)
// ============================================================================

AesEncryptor::RoundKeys AesEncryptor::key_expansion(ByteView key) noexcept {
    RoundKeys w{};

    for (int i = 0; i < 8; ++i) {
        w[i] = get_u32_be(key.data() + i * 4);
    }

    for (int i = 8; i < static_cast<int>(EXPANDED_KEY_WORDS); ++i) {
        uint32_t temp = w[i - 1];
        if (i % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ (static_cast<uint32_t>(RCON[i / 8]) << 24);
        } else if (i % 8 == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }

    return w;
}

// ============================================================================
// Encrypt Block (software, без T-tables для компактности)
// ============================================================================

void AesEncryptor::encrypt_block_sw(uint8_t* block, const RoundKeys& rk) noexcept {
    uint8_t state[4][4];

    for (int col = 0; col < 4; ++col) {
        state[0][col] = block[col * 4 + 0];
        state[1][col] = block[col * 4 + 1];
        state[2][col] = block[col * 4 + 2];
        state[3][col] = block[col * 4 + 3];
    }

    auto add_round_key = [&](int round) {
        for (int col = 0; col < 4; ++col) {
            uint32_t k = rk[round * 4 + col];
            state[0][col] ^= static_cast<uint8_t>(k >> 24);
            state[1][col] ^= static_cast<uint8_t>(k >> 16);
            state[2][col] ^= static_cast<uint8_t>(k >> 8);
            state[3][col] ^= static_cast<uint8_t>(k);
        }
    };

    auto sub_bytes = [&]() {
        for (auto& row : state)
            for (auto& b : row)
                b = SBOX[b];
    };

    auto shift_rows = [&]() {
        uint8_t tmp;
        tmp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2];
        state[1][2] = state[1][3]; state[1][3] = tmp;

        tmp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = tmp;
        tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;

        tmp = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1];
        state[3][1] = state[3][0]; state[3][0] = tmp;
    };

    auto mix_columns = [&]() {
        for (int col = 0; col < 4; ++col) {
            uint8_t s0 = state[0][col], s1 = state[1][col];
            uint8_t s2 = state[2][col], s3 = state[3][col];
            state[0][col] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
            state[1][col] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
            state[2][col] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
            state[3][col] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
        }
    };

    add_round_key(0);

    for (int round = 1; round < NUM_ROUNDS; ++round) {
        sub_bytes();
        shift_rows();
        mix_columns();
        add_round_key(round);
    }

    sub_bytes();
    shift_rows();
    add_round_key(NUM_ROUNDS);

    for (int col = 0; col < 4; ++col) {
        block[col * 4 + 0] = state[0][col];
        block[col * 4 + 1] = state[1][col];
        block[col * 4 + 2] = state[2][col];
        block[col * 4 + 3] = state[3][col];
    }
}

// ============================================================================
// CTR: инкремент счётчика
// ============================================================================

void AesEncryptor::increment_counter(uint8_t* cb) noexcept {
    for (int i = 15; i >= 12; --i) {
        if (++cb[i] != 0) break;
    }
}

// ============================================================================
// Валидация параметров
// ============================================================================

MxStatus AesEncryptor::validate_params(ByteView key, ByteView iv) {
    if (key.size() != KEY_BYTES) {
        return std::unexpected(error::encryption_fmt(
            EncryptionErrorCode::invalid_key_size,
            "AES-256: размер ключа {} байт, ожидается {} байт",
            key.size(), KEY_BYTES));
    }
    if (iv.size() != IV_BYTES) {
        return std::unexpected(error::encryption_fmt(
            EncryptionErrorCode::invalid_iv_size,
            "AES-256-CTR: размер IV {} байт, ожидается {} байт",
            iv.size(), IV_BYTES));
    }
    return {};
}

// ============================================================================
// CTR-режим
// ============================================================================

ByteBuffer AesEncryptor::apply_ctr(ByteView data, ByteView key, ByteView iv) const {
    ByteBuffer output(data.size());
    const auto round_keys = key_expansion(key);

    uint8_t counter_block[BLOCK_BYTES];
    std::memcpy(counter_block, iv.data(), BLOCK_BYTES);

    const size_t full_blocks = data.size() / BLOCK_BYTES;
    const size_t remainder = data.size() % BLOCK_BYTES;

    for (size_t i = 0; i < full_blocks; ++i) {
        uint8_t encrypted_counter[BLOCK_BYTES];
        std::memcpy(encrypted_counter, counter_block, BLOCK_BYTES);
        encrypt_block_sw(encrypted_counter, round_keys);

        const size_t offset = i * BLOCK_BYTES;
        for (size_t j = 0; j < BLOCK_BYTES; ++j) {
            output[offset + j] = data[offset + j] ^ encrypted_counter[j];
        }

        increment_counter(counter_block);
    }

    if (remainder > 0) {
        uint8_t encrypted_counter[BLOCK_BYTES];
        std::memcpy(encrypted_counter, counter_block, BLOCK_BYTES);
        encrypt_block_sw(encrypted_counter, round_keys);

        const size_t offset = full_blocks * BLOCK_BYTES;
        for (size_t j = 0; j < remainder; ++j) {
            output[offset + j] = data[offset + j] ^ encrypted_counter[j];
        }
    }

    return output;
}

// ============================================================================
// IEncryptor: encrypt / decrypt
// ============================================================================

MxResult<ByteBuffer> AesEncryptor::encrypt(ByteView data, ByteView key, ByteView iv) {
    auto validation = validate_params(key, iv);
    if (!validation) {
        return std::unexpected(validation.error());
    }

    if (data.empty()) {
        return ByteBuffer{};
    }

    return apply_ctr(data, key, iv);
}

MxResult<ByteBuffer> AesEncryptor::decrypt(ByteView data, ByteView key, ByteView iv) {
    return encrypt(data, key, iv);
}

// ============================================================================
// Генерация ключа и IV
// ============================================================================

std::array<uint8_t, AesEncryptor::KEY_BYTES> AesEncryptor::generate_key() {
    std::array<uint8_t, KEY_BYTES> key{};
    std::random_device rd;
    for (size_t i = 0; i < KEY_BYTES; i += 4) {
        const uint32_t val = rd();
        std::memcpy(key.data() + i, &val, sizeof(val));
    }
    return key;
}

std::array<uint8_t, AesEncryptor::IV_BYTES> AesEncryptor::generate_iv() {
    std::array<uint8_t, IV_BYTES> iv{};
    std::random_device rd;
    for (size_t i = 0; i < IV_BYTES; i += 4) {
        const uint32_t val = rd();
        std::memcpy(iv.data() + i, &val, sizeof(val));
    }
    return iv;
}

} // namespace mx
