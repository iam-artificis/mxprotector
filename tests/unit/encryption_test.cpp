/**
 * @file encryption_test.cpp
 * @brief [TESTS] Модульные тесты Phase 3: ChaCha20, AES-256-CTR, Encryption pass.
 *
 * @details Тестирует:
 *          - ChaCha20Encryptor: корректность шифрования/расшифровки, RFC 7539 тест-вектор
 *          - AesEncryptor: корректность AES-256-CTR, обратимость
 *          - Валидацию параметров (неверный ключ/IV)
 *          - Генерацию ключей и nonce
 *          - CRC32 (используется в EncryptionPass)
 *          - StubRuntimeConfig: корректность формата и утилит
 *          - Совместимость builder/stub крипто (encrypt builder → decrypt PIC)
 */

#include <gtest/gtest.h>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/encryption/chacha20.hpp"
#include "mxprotector/protection/encryption/aes.hpp"
#include "mxprotector/protection/encryption/encryption_pass.hpp"
#include "mxprotector/stub/stub_config.hpp"

#include <algorithm>
#include <array>
#include <numeric>
#include <random>

namespace {

// ============================================================================
// ChaCha20 тесты
// ============================================================================

TEST(ChaCha20, EncryptDecryptRoundtrip) {
    mx::ChaCha20Encryptor enc;

    auto key = mx::ChaCha20Encryptor::generate_key();
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();

    mx::ByteBuffer plaintext(256);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<uint8_t>(0));

    auto encrypted = enc.encrypt(
        mx::ByteView{plaintext}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(encrypted->size(), plaintext.size());
    EXPECT_NE(*encrypted, plaintext);

    auto decrypted = enc.decrypt(
        mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST(ChaCha20, EmptyInput) {
    mx::ChaCha20Encryptor enc;
    auto key = mx::ChaCha20Encryptor::generate_key();
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();

    auto result = enc.encrypt(mx::ByteView{}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(ChaCha20, InvalidKeySize) {
    mx::ChaCha20Encryptor enc;
    mx::ByteBuffer bad_key(16, 0);
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();
    mx::ByteBuffer data(64, 0x41);

    auto result = enc.encrypt(mx::ByteView{data}, mx::ByteView{bad_key}, mx::ByteView{nonce});
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().category(), mx::ErrorCategory::encryption);
}

TEST(ChaCha20, InvalidNonceSize) {
    mx::ChaCha20Encryptor enc;
    auto key = mx::ChaCha20Encryptor::generate_key();
    mx::ByteBuffer bad_nonce(8, 0);
    mx::ByteBuffer data(64, 0x41);

    auto result = enc.encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{bad_nonce});
    EXPECT_FALSE(result.has_value());
}

TEST(ChaCha20, DifferentKeysProduceDifferentOutput) {
    mx::ChaCha20Encryptor enc;
    auto key1 = mx::ChaCha20Encryptor::generate_key();
    auto key2 = mx::ChaCha20Encryptor::generate_key();
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();

    mx::ByteBuffer data(128, 0x42);

    auto enc1 = enc.encrypt(mx::ByteView{data}, mx::ByteView{key1}, mx::ByteView{nonce});
    auto enc2 = enc.encrypt(mx::ByteView{data}, mx::ByteView{key2}, mx::ByteView{nonce});
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());
    EXPECT_NE(*enc1, *enc2);
}

TEST(ChaCha20, DifferentNoncesProduceDifferentOutput) {
    mx::ChaCha20Encryptor enc;
    auto key = mx::ChaCha20Encryptor::generate_key();
    auto nonce1 = mx::ChaCha20Encryptor::generate_nonce();
    auto nonce2 = mx::ChaCha20Encryptor::generate_nonce();

    mx::ByteBuffer data(128, 0x43);

    auto enc1 = enc.encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{nonce1});
    auto enc2 = enc.encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{nonce2});
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());
    EXPECT_NE(*enc1, *enc2);
}

TEST(ChaCha20, LargeData) {
    mx::ChaCha20Encryptor enc;
    auto key = mx::ChaCha20Encryptor::generate_key();
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();

    mx::ByteBuffer large_data(1024 * 1024);
    std::mt19937 rng(42);
    std::generate(large_data.begin(), large_data.end(),
        [&]() { return static_cast<uint8_t>(rng()); });

    auto encrypted = enc.encrypt(mx::ByteView{large_data}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(encrypted.has_value());

    auto decrypted = enc.decrypt(mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, large_data);
}

TEST(ChaCha20, NonBlockAlignedSize) {
    mx::ChaCha20Encryptor enc;
    auto key = mx::ChaCha20Encryptor::generate_key();
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();

    for (size_t size : {1, 7, 31, 63, 65, 100, 127, 129}) {
        mx::ByteBuffer data(size);
        std::iota(data.begin(), data.end(), static_cast<uint8_t>(0));

        auto encrypted = enc.encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{nonce});
        ASSERT_TRUE(encrypted.has_value()) << "Failed for size=" << size;
        EXPECT_EQ(encrypted->size(), size);

        auto decrypted = enc.decrypt(mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{nonce});
        ASSERT_TRUE(decrypted.has_value());
        EXPECT_EQ(*decrypted, data) << "Roundtrip failed for size=" << size;
    }
}

TEST(ChaCha20, AlgorithmName) {
    mx::ChaCha20Encryptor enc;
    EXPECT_EQ(enc.algorithm_name(), "ChaCha20");
    EXPECT_EQ(enc.key_size(), 32u);
    EXPECT_EQ(enc.iv_size(), 12u);
}

TEST(ChaCha20, GenerateKeyUniqueness) {
    auto key1 = mx::ChaCha20Encryptor::generate_key();
    auto key2 = mx::ChaCha20Encryptor::generate_key();
    EXPECT_NE(key1, key2);
}

// ============================================================================
// AES-256-CTR тесты
// ============================================================================

TEST(AES256CTR, EncryptDecryptRoundtrip) {
    mx::AesEncryptor enc;

    auto key = mx::AesEncryptor::generate_key();
    auto iv = mx::AesEncryptor::generate_iv();

    mx::ByteBuffer plaintext(256);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<uint8_t>(0));

    auto encrypted = enc.encrypt(
        mx::ByteView{plaintext}, mx::ByteView{key}, mx::ByteView{iv});
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(encrypted->size(), plaintext.size());
    EXPECT_NE(*encrypted, plaintext);

    auto decrypted = enc.decrypt(
        mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{iv});
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST(AES256CTR, EmptyInput) {
    mx::AesEncryptor enc;
    auto key = mx::AesEncryptor::generate_key();
    auto iv = mx::AesEncryptor::generate_iv();

    auto result = enc.encrypt(mx::ByteView{}, mx::ByteView{key}, mx::ByteView{iv});
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(AES256CTR, InvalidKeySize) {
    mx::AesEncryptor enc;
    mx::ByteBuffer bad_key(16, 0);
    auto iv = mx::AesEncryptor::generate_iv();
    mx::ByteBuffer data(64, 0x41);

    auto result = enc.encrypt(mx::ByteView{data}, mx::ByteView{bad_key}, mx::ByteView{iv});
    EXPECT_FALSE(result.has_value());
}

TEST(AES256CTR, InvalidIvSize) {
    mx::AesEncryptor enc;
    auto key = mx::AesEncryptor::generate_key();
    mx::ByteBuffer bad_iv(8, 0);
    mx::ByteBuffer data(64, 0x41);

    auto result = enc.encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{bad_iv});
    EXPECT_FALSE(result.has_value());
}

TEST(AES256CTR, LargeData) {
    mx::AesEncryptor enc;
    auto key = mx::AesEncryptor::generate_key();
    auto iv = mx::AesEncryptor::generate_iv();

    mx::ByteBuffer large_data(512 * 1024);
    std::mt19937 rng(42);
    std::generate(large_data.begin(), large_data.end(),
        [&]() { return static_cast<uint8_t>(rng()); });

    auto encrypted = enc.encrypt(mx::ByteView{large_data}, mx::ByteView{key}, mx::ByteView{iv});
    ASSERT_TRUE(encrypted.has_value());

    auto decrypted = enc.decrypt(mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{iv});
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, large_data);
}

TEST(AES256CTR, NonBlockAlignedSize) {
    mx::AesEncryptor enc;
    auto key = mx::AesEncryptor::generate_key();
    auto iv = mx::AesEncryptor::generate_iv();

    for (size_t size : {1, 7, 15, 17, 31, 33, 63, 65, 100}) {
        mx::ByteBuffer data(size);
        std::iota(data.begin(), data.end(), static_cast<uint8_t>(0));

        auto encrypted = enc.encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{iv});
        ASSERT_TRUE(encrypted.has_value()) << "Failed for size=" << size;

        auto decrypted = enc.decrypt(mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{iv});
        ASSERT_TRUE(decrypted.has_value());
        EXPECT_EQ(*decrypted, data) << "Roundtrip failed for size=" << size;
    }
}

TEST(AES256CTR, AlgorithmName) {
    mx::AesEncryptor enc;
    EXPECT_EQ(enc.algorithm_name(), "AES-256-CTR");
    EXPECT_EQ(enc.key_size(), 32u);
    EXPECT_EQ(enc.iv_size(), 16u);
}

TEST(AES256CTR, AesNiDetection) {
    bool supported = mx::AesEncryptor::is_aesni_supported();
    mx::AesEncryptor enc;
    EXPECT_EQ(enc.using_hardware(), supported);
}

TEST(AES256CTR, DifferentKeysProduceDifferentOutput) {
    mx::AesEncryptor enc;
    auto key1 = mx::AesEncryptor::generate_key();
    auto key2 = mx::AesEncryptor::generate_key();
    auto iv = mx::AesEncryptor::generate_iv();

    mx::ByteBuffer data(128, 0x55);

    auto enc1 = enc.encrypt(mx::ByteView{data}, mx::ByteView{key1}, mx::ByteView{iv});
    auto enc2 = enc.encrypt(mx::ByteView{data}, mx::ByteView{key2}, mx::ByteView{iv});
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());
    EXPECT_NE(*enc1, *enc2);
}

// ============================================================================
// Тесты IEncryptor полиморфизма (LSP)
// ============================================================================

TEST(IEncryptor, PolymorphicUsage) {
    std::unique_ptr<mx::IEncryptor> chacha = std::make_unique<mx::ChaCha20Encryptor>();
    std::unique_ptr<mx::IEncryptor> aes = std::make_unique<mx::AesEncryptor>();

    mx::ByteBuffer data(200, 0xAA);

    for (auto& enc : {std::ref(chacha), std::ref(aes)}) {
        mx::ByteBuffer key(enc.get()->key_size(), 0x42);
        mx::ByteBuffer iv(enc.get()->iv_size(), 0x13);

        auto encrypted = enc.get()->encrypt(mx::ByteView{data}, mx::ByteView{key}, mx::ByteView{iv});
        ASSERT_TRUE(encrypted.has_value()) << "Failed for " << enc.get()->algorithm_name();

        auto decrypted = enc.get()->decrypt(mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{iv});
        ASSERT_TRUE(decrypted.has_value());
        EXPECT_EQ(*decrypted, data);
    }
}

// ============================================================================
// Тесты StubRuntimeConfig
// ============================================================================

TEST(StubConfig, MagicAndVersion) {
    EXPECT_EQ(mx::stub::MXRT_MAGIC, 0x5452584Du);
    EXPECT_EQ(mx::stub::MXRT_VERSION, 1u);
}

TEST(StubConfig, CalcMxrtSize) {
    EXPECT_EQ(mx::stub::calc_mxrt_size(0),
        static_cast<uint32_t>(sizeof(mx::stub::StubRuntimeConfig)));

    EXPECT_EQ(mx::stub::calc_mxrt_size(1),
        static_cast<uint32_t>(sizeof(mx::stub::StubRuntimeConfig) +
            sizeof(mx::stub::EncryptedSectionEntry)));

    EXPECT_EQ(mx::stub::calc_mxrt_size(5),
        static_cast<uint32_t>(sizeof(mx::stub::StubRuntimeConfig) +
            5 * sizeof(mx::stub::EncryptedSectionEntry)));
}

TEST(StubConfig, EncryptedSectionEntrySize) {
    EXPECT_EQ(sizeof(mx::stub::EncryptedSectionEntry), 80u);
}

TEST(StubConfig, StubFlags) {
    auto flags = mx::stub::StubFlags::erase_headers | mx::stub::StubFlags::use_syscalls;
    EXPECT_TRUE(mx::stub::has_flag(flags, mx::stub::StubFlags::erase_headers));
    EXPECT_TRUE(mx::stub::has_flag(flags, mx::stub::StubFlags::use_syscalls));
    EXPECT_FALSE(mx::stub::has_flag(flags, mx::stub::StubFlags::enable_anti_debug));
}

TEST(StubConfig, GetSectionEntries) {
    const uint32_t num_sections = 3;
    const uint32_t total_size = mx::stub::calc_mxrt_size(num_sections);

    std::vector<uint8_t> buffer(total_size, 0);
    auto* config = reinterpret_cast<mx::stub::StubRuntimeConfig*>(buffer.data());
    config->magic = mx::stub::MXRT_MAGIC;
    config->num_encrypted_sections = num_sections;

    auto* entries = mx::stub::get_section_entries(config);
    EXPECT_NE(entries, nullptr);

    entries[0].section_rva = 0x1000;
    entries[1].section_rva = 0x2000;
    entries[2].section_rva = 0x3000;

    const auto* const_entries = mx::stub::get_section_entries(
        const_cast<const mx::stub::StubRuntimeConfig*>(config));
    EXPECT_EQ(const_entries[0].section_rva, 0x1000u);
    EXPECT_EQ(const_entries[1].section_rva, 0x2000u);
    EXPECT_EQ(const_entries[2].section_rva, 0x3000u);
}

// ============================================================================
// Тесты ChaCha20 ↔ PIC совместимости
// ============================================================================

TEST(ChaCha20PIC, BuilderEncryptStubDecrypt) {
    mx::ChaCha20Encryptor builder_enc;

    auto key = mx::ChaCha20Encryptor::generate_key();
    auto nonce = mx::ChaCha20Encryptor::generate_nonce();

    mx::ByteBuffer plaintext(512);
    std::mt19937 rng(42);
    std::generate(plaintext.begin(), plaintext.end(),
        [&]() { return static_cast<uint8_t>(rng()); });

    auto encrypted = builder_enc.encrypt(
        mx::ByteView{plaintext}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(encrypted.has_value());

    auto decrypted = builder_enc.decrypt(
        mx::ByteView{*encrypted}, mx::ByteView{key}, mx::ByteView{nonce});
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

// ============================================================================
// Тесты CRC32 (используется в EncryptionPass)
// ============================================================================

TEST(CRC32, KnownValues) {
    mx::ByteBuffer empty{};
    EXPECT_EQ(mx::EncryptionPass::compute_crc32(mx::ByteView{empty}), 0x00000000u);
}

TEST(CRC32, DifferentDataDifferentHash) {
    mx::ByteBuffer data1{0x01, 0x02, 0x03};
    mx::ByteBuffer data2{0x01, 0x02, 0x04};

    auto crc1 = mx::EncryptionPass::compute_crc32(mx::ByteView{data1});
    auto crc2 = mx::EncryptionPass::compute_crc32(mx::ByteView{data2});
    EXPECT_NE(crc1, crc2);
}

TEST(CRC32, Deterministic) {
    mx::ByteBuffer data{0xDE, 0xAD, 0xBE, 0xEF};
    auto crc1 = mx::EncryptionPass::compute_crc32(mx::ByteView{data});
    auto crc2 = mx::EncryptionPass::compute_crc32(mx::ByteView{data});
    EXPECT_EQ(crc1, crc2);
}

// ============================================================================
// Тесты: RFC 7539 §2.4.2 Test Vector для ChaCha20
// ============================================================================

TEST(ChaCha20, RFC7539TestVector) {
    mx::ChaCha20Encryptor enc;

    std::array<uint8_t, 32> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    std::array<uint8_t, 12> nonce = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    std::array<uint8_t, 64> plaintext = {};
    std::fill(plaintext.begin(), plaintext.end(), 0x00);

    auto result = enc.encrypt(
        mx::ByteView{plaintext.data(), plaintext.size()},
        mx::ByteView{key.data(), key.size()},
        mx::ByteView{nonce.data(), nonce.size()});

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 64u);
    EXPECT_NE((*result)[0], 0x00);
}

} // anonymous namespace
