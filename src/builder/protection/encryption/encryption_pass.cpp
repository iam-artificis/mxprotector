/**
 * @file encryption_pass.cpp
 * @brief [BUILDER] Реализация прохода шифрования секций PE.
 *
 * @details Алгоритм работы EncryptionPass:
 *          1. Обход всех секций PE: фильтрация подходящих для шифрования
 *          2. Для каждой секции:
 *             a. Генерация уникального ключа и IV
 *             b. Вычисление CRC32 оригинальных данных
 *             c. Шифрование данных секции (ChaCha20 или AES-256-CTR)
 *             d. Замена данных секции зашифрованными
 *             e. Снятие флага EXECUTE с секции (защита от запуска до расшифровки)
 *             f. Формирование EncryptedSectionEntry
 *          3. Сборка StubRuntimeConfig с метаданными
 *          4. Добавление секции .mxrt в PE
 *          5. Сохранение оригинального entry point для STUB
 *
 * @note Секции .reloc, .rsrc, .pdata, .edata и .mxrt НЕ шифруются.
 *       Мастер-ключ XOR-ится с секционными ключами для дополнительной защиты.
 */

#include "mxprotector/protection/encryption/encryption_pass.hpp"
#include "mxprotector/protection/encryption/chacha20.hpp"
#include "mxprotector/protection/encryption/aes.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <random>

namespace mx {

// ============================================================================
// CRC32 (ISO 3309 polynomial 0xEDB88320)
// ============================================================================

uint32_t EncryptionPass::compute_crc32(ByteView data) noexcept {
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

// ============================================================================
// Фильтрация секций
// ============================================================================

bool EncryptionPass::should_encrypt_section(const pe::SectionInfo& section) noexcept {
    if (section.data.empty()) return false;
    if (section.virtual_size == 0) return false;

    if (section.name == ".reloc" || section.name == ".rsrc" ||
        section.name == ".pdata" || section.name == ".edata" ||
        section.name == ".mxrt"  || section.name == ".debug" ||
        section.name == ".CRT"   || section.name == ".tls")
    {
        return false;
    }

    const bool has_code = (section.characteristics & pe::IMAGE_SCN_CNT_CODE) != 0;
    const bool has_data = (section.characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
    const bool is_executable = (section.characteristics & pe::IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool is_readable = (section.characteristics & pe::IMAGE_SCN_MEM_READ) != 0;

    return (has_code || has_data) && (is_executable || is_readable);
}

// ============================================================================
// Фабрика encryptor
// ============================================================================

std::unique_ptr<IEncryptor> EncryptionPass::create_encryptor(
    const ProtectionContext& ctx)
{
    if (ctx.config().prefer_aes && AesEncryptor::is_aesni_supported()) {
        return std::make_unique<AesEncryptor>();
    }
    return std::make_unique<ChaCha20Encryptor>();
}

// ============================================================================
// Проверка применимости
// ============================================================================

bool EncryptionPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    return ctx.config().enable_encryption;
}

// ============================================================================
// Сборка секции .mxrt
// ============================================================================

ByteBuffer EncryptionPass::build_mxrt_section(
    const ProtectionContext& ctx,
    const std::vector<stub::EncryptedSectionEntry>& entries)
{
    const uint32_t config_size = stub::calc_mxrt_size(
        static_cast<uint32_t>(entries.size()));

    ByteBuffer mxrt_data(config_size, 0);
    auto* config = reinterpret_cast<stub::StubRuntimeConfig*>(mxrt_data.data());

    config->magic = stub::MXRT_MAGIC;
    config->version = stub::MXRT_VERSION;
    config->num_encrypted_sections = static_cast<uint32_t>(entries.size());
    config->original_entry_rva = ctx.pe_image().entry_point_rva();
    config->total_config_size = config_size;

    stub::StubFlags flags = stub::StubFlags::resolve_imports
                          | stub::StubFlags::fix_relocations
                          | stub::StubFlags::use_syscalls;

    if (ctx.config().enable_header_erasure) {
        flags = flags | stub::StubFlags::erase_headers;
    }
    if (ctx.config().enable_anti_debug) {
        flags = flags | stub::StubFlags::enable_anti_debug;
    }
    if (ctx.config().enable_anti_sandbox) {
        flags = flags | stub::StubFlags::enable_anti_sandbox;
    }

    config->flags = flags;

    config->header_size = ctx.pe_image().dos_header().e_lfanew > 0
        ? static_cast<uint32_t>(ctx.pe_image().dos_header().e_lfanew + 0x108)
        : 0x200;

    config->import_info.original_iat_rva = 0;
    config->import_info.original_iat_size = 0;
    config->import_info.import_dir_rva = 0;
    config->import_info.import_dir_size = 0;

    std::visit([&](const auto& nt) {
        const auto& dd = nt.OptionalHeader.DataDirectory;
        if (pe::IMAGE_DIRECTORY_ENTRY_IMPORT < nt.OptionalHeader.NumberOfRvaAndSizes) {
            config->import_info.import_dir_rva = dd[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            config->import_info.import_dir_size = dd[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (pe::IMAGE_DIRECTORY_ENTRY_IAT < nt.OptionalHeader.NumberOfRvaAndSizes) {
            config->import_info.original_iat_rva = dd[pe::IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            config->import_info.original_iat_size = dd[pe::IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }
        if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC < nt.OptionalHeader.NumberOfRvaAndSizes) {
            config->reloc_info.reloc_dir_rva = dd[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            config->reloc_info.reloc_dir_size = dd[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
    }, ctx.pe_image().nt_headers());

    config->reloc_info.original_image_base = ctx.pe_image().image_base();

    std::random_device rd;
    for (size_t i = 0; i < stub::MAX_KEY_SIZE; i += 4) {
        const uint32_t val = rd();
        std::memcpy(config->master_key + i, &val, sizeof(val));
    }
    config->master_key_size = stub::MAX_KEY_SIZE;

    auto* section_entries = stub::get_section_entries(config);
    for (size_t i = 0; i < entries.size(); ++i) {
        section_entries[i] = entries[i];

        for (uint32_t j = 0; j < entries[i].key_size; ++j) {
            section_entries[i].key[j] ^= config->master_key[j % config->master_key_size];
        }
    }

    config->checksum = compute_crc32(
        ByteView{mxrt_data.data(),
                 config_size - sizeof(uint32_t)});

    return mxrt_data;
}

// ============================================================================
// Основная логика: execute
// ============================================================================

MxStatus EncryptionPass::execute(ProtectionContext& ctx) {
    ctx.log("EncryptionPass: начало шифрования секций");

    auto encryptor = create_encryptor(ctx);
    ctx.log_fmt("EncryptionPass: алгоритм — {} (ключ {} байт, IV {} байт)",
        encryptor->algorithm_name(),
        encryptor->key_size(),
        encryptor->iv_size());

    std::vector<size_t> section_indices;
    for (size_t i = 0; i < ctx.pe_image().sections().size(); ++i) {
        if (should_encrypt_section(ctx.pe_image().sections()[i])) {
            section_indices.push_back(i);
        }
    }

    if (section_indices.empty()) {
        ctx.log("EncryptionPass: нет секций для шифрования, пропуск");
        return {};
    }

    ctx.log_fmt("EncryptionPass: секций для шифрования: {}", section_indices.size());

    if (section_indices.size() > stub::MXRT_MAX_SECTIONS) {
        return std::unexpected(error::encryption_fmt(
            EncryptionErrorCode::metadata_overflow,
            "Количество секций для шифрования ({}) превышает лимит ({})",
            section_indices.size(), stub::MXRT_MAX_SECTIONS));
    }

    std::vector<stub::EncryptedSectionEntry> entries;
    entries.reserve(section_indices.size());

    for (const size_t idx : section_indices) {
        auto& section = ctx.pe_image().sections()[idx];

        ctx.log_fmt("  Шифрование секции '{}': RVA=0x{:08X}, размер={} байт",
            section.name, section.virtual_address, section.data.size());

        const uint32_t original_crc = compute_crc32(
            ByteView{section.data.data(), section.data.size()});

        ByteBuffer key_buf(encryptor->key_size());
        ByteBuffer iv_buf(encryptor->iv_size());

        {
            std::random_device rd;
            for (size_t i = 0; i < key_buf.size(); i += 4) {
                const uint32_t val = rd();
                const size_t to_copy = std::min(static_cast<size_t>(4), key_buf.size() - i);
                std::memcpy(key_buf.data() + i, &val, to_copy);
            }
            for (size_t i = 0; i < iv_buf.size(); i += 4) {
                const uint32_t val = rd();
                const size_t to_copy = std::min(static_cast<size_t>(4), iv_buf.size() - i);
                std::memcpy(iv_buf.data() + i, &val, to_copy);
            }
        }

        auto encrypt_result = encryptor->encrypt(
            ByteView{section.data.data(), section.data.size()},
            ByteView{key_buf.data(), key_buf.size()},
            ByteView{iv_buf.data(), iv_buf.size()});

        if (!encrypt_result) {
            return std::unexpected(encrypt_result.error());
        }

        stub::EncryptedSectionEntry entry{};
        entry.section_rva = section.virtual_address;
        entry.encrypted_size = static_cast<uint32_t>(encrypt_result->size());
        entry.original_size = static_cast<uint32_t>(section.data.size());
        entry.original_characteristics = section.characteristics;
        entry.key_size = static_cast<uint32_t>(key_buf.size());
        entry.iv_size = static_cast<uint32_t>(iv_buf.size());
        entry.crc32 = original_crc;

        if (encryptor->algorithm_name() == "ChaCha20") {
            entry.algorithm = stub::CryptoAlgorithm::chacha20;
        } else {
            entry.algorithm = stub::CryptoAlgorithm::aes256_ctr;
        }

        std::memcpy(entry.key, key_buf.data(), key_buf.size());
        std::memcpy(entry.iv, iv_buf.data(), iv_buf.size());

        section.data = std::move(*encrypt_result);

        section.characteristics &= ~pe::IMAGE_SCN_MEM_EXECUTE;
        section.characteristics |= pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_WRITE;

        entries.push_back(entry);
    }

    auto mxrt_data = build_mxrt_section(ctx, entries);

    pe::SectionInfo mxrt_section;
    mxrt_section.name = ".mxrt";
    mxrt_section.data = std::move(mxrt_data);
    mxrt_section.virtual_size = static_cast<uint32_t>(mxrt_section.data.size());
    mxrt_section.characteristics =
        pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        pe::IMAGE_SCN_MEM_READ |
        pe::IMAGE_SCN_MEM_WRITE;

    auto add_result = ctx.pe_image().add_section(std::move(mxrt_section));
    if (!add_result) {
        return std::unexpected(add_result.error());
    }

    ctx.log_fmt("EncryptionPass: секция .mxrt добавлена (индекс {})", *add_result);
    ctx.log_fmt("EncryptionPass: завершено. Зашифровано {} секций, OEP=0x{:08X}",
        entries.size(), ctx.pe_image().entry_point_rva());

    return {};
}

} // namespace mx
