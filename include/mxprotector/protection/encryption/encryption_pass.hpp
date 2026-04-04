/**
 * @file encryption_pass.hpp
 * @brief [BUILDER] Проход шифрования секций PE-файла.
 *
 * @details EncryptionPass шифрует кодовые и данные-секции PE:
 *          1. Выбирает алгоритм (ChaCha20 или AES-256-CTR) по конфигурации
 *          2. Генерирует уникальный ключ и IV для каждой секции
 *          3. Шифрует данные секции in-place
 *          4. Формирует метаданные для STUB (StubRuntimeConfig)
 *          5. Добавляет секцию .mxrt с конфигурацией STUB
 *          6. Перенаправляет точку входа на STUB
 *
 *          Проход выполняется после мутации/обфускации и перед инъекцией STUB.
 *          Приоритет: 600 (категория encryption).
 *
 * @note Проход не шифрует секцию .reloc и секции с ресурсами (.rsrc),
 *       так как они нужны загрузчику Windows до передачи управления STUB.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/interfaces.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/pass.hpp"
#include "mxprotector/stub/stub_config.hpp"

namespace mx {

class ProtectionContext;

/**
 * @brief Проход шифрования секций PE в пайплайне защиты.
 *
 * @details Реализует IProtectionPass. Шифрует все подходящие секции,
 *          генерирует метаданные .mxrt, обновляет entry point.
 *
 *          SOLID (SRP): отвечает только за шифрование секций и формирование
 *          конфигурации STUB. Сам STUB инжектируется отдельным проходом.
 *          SOLID (OCP): поддержка новых алгоритмов — через IEncryptor.
 */
class EncryptionPass final : public IProtectionPass {
public:
    EncryptionPass() = default;
    ~EncryptionPass() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "EncryptionPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::encryption;
    }

    /// @brief Приоритет 600 — после мутации/обфускации, перед STUB injection.
    [[nodiscard]] uint32_t priority() const noexcept override {
        return 600;
    }

    /**
     * @brief Выполняет шифрование секций PE.
     * @param ctx Контекст пайплайна.
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;

    /**
     * @brief Проверяет применимость: config.enable_encryption == true.
     * @param ctx Контекст.
     * @return true если шифрование включено.
     */
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;

    /**
     * @brief Вычисляет CRC32 блока данных (ISO 3309, polynomial 0xEDB88320).
     * @param data Данные для хеширования.
     * @return Значение CRC32.
     *
     * @note Публичный — используется для верификации расшифрованных секций.
     */
    [[nodiscard]] static uint32_t compute_crc32(ByteView data) noexcept;

private:
    /**
     * @brief Проверяет, нужно ли шифровать секцию.
     * @param section Информация о секции.
     * @return true если секция подлежит шифрованию.
     *
     * @details Шифруются секции с кодом (.text) и данными (.data, .rdata).
     *          НЕ шифруются: .reloc, .rsrc, .mxrt, .pdata, .edata.
     */
    [[nodiscard]] static bool should_encrypt_section(const pe::SectionInfo& section) noexcept;

    /**
     * @brief Создаёт IEncryptor по конфигурации (ChaCha20 или AES).
     * @param ctx Контекст с конфигурацией.
     * @return Указатель на encryptor.
     */
    [[nodiscard]] static std::unique_ptr<IEncryptor> create_encryptor(
        const ProtectionContext& ctx);

    /**
     * @brief Формирует StubRuntimeConfig из зашифрованных секций.
     * @param ctx Контекст.
     * @param entries Записи зашифрованных секций.
     * @return Сериализованная конфигурация .mxrt.
     */
    [[nodiscard]] static ByteBuffer build_mxrt_section(
        const ProtectionContext& ctx,
        const std::vector<stub::EncryptedSectionEntry>& entries);

};

} // namespace mx
