/**
 * @file stub_config.hpp
 * @brief [BUILDER/STUB] Разделяемые структуры метаданных между Builder и STUB.
 *
 * @details Определяет бинарный формат конфигурации, который Builder записывает
 *          в секцию .mxrt защищённого PE, а STUB читает при старте для расшифровки
 *          секций, разрешения импортов и восстановления релокаций.
 *
 *          Все структуры упакованы (#pragma pack(push, 1)) и используют
 *          exact-sized типы для бинарной совместимости между Builder и STUB.
 *
 * @note Этот заголовок НЕ зависит от STL — используется и в STUB (PIC, no-CRT).
 *       В Builder инклудится через обычный include path.
 *       В STUB компилируется с ограничениями PIC.
 */

#pragma once

#include <cstdint>

namespace mx::stub {

// ============================================================================
// Магические константы и версии
// ============================================================================

/// @brief Магическая сигнатура секции .mxrt ("MXRT").
constexpr uint32_t MXRT_MAGIC = 0x5452584D;

/// @brief Текущая версия формата метаданных.
constexpr uint32_t MXRT_VERSION = 1;

/// @brief Максимальное количество зашифрованных секций.
constexpr uint32_t MXRT_MAX_SECTIONS = 32;

/// @brief Размер ключа ChaCha20 (256 бит).
constexpr uint32_t CHACHA20_KEY_SIZE = 32;

/// @brief Размер nonce ChaCha20 (96 бит, RFC 7539).
constexpr uint32_t CHACHA20_NONCE_SIZE = 12;

/// @brief Размер ключа AES-256.
constexpr uint32_t AES256_KEY_SIZE = 32;

/// @brief Размер IV для AES-256-CTR (128 бит).
constexpr uint32_t AES256_IV_SIZE = 16;

/// @brief Максимальный размер ключа/IV среди поддерживаемых алгоритмов.
constexpr uint32_t MAX_KEY_SIZE = 32;
constexpr uint32_t MAX_IV_SIZE = 16;

// ============================================================================
// Перечисления
// ============================================================================

/**
 * @brief Алгоритм шифрования, использованный для секции.
 */
enum class CryptoAlgorithm : uint8_t {
    chacha20    = 0, ///< ChaCha20 (RFC 7539)
    aes256_ctr  = 1  ///< AES-256 в режиме CTR
};

/**
 * @brief Флаги конфигурации STUB.
 * @details Битовая маска, определяющая поведение загрузчика.
 */
enum class StubFlags : uint32_t {
    none                = 0x00000000,
    erase_headers       = 0x00000001, ///< Стереть PE-заголовки после загрузки
    encrypt_headers     = 0x00000002, ///< Зашифровать заголовки вместо стирания
    resolve_imports     = 0x00000004, ///< Разрешить импорты динамически
    fix_relocations     = 0x00000008, ///< Пересчитать релокации
    enable_anti_debug   = 0x00000010, ///< Активировать анти-отладку
    enable_anti_sandbox = 0x00000020, ///< Активировать анти-песочницу
    enable_integrity    = 0x00000040, ///< Активировать проверку целостности
    use_syscalls        = 0x00000080, ///< Использовать indirect syscalls
    page_guard_trap     = 0x00000100, ///< Установить PAGE_GUARD-ловушки
};

/// @brief Побитовое ИЛИ для StubFlags.
[[nodiscard]] constexpr StubFlags operator|(StubFlags a, StubFlags b) noexcept {
    return static_cast<StubFlags>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/// @brief Побитовое И для StubFlags.
[[nodiscard]] constexpr StubFlags operator&(StubFlags a, StubFlags b) noexcept {
    return static_cast<StubFlags>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/// @brief Проверка наличия флага.
[[nodiscard]] constexpr bool has_flag(StubFlags flags, StubFlags flag) noexcept {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

// ============================================================================
// Упакованные структуры метаданных (бинарный формат секции .mxrt)
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Запись об одной зашифрованной секции.
 *
 * @details Содержит всю информацию, необходимую STUB для расшифровки:
 *          RVA, размер, ключ, IV и оригинальные атрибуты секции.
 */
struct EncryptedSectionEntry {
    uint32_t        section_rva;          ///< RVA начала секции в образе
    uint32_t        encrypted_size;       ///< Размер зашифрованных данных (байт)
    uint32_t        original_size;        ///< Оригинальный размер данных (до padding)
    uint32_t        original_characteristics; ///< Оригинальные флаги секции (RWX)
    CryptoAlgorithm algorithm;            ///< Алгоритм шифрования
    uint8_t         reserved[3];          ///< Выравнивание до 4 байт
    uint8_t         key[MAX_KEY_SIZE];    ///< Ключ шифрования
    uint8_t         iv[MAX_IV_SIZE];      ///< IV / nonce
    uint32_t        key_size;             ///< Фактический размер ключа (байт)
    uint32_t        iv_size;              ///< Фактический размер IV (байт)
    uint32_t        crc32;                ///< CRC32 оригинальных данных (для верификации)
};

static_assert(sizeof(EncryptedSectionEntry) == 80,
    "EncryptedSectionEntry должен быть 80 байт");

/**
 * @brief Информация об оригинальной таблице импортов.
 *
 * @details STUB использует эти данные для динамического разрешения импортов.
 *          Оригинальная IAT стирается из PE; импорты разрешаются STUB через
 *          LoadLibraryA/GetProcAddress или через syscall-based resolution.
 */
struct ImportTableInfo {
    uint32_t original_iat_rva;     ///< RVA оригинальной IAT
    uint32_t original_iat_size;    ///< Размер IAT
    uint32_t import_dir_rva;       ///< RVA директории импортов
    uint32_t import_dir_size;      ///< Размер директории импортов
};

/**
 * @brief Информация о релокациях для пересчёта.
 */
struct RelocationInfo {
    uint32_t reloc_dir_rva;        ///< RVA директории релокаций
    uint32_t reloc_dir_size;       ///< Размер директории
    uint64_t original_image_base;  ///< Оригинальная база загрузки
};

/**
 * @brief Главный заголовок конфигурации STUB (.mxrt).
 *
 * @details Первая структура в секции .mxrt. Содержит глобальные параметры
 *          и счётчики для последующих массивов данных.
 *
 *          Расположение данных в .mxrt:
 *          [StubRuntimeConfig]
 *          [EncryptedSectionEntry × num_encrypted_sections]
 */
struct StubRuntimeConfig {
    uint32_t         magic;                  ///< MXRT_MAGIC (0x5452584D)
    uint32_t         version;                ///< Версия формата (MXRT_VERSION)
    StubFlags        flags;                  ///< Флаги поведения STUB
    uint32_t         num_encrypted_sections; ///< Количество зашифрованных секций
    uint32_t         original_entry_rva;     ///< Оригинальный RVA точки входа (OEP)
    ImportTableInfo  import_info;            ///< Информация о таблице импортов
    RelocationInfo   reloc_info;             ///< Информация о релокациях
    uint32_t         header_size;            ///< Размер заголовков PE (для стирания)
    uint32_t         total_config_size;      ///< Полный размер конфигурации .mxrt
    uint8_t          master_key[MAX_KEY_SIZE]; ///< Мастер-ключ (для XOR с секционными ключами)
    uint32_t         master_key_size;        ///< Размер мастер-ключа
    uint32_t         checksum;               ///< CRC32 всей конфигурации (без checksum)
};

#pragma pack(pop)

// ============================================================================
// Утилиты для работы с конфигурацией
// ============================================================================

/**
 * @brief Вычисляет полный размер конфигурации .mxrt.
 * @param num_sections Количество зашифрованных секций.
 * @return Размер в байтах.
 */
[[nodiscard]] constexpr uint32_t calc_mxrt_size(uint32_t num_sections) noexcept {
    return static_cast<uint32_t>(
        sizeof(StubRuntimeConfig) +
        sizeof(EncryptedSectionEntry) * num_sections);
}

/**
 * @brief Возвращает указатель на массив EncryptedSectionEntry после заголовка.
 * @param config Указатель на StubRuntimeConfig.
 * @return Указатель на первый EncryptedSectionEntry.
 *
 * @note Безопасно для PIC — использует только арифметику указателей.
 */
[[nodiscard]] inline const EncryptedSectionEntry* get_section_entries(
    const StubRuntimeConfig* config) noexcept
{
    return reinterpret_cast<const EncryptedSectionEntry*>(
        reinterpret_cast<const uint8_t*>(config) + sizeof(StubRuntimeConfig));
}

/// @copydoc get_section_entries(const StubRuntimeConfig*)
[[nodiscard]] inline EncryptedSectionEntry* get_section_entries(
    StubRuntimeConfig* config) noexcept
{
    return reinterpret_cast<EncryptedSectionEntry*>(
        reinterpret_cast<uint8_t*>(config) + sizeof(StubRuntimeConfig));
}

} // namespace mx::stub
