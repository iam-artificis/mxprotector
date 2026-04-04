/**
 * @file section_decryptor.cpp
 * @brief [STUB] Расшифровка зашифрованных секций PE в рантайме.
 *
 * @details Читает массив EncryptedSectionEntry из .mxrt и для каждой секции:
 *          1. Восстанавливает ключ (XOR с master_key)
 *          2. Выбирает криптоалгоритм (ChaCha20 / AES-256-CTR)
 *          3. Расшифровывает данные in-place
 *          4. Восстанавливает оригинальные атрибуты секции (RWX)
 *
 * @note PIC, без CRT/STL. Все операции in-place (не требуют доп. памяти).
 *       VirtualProtect вызывается через indirect syscall.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"
#include "../syscall/syscall_defs.hpp"

namespace mx::stub::pic {

/// @brief Объявления PIC-крипто (определены в crypto/).
extern void chacha20_decrypt_inplace(
    uint8_t* data, uint32_t data_size,
    const uint8_t* key, const uint8_t* nonce) noexcept;

extern void aes256_ctr_decrypt_inplace(
    uint8_t* data, uint32_t data_size,
    const uint8_t* key, const uint8_t* iv) noexcept;

/// @brief Indirect syscall (определён в gate.asm). Tail-call трамплин с поддержкой 5+ Nt-аргументов.
extern "C" uint64_t indirect_syscall(
    uint32_t ssn, uint64_t syscall_addr,
    uint64_t arg1, uint64_t arg2,
    uint64_t arg3, uint64_t arg4,
    uint64_t arg5);

/**
 * @brief Изменяет атрибуты защиты памяти через NtProtectVirtualMemory (indirect syscall).
 *
 * @param table   Таблица syscall.
 * @param address Адрес начала региона.
 * @param size    Размер региона.
 * @param protect Новые флаги защиты (PAGE_*).
 * @return NTSTATUS (0 = успех).
 */
static uint32_t protect_memory(
    const SyscallTable& table,
    void* address,
    uint64_t size,
    uint32_t protect) noexcept
{
    const auto& entry = table.get(NtFunction::NtProtectVirtualMemory);
    if (!entry.resolved) return 0xC0000001;

    void* base_addr = address;
    uint64_t region_size = size;
    uint32_t old_protect = 0;

    const uint64_t process_handle = static_cast<uint64_t>(-1);

    return static_cast<uint32_t>(indirect_syscall(
        entry.ssn, entry.syscall_addr,
        process_handle,
        reinterpret_cast<uint64_t>(&base_addr),
        reinterpret_cast<uint64_t>(&region_size),
        static_cast<uint64_t>(protect),
        reinterpret_cast<uint64_t>(&old_protect)));
}

/**
 * @brief Расшифровывает все секции, описанные в StubRuntimeConfig.
 *
 * @param image_base  VA базы загрузки образа.
 * @param config      Указатель на StubRuntimeConfig (в секции .mxrt).
 * @param table       Таблица syscall (для NtProtectVirtualMemory).
 * @return Количество успешно расшифрованных секций.
 *
 * @details Для каждой EncryptedSectionEntry:
 *          1. Вычисляет VA секции = image_base + section_rva
 *          2. Делает секцию RW (VirtualProtect)
 *          3. Восстанавливает ключ (XOR с master_key)
 *          4. Вызывает chacha20_decrypt_inplace() или aes256_ctr_decrypt_inplace()
 *          5. Восстанавливает оригинальные атрибуты (VirtualProtect)
 */
uint32_t decrypt_sections(
    uint64_t                    image_base,
    const StubRuntimeConfig*    config,
    const SyscallTable&         table) noexcept
{
    if (!config) return 0;
    if (config->magic != MXRT_MAGIC) return 0;
    if (config->num_encrypted_sections == 0) return 0;

    const auto* entries = get_section_entries(config);
    uint32_t decrypted_count = 0;

    for (uint32_t i = 0; i < config->num_encrypted_sections; ++i) {
        const auto& entry = entries[i];

        auto* section_data = va_to_ptr<uint8_t>(image_base + entry.section_rva);

        protect_memory(table, section_data, entry.encrypted_size, PAGE_READWRITE);

        uint8_t restored_key[MAX_KEY_SIZE];
        for (uint32_t k = 0; k < entry.key_size; ++k) {
            restored_key[k] = entry.key[k] ^ config->master_key[k % config->master_key_size];
        }

        if (entry.algorithm == CryptoAlgorithm::chacha20) {
            chacha20_decrypt_inplace(
                section_data,
                entry.encrypted_size,
                restored_key,
                entry.iv);
        } else {
            aes256_ctr_decrypt_inplace(
                section_data,
                entry.encrypted_size,
                restored_key,
                entry.iv);
        }

        uint32_t new_protect = PAGE_READONLY;
        const uint32_t chars = entry.original_characteristics;

        const bool exec = (chars & 0x20000000) != 0;
        const bool write = (chars & 0x80000000) != 0;

        if (exec && write) {
            new_protect = PAGE_EXECUTE_READWRITE;
        } else if (exec) {
            new_protect = PAGE_EXECUTE_READ;
        } else if (write) {
            new_protect = PAGE_READWRITE;
        }

        protect_memory(table, section_data, entry.encrypted_size, new_protect);

        ++decrypted_count;
    }

    return decrypted_count;
}

} // namespace mx::stub::pic
