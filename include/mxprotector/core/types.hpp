/**
 * @file types.hpp
 * @brief [BUILDER/STUB/SDK] Фундаментальные типы, псевдонимы и перечисления проекта MxProtector.
 *
 * @details Этот файл является корневой зависимостью для ВСЕХ модулей проекта.
 *          Определяет базовые типы данных, используемые повсеместно:
 *          буферы, адреса (RVA/VA/FileOffset), архитектуру, тип PE и категории проходов.
 *          НЕ зависит ни от одного другого заголовка проекта.
 *
 * @note Все типы используют exact-sized (uint8_t, uint32_t и т.д.) согласно стандартам проекта.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <array>
#include <functional>

namespace mx {

// ============================================================================
// Базовые буферные типы
// ============================================================================

/// @brief Владеющий буфер байтов (основной тип для хранения данных PE).
using ByteBuffer = std::vector<uint8_t>;

/// @brief Неизменяемое представление буфера байтов (для чтения без копирования).
using ByteView = std::span<const uint8_t>;

/// @brief Изменяемое представление буфера байтов (для модификации in-place).
using MutableByteView = std::span<uint8_t>;

// ============================================================================
// Адресные типы
// ============================================================================

/// @brief Relative Virtual Address — смещение относительно базы образа.
using Rva = uint32_t;

/// @brief Virtual Address — абсолютный виртуальный адрес в памяти процесса.
using Va = uint64_t;

/// @brief Смещение от начала файла на диске.
using FileOffset = uint32_t;

// ============================================================================
// Перечисления
// ============================================================================

/**
 * @brief Архитектура целевого PE-файла.
 * @note Определяется по полю Machine в IMAGE_FILE_HEADER.
 */
enum class Architecture : uint8_t {
    x86 = 0,   ///< 32-битная архитектура (IMAGE_FILE_MACHINE_I386)
    x64 = 1    ///< 64-битная архитектура (IMAGE_FILE_MACHINE_AMD64)
};

/**
 * @brief Тип PE-файла, определяемый по характеристикам и подсистеме.
 */
enum class PeType : uint8_t {
    executable      = 0,  ///< .exe — исполняемый файл
    dynamic_library = 1,  ///< .dll — динамическая библиотека
    kernel_driver   = 2   ///< .sys — драйвер ядра (IMAGE_SUBSYSTEM_NATIVE)
};

/**
 * @brief Категория прохода защиты — определяет, к какому классу относится трансформация.
 * @details Используется PassManager для упорядочивания и группировки проходов.
 */
enum class PassCategory : uint8_t {
    mutation          = 0,  ///< Мутация инструкций (substitution, junk, splitting)
    obfuscation       = 1,  ///< Обфускация (opaque predicates, MBA, constant unfolding)
    virtualization    = 2,  ///< Виртуализация (трансляция в VM bytecode)
    cfg_transform     = 3,  ///< Трансформация CFG (flattening, bogus flow)
    anti_analysis     = 4,  ///< Анти-анализ (anti-disasm, nanomites, code interleaving)
    encryption        = 5,  ///< Шифрование секций/кода
    packing           = 6,  ///< Упаковка/сжатие
    stub_injection    = 7   ///< Инъекция STUB runtime
};

/**
 * @brief Уровень защиты — предустановка, определяющая набор и силу проходов.
 */
enum class ProtectionLevel : uint8_t {
    minimal  = 0,  ///< Минимальная: только базовая мутация и шифрование
    standard = 1,  ///< Стандартная: мутация + обфускация + CFG flattening
    strong   = 2,  ///< Сильная: + VM для маркированного кода + anti-debug
    maximum  = 3   ///< Максимальная: все проходы, включая VM nesting и nanomites
};

/**
 * @brief Тип региона кода, помеченного SDK-маркером.
 * @details Сканер маркеров определяет тип и передаёт соответствующему проходу.
 */
enum class MarkerType : uint8_t {
    vm_begin        = 0,  ///< MX_VM_BEGIN — начало виртуализируемого региона
    vm_end          = 1,  ///< MX_VM_END — конец виртуализируемого региона
    mutate_begin    = 2,  ///< MX_MUTATE_BEGIN — начало мутируемого региона
    mutate_end      = 3,  ///< MX_MUTATE_END — конец мутируемого региона
    obfuscate_begin = 4,  ///< MX_OBFUSCATE_BEGIN — начало обфусцируемого региона
    obfuscate_end   = 5,  ///< MX_OBFUSCATE_END — конец обфусцируемого региона
    guard_begin     = 6,  ///< MX_GUARD_BEGIN — начало runtime-guarded блока
    guard_end       = 7   ///< MX_GUARD_END — конец runtime-guarded блока
};

// ============================================================================
// Вспомогательные структуры
// ============================================================================

/**
 * @brief Диапазон адресов [start, start + size).
 * @details Используется для описания регионов в PE (секции, маркированные зоны и т.д.).
 */
struct AddressRange {
    Va       start = 0; ///< Начальный адрес (VA)
    uint64_t size  = 0; ///< Размер в байтах

    /// @brief Проверяет, содержит ли диапазон указанный адрес.
    [[nodiscard]] constexpr bool contains(Va address) const noexcept {
        return address >= start && address < (start + size);
    }

    /// @brief Проверяет пересечение с другим диапазоном.
    [[nodiscard]] constexpr bool overlaps(const AddressRange& other) const noexcept {
        return start < (other.start + other.size) && other.start < (start + size);
    }

    /// @brief Конечный адрес (не включительно).
    [[nodiscard]] constexpr Va end() const noexcept {
        return start + size;
    }
};

/**
 * @brief Описание маркированного региона, найденного SDK-сканером.
 */
struct MarkedRegion {
    MarkerType type;              ///< Тип маркера (VM/Mutate/Obfuscate)
    Rva        start_rva;         ///< RVA начала тела региона (сразу после begin-маркера)
    Rva        end_rva;            ///< RVA конца тела региона (начало end-маркера)
    uint32_t   section_index;     ///< Индекс секции, содержащей регион
    uint32_t   begin_marker_size; ///< Размер begin-маркерной конструкции (в байтах)
    uint32_t   end_marker_size;   ///< Размер end-маркерной конструкции (в байтах)
};

} // namespace mx
