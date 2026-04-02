/**
 * @file api.hpp
 * @brief [SDK] Публичный API MxProtector SDK — единый include-файл.
 *
 * @details Подключает все компоненты SDK: маркеры защиты, compile-time шифрование
 *          строк и обфускацию констант. Пользователю достаточно подключить
 *          только этот файл для доступа ко всей функциональности SDK.
 *
 * @par Пример использования:
 * @code
 * #include <mxprotector_sdk/api.hpp>
 *
 * void protected_function() {
 *     MX_VM_BEGIN
 *     auto key = MX_STRING("license_key_aes256");
 *     int max_attempts = MX_CONST(5);
 *     // ... защищённая логика ...
 *     MX_VM_END
 * }
 * @endcode
 */

#pragma once

#include "mxprotector_sdk/markers.hpp"
#include "mxprotector_sdk/strings.hpp"
#include "mxprotector_sdk/constants.hpp"
