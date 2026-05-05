# ==============================================================================
# MxProtector — корневой CMakeLists.txt
#
# Windows x64 Binary Protection Suite.
# Подключает: Zydis (external), Builder (src/builder), тесты (tests).
# Стандарт: C++23.
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

project(MxProtector
    VERSION 1.0.0
    LANGUAGES C CXX
    DESCRIPTION "Windows x64 Binary Protection Suite"
)

# ==============================================================================
# Глобальные настройки
# ==============================================================================

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MX_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

# ==============================================================================
# Зависимости
# ==============================================================================

# Zydis — x86/x64 дизассемблер
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
add_subdirectory(external/zydis)

# ==============================================================================
# Подпроекты
# ==============================================================================

add_subdirectory(src/builder)

# Тесты (опционально). enable_testing() в корне нужен для того, чтобы
# CMake сгенерировал верхнеуровневый CTestTestfile.cmake — без него
# `ctest` из build-root не видит тесты из tests/unit/ (gtest_discover_tests
# регистрирует их, но только в подкаталоге).
option(MXPROTECTOR_BUILD_TESTS "Собирать модульные тесты" OFF)
if(MXPROTECTOR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
