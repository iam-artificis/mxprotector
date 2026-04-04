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

# STUB runtime (опционально — требует MASM для ASM)
option(MXPROTECTOR_BUILD_STUB "Собирать STUB runtime payload" OFF)
if(MXPROTECTOR_BUILD_STUB)
    add_subdirectory(src/stub)
endif()

# Тесты (опционально)
option(MXPROTECTOR_BUILD_TESTS "Собирать модульные тесты" OFF)
if(MXPROTECTOR_BUILD_TESTS)
    add_subdirectory(tests)
endif()
