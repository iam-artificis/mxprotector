# ==============================================================================
# [TESTS] CMakeLists.txt — модульные тесты MxProtector.
#
# Подключает GoogleTest через FetchContent и добавляет поддиректорию unit/.
# Тесты покрывают: PE-парсинг, дизассемблирование, CFG, маркеры, пайплайн.
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
)

# Предотвращаем установку GTest вместе с проектом
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

enable_testing()

add_subdirectory(unit)

add_executable(mx_test_target testapp/test_target.cpp)
target_include_directories(mx_test_target PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/sdk/include)

# Интеграционные тесты (требуют MSVC + MASM для gate.asm)
option(MXPROTECTOR_BUILD_INTEGRATION_TESTS "Собирать live-тесты syscall engine" OFF)
if(MXPROTECTOR_BUILD_INTEGRATION_TESTS)
    add_subdirectory(integration)
endif()
