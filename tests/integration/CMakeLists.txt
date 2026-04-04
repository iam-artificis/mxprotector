# ==============================================================================
# [TESTS] integration/CMakeLists.txt — live-тесты syscall engine.
#
# Компилирует standalone тест, который линкуется с gate.asm (MASM)
# и выполняет реальные syscall-вызовы NtProtectVirtualMemory.
#
# Требует: MSVC x64, MASM (ml64). Включается через опцию CMake:
#   -DMXPROTECTOR_BUILD_INTEGRATION_TESTS=ON
#
# Альтернативная ручная сборка:
#   ml64 /c /nologo ../../src/stub/syscall/gate.asm /Fo gate.obj
#   cl /std:c++20 /EHsc /W4 syscall_live_test.cpp gate.obj /Fe:syscall_test.exe
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

if(NOT MSVC)
    message(STATUS "[Integration Tests] Skipped: MSVC required for MASM support")
    return()
endif()

enable_language(ASM_MASM)

add_executable(syscall_live_test
    syscall_live_test.cpp
    test_helpers.asm
    ${CMAKE_SOURCE_DIR}/src/stub/syscall/gate.asm
)

target_compile_features(syscall_live_test PRIVATE cxx_std_20)

target_include_directories(syscall_live_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/stub/include
)

if(MSVC)
    # Применяем C++ флаги ТОЛЬКО к .cpp файлам (не к ASM)
    set_source_files_properties(syscall_live_test.cpp PROPERTIES
        COMPILE_OPTIONS "/W4;/utf-8;/Zc:__cplusplus;/permissive-"
    )
endif()

# Регистрация как CTest
add_test(NAME syscall_live_test COMMAND syscall_live_test)
