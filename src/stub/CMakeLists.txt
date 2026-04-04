# ==============================================================================
# [STUB] CMakeLists.txt — сборка STUB runtime payload.
#
# STUB — инжектируемый движок, работающий внутри защищённого PE.
# Требования: PIC, без CRT/STL, indirect syscalls.
#
# Сборка: статическая библиотека для тестирования на хосте.
# Финальный shellcode: линкуется отдельно с /GS- /NODEFAULTLIB (Phase 8+).
#
# Компоненты:
#   - crypto/    : PIC ChaCha20 + AES-256-CTR
#   - syscall/   : Hell's Gate / Halo's Gate SSN resolver
#   - loader/    : Расшифровка, импорты, релокации, stub_main
#   - integrity/ : Стирание заголовков, PAGE_GUARD
#   - entry.asm  : PIC точка входа (MASM x64)
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

# ==============================================================================
# Исходные файлы STUB (C++)
# ==============================================================================

set(STUB_SOURCES
    # Криптография (PIC)
    crypto/chacha20_pic.cpp
    crypto/aes_pic.cpp

    # Syscall Engine
    syscall/resolver.cpp

    # Загрузчик
    loader/stub_main.cpp
    loader/section_decryptor.cpp
    loader/import_resolver.cpp
    loader/relocation_fixer.cpp

    # Целостность / Anti-Dump
    integrity/header_eraser.cpp
)

# ==============================================================================
# ASM файлы (MASM x64)
# ==============================================================================

set(STUB_ASM_SOURCES
    entry.asm
    syscall/gate.asm
)

# ==============================================================================
# Цель: mxprotector_stub (статическая библиотека для тестирования)
# ==============================================================================

add_library(mxprotector_stub STATIC ${STUB_SOURCES})

target_compile_features(mxprotector_stub PRIVATE cxx_std_23)

target_include_directories(mxprotector_stub PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# MSVC-специфичные флаги для STUB
if(MSVC)
    target_compile_options(mxprotector_stub PRIVATE
        /W4
        /utf-8
        /Zc:__cplusplus
        /permissive-
        /GS-              # Отключить stack cookies (PIC requirement)
    )

    # MASM для ASM-файлов (STUB shellcode entry + syscall gate)
    enable_language(ASM_MASM)
    target_sources(mxprotector_stub PRIVATE ${STUB_ASM_SOURCES})
else()
    target_compile_options(mxprotector_stub PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -fno-stack-protector  # Аналог /GS-
        -fPIC
    )
endif()
