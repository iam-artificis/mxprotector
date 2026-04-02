########################################################################
## @file CompilerFlags.cmake
## @brief [BUILDER] Флаги компилятора для всех целей проекта MxProtector.
##
## @note Устанавливает C++23, строгие предупреждения, оптимизации.
##       MSVC-ориентированный набор флагов с fallback для GCC/Clang.
########################################################################

## ---------- Общие флаги ----------
if(MSVC)
    add_compile_options(
        /W4          # Уровень предупреждений 4
        /WX          # Предупреждения как ошибки
        /permissive- # Строгое соответствие стандарту
        /Zc:__cplusplus  # Корректное значение __cplusplus
        /Zc:preprocessor # Стандартный препроцессор
        /utf-8       # Исходники в UTF-8
        /EHsc        # Модель обработки исключений (только для Builder)
        /MP          # Многопоточная компиляция
    )

    ## Определяем NOMINMAX и WIN32_LEAN_AND_MEAN глобально
    add_compile_definitions(
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
    )

    ## Release-оптимизации
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Ob2 /GL /DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")

elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wno-unused-parameter
        -fPIC
    )

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -DNDEBUG")
endif()

message(STATUS "[MxProtector] Компилятор: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "[MxProtector] Стандарт: C++${CMAKE_CXX_STANDARD}")
