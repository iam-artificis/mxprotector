########################################################################
## @file Dependencies.cmake
## @brief [BUILDER] Подключение внешних зависимостей проекта MxProtector.
##
## @note Zydis подключается как git submodule через add_subdirectory.
##       GoogleTest загружается через FetchContent (только для тестов).
########################################################################

## ---------- Zydis (дизассемблер x86/x64) ----------
## Отключаем ненужные компоненты Zydis для ускорения сборки
option(ZYDIS_BUILD_TOOLS    "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_BUILD_TESTS    "" OFF)
option(ZYDIS_BUILD_DOXYGEN  "" OFF)
option(ZYAN_BUILD_SHARED_LIB "" OFF)

set(ZYDIS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/zydis")

if(EXISTS "${ZYDIS_DIR}/CMakeLists.txt")
    add_subdirectory("${ZYDIS_DIR}" EXCLUDE_FROM_ALL)
    message(STATUS "[MxProtector] Zydis найден: ${ZYDIS_DIR}")
else()
    message(FATAL_ERROR
        "[MxProtector] Zydis не найден в ${ZYDIS_DIR}.\n"
        "Выполните: git submodule update --init --recursive")
endif()
