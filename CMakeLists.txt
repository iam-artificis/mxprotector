# ==============================================================================
# MxProtector - root CMakeLists.txt
#
# Windows x64 Binary Protection Suite.
# Wires in: Zydis (external), Builder (src/builder), tests (tests/).
# Standard: C++23.
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

project(MxProtector
    VERSION 1.0.0
    LANGUAGES C CXX
    DESCRIPTION "Windows x64 Binary Protection Suite"
)

# ==============================================================================
# Global settings
# ==============================================================================

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MX_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

# ==============================================================================
# Dependencies
# ==============================================================================

# Zydis - x86/x64 disassembler
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
add_subdirectory(external/zydis)

# ==============================================================================
# Subprojects
# ==============================================================================

add_subdirectory(src/builder)

# Tests (optional). enable_testing() at the root is required so CMake
# generates a top-level CTestTestfile.cmake - without it, `ctest` run
# from the build root does not see tests under tests/unit/
# (gtest_discover_tests registers them, but only under the subdir).
option(MXPROTECTOR_BUILD_TESTS "Build unit tests" OFF)
if(MXPROTECTOR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
