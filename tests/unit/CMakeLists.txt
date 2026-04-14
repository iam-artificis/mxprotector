# ==============================================================================
# [TESTS] unit/CMakeLists.txt — модульные тесты Phase 2.
#
# Тесты: подстановка инструкций, junk-генератор, constant unfolding,
#         opaque predicates, x86 encoding helpers.
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

# ==============================================================================
# Исходные файлы тестов
# ==============================================================================

set(TEST_SOURCES
    mutation_engine_test.cpp
    cfg_flattening_test.cpp
    vm_stack_layout_test.cpp
    anti_emulation_check_test.cpp
    mx_string_test.cpp
    x64_specialized_handlers_test.cpp
    x64_inner_vm_runtime_test.cpp
    anti_tamper_test.cpp
    string_scanner_test.cpp
    string_xref_finder_test.cpp
    string_encryptor_test.cpp
    string_decryptor_codegen_test.cpp
    string_protection_pass_test.cpp
)

# VM sources needed for VmStackLayout + x64 handler tests and for
# StringProtectionPass --strings=vm lift/generate symbols pulled in by
# the S2c orchestrator.
set(VM_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/vm_stack_layout.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/vm_lifter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/vm_runtime_gen.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_emitters.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_vflags.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_handlers.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_inner_vm.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_vm_backend.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/zydis_disassembler.cpp
)

# Anti-emulation sources needed for check registry tests
set(ANTI_EMU_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_emulation/check_registry.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_emulation/rdtsc_timing_check.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_emulation/cpuid_hypervisor_check.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_emulation/eflags_reserved_bit_check.cpp
)

# Anti-tamper sources needed for anti_tamper_test
set(ANTI_TAMPER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/hells_gate_resolver.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/check_registry.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/hw_breakpoint_check.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/import_hook_check.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/self_crc_check.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/page_protection_check.cpp
)

# S2 string-protection sources needed for scanner/xref tests (and future
# encryptor/runtime tests as they're added)
set(STRING_PROTECT_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_xref_finder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_encryptor.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_decryptor_codegen.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_protection_pass.cpp
)

# ==============================================================================
# Исходные файлы мутации/обфускации (нужны для линковки)
# ==============================================================================

set(MUTATION_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/instruction_substitution.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/junk_generator.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/register_reassignment.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/instruction_splitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/opaque_predicates.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/constant_unfolding.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/mba_transform.cpp
)

# Phase 3: CFF + Assembler
set(CFF_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/x86_code_emitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/cfg_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/section_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cfg_flattening_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/dispatcher_gen.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/bogus_flow.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/map_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/mba_transition_gen.cpp
)

# ==============================================================================
# Цель: mxprotector_tests
# ==============================================================================

add_executable(mxprotector_tests
    ${TEST_SOURCES}
    ${MUTATION_SOURCES}
    ${CFF_SOURCES}
    ${VM_SOURCES}
    ${ANTI_EMU_SOURCES}
    ${ANTI_TAMPER_SOURCES}
    ${STRING_PROTECT_SOURCES})

target_compile_features(mxprotector_tests PRIVATE cxx_std_23)

target_include_directories(mxprotector_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/external/zydis/include
    ${CMAKE_SOURCE_DIR}/external/zydis/dependencies/zycore/include
    ${CMAKE_SOURCE_DIR}/src/builder
    ${CMAKE_SOURCE_DIR}/src/sdk/include
)

target_link_libraries(mxprotector_tests PRIVATE
    GTest::gtest_main
    Zydis
)

if(MSVC)
    target_compile_options(mxprotector_tests PRIVATE
        /W4
        /utf-8
        /Zc:__cplusplus
        /permissive-
    )
endif()

include(GoogleTest)
gtest_discover_tests(mxprotector_tests)
