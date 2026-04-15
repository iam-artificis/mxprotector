# ==============================================================================
# [BUILDER] CMakeLists.txt — сборка исполняемого файла mxprotector_builder.
#
# Собирает все исходники из src/builder/ (PE-модуль, анализ, защита, CLI)
# и линкует с библиотекой Zydis для дизассемблирования.
# Стандарт: C++23.
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

# ==============================================================================
# Исходные файлы
# ==============================================================================

set(BUILDER_SOURCES
    # Точка входа
    main.cpp

    # CLI
    cli/cli_handler.cpp

    # PE-модуль
    pe/pe_parser.cpp
    pe/pe_builder.cpp
    pe/section_manager.cpp
    pe/import_table.cpp
    pe/export_table.cpp
    pe/relocation_table.cpp

    # Модуль анализа
    analysis/zydis_disassembler.cpp
    analysis/cfg_builder.cpp
    analysis/marker_scanner.cpp

    # Инфраструктура защиты
    protection/pass_manager.cpp

    # Фаза 2: Мутация
    protection/mutation/mutation_pass.cpp
    protection/mutation/instruction_substitution.cpp
    protection/mutation/register_reassignment.cpp
    protection/mutation/junk_generator.cpp

    # Фаза 2: Обфускация
    protection/obfuscation/obfuscation_pass.cpp
    protection/obfuscation/opaque_predicates.cpp
    protection/obfuscation/constant_unfolding.cpp
    protection/obfuscation/mba_transform.cpp

    # Phase 3: Mutation Strengthening
    protection/mutation/instruction_splitter.cpp

    # Phase 3: Assembler / Code Emitter
    analysis/x86_code_emitter.cpp

    # Phase 3: CFG Flattening
    protection/cfg/cfg_flattening_pass.cpp
    protection/cfg/dispatcher_gen.cpp
    protection/cfg/bogus_flow.cpp
    protection/cfg/map_parser.cpp
    protection/cfg/mba_transition_gen.cpp

    # Phase 4: Virtualization (VM engine)
    protection/vm/vm_lifter.cpp
    protection/vm/vm_stack_layout.cpp
    protection/vm/vm_runtime_gen.cpp
    protection/vm/virtualization_pass.cpp

    # Phase 4: x64 VM backend (split out of vm_runtime_gen.cpp)
    protection/vm/x64/x64_emitters.cpp
    protection/vm/x64/x64_vflags.cpp
    protection/vm/x64/x64_handlers.cpp
    protection/vm/x64/x64_inner_vm.cpp
    protection/vm/x64/x64_inner_vm_wrappers.cpp
    protection/vm/x64/x64_vm_backend.cpp

    # Phase 5: Self-unpacking packer (multi-section XOR + anti-debug + IAT wipe)
    protection/packer/packer_pass.cpp
    protection/packer/rc4.cpp
    protection/packer/stolen_bytes.cpp

    # S2: String protection — scanner / xref / encryptor / runtime emitter / pass
    protection/string/string_scanner.cpp
    protection/string/string_xref_finder.cpp
    protection/string/string_encryptor.cpp
    protection/string/string_decryptor_codegen.cpp
    protection/string/string_protection_pass.cpp

    # Phase 6: Anti-emulation checks — one file per technique
    protection/anti_emulation/check_registry.cpp
    protection/anti_emulation/rdtsc_timing_check.cpp
    protection/anti_emulation/cpuid_hypervisor_check.cpp
    protection/anti_emulation/eflags_reserved_bit_check.cpp

    # Phase 6: Anti-tamper checks — direct syscall + DR sweep
    protection/anti_tamper/hells_gate_resolver.cpp
    protection/anti_tamper/check_registry.cpp
    protection/anti_tamper/hw_breakpoint_check.cpp
    protection/anti_tamper/import_hook_check.cpp
    protection/anti_tamper/self_crc_check.cpp
    protection/anti_tamper/page_protection_check.cpp
    protection/anti_tamper/debug_object_handle_check.cpp
)

# ==============================================================================
# Цель: mxprotector_builder
# ==============================================================================

add_executable(mxprotector_builder ${BUILDER_SOURCES})

target_compile_features(mxprotector_builder PRIVATE cxx_std_23)

target_include_directories(mxprotector_builder PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/external/zydis/include
    ${CMAKE_SOURCE_DIR}/external/zydis/dependencies/zycore/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(mxprotector_builder PRIVATE
    Zydis
)

# MSVC-специфичные флаги
if(MSVC)
    target_compile_options(mxprotector_builder PRIVATE
        /W4
        /utf-8
        /Zc:__cplusplus
        /permissive-
    )
else()
    target_compile_options(mxprotector_builder PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# ==============================================================================
# Установка
# ==============================================================================

install(TARGETS mxprotector_builder
    RUNTIME DESTINATION bin
)
