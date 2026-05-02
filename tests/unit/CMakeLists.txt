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
    hash_opaque_predicate_test.cpp
    veh_int3_trap_test.cpp
    stub_self_hash_test.cpp
    fnv1a_test.cpp
    marker_scanner_test.cpp
    guard_page_layout_test.cpp
    guard_veh_emitter_test.cpp
    guard_decrypt_unit_test.cpp
    guard_tls_installer_test.cpp
    target_info_test.cpp
    pe_parser_pe_type_test.cpp
    section_intent_test.cpp
    layout_policy_test.cpp
    section_emitter_test.cpp
    expansion_sink_test.cpp
    relocation_injector_test.cpp
    pass_applicability_test.cpp
    vm_kernel_safety_test.cpp
    reloc_applier_test.cpp
    driver_cipher_body_test.cpp
    reloc_partition_test.cpp
    dll_characteristics_audit_test.cpp
    section_name_pool_test.cpp
    trace_hints_test.cpp
)

# VM sources needed for VmStackLayout + x64 handler tests and for
# StringProtectionPass --strings=vm lift/generate symbols pulled in by
# the S2c orchestrator.
set(VM_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/virtualization_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/virtualization_pipeline.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/vm_stack_layout.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/vm_lifter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/vm_runtime_gen.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_emitters.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_vflags.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_handlers.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_inner_vm.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_inner_vm_wrappers.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_blob_patcher.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_bytecode_encoder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_entry_stub.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/vm/x64/x64_handler_emitter.cpp
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
    ${CMAKE_SOURCE_DIR}/src/builder/protection/anti_tamper/debug_object_handle_check.cpp
)

# S2 string-protection sources needed for scanner/xref tests (and future
# encryptor/runtime tests as they're added)
set(STRING_PROTECT_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_xref_finder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_encryptor.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_decryptor_codegen.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_protection_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_protection_pipeline.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_candidate_gather.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_artifact_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_section_assembler.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/string/string_section_committer.cpp
)

# Packer sub-module sources needed by individual packer unit tests
# (veh_int3_trap + stub_self_hash for their respective tests) plus the
# full packer-pass chain so pass_applicability_test can instantiate
# PackerPass. Depends on hells_gate_resolver from ANTI_TAMPER_SOURCES
# and the VM_SOURCES for the KSA VM lifter.
set(PACKER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/veh_int3_trap.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/stub_self_hash.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_ksa_vm_lifter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_stub_artifacts.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_stub_patcher.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_tls_finalizer.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_section_encryptor.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/packer_setup.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/cipher_body.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/driver_cipher_body.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/reloc_applier.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/reloc_partition.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/rc4.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/stolen_bytes.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/stub_emitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/packer/tls_callback.cpp
)

# ==============================================================================
# Исходные файлы мутации/обфускации (нужны для линковки)
# ==============================================================================

set(MUTATION_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/mutation_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/instruction_substitution.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/padding_filler.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/rules/opcode_swap_rule.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/rules/direction_flip_rule.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/rules/imm8_negation_rule.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/rules/shift_add_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/rules/semantic_transform_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/rules/inc_dec_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/junk_generator.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/register_reassignment.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/instruction_splitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/overflow/jmp_emit.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/overflow/extend_in_place_sink.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/mutation/overflow/separate_overflow_sink.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/obfuscation_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/opaque_predicates.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/constant_unfolding.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/mba_transform.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/obfuscation/hash_opaque_predicate.cpp
)

# Phase 3: CFF + Assembler
set(CFF_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/x86_code_emitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/cfg_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/section_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/pe_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/pe_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/import_table.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/export_table.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/relocation_table.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/section_emitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/relocation_injector.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/pe/layout/standard_layout.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/core/context.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cfg_flattening_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cfg_flattening_pipeline.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cfg_flattener.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cff_function_source.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cff_relocation_fixup.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cff_safety_filters.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cff_trampoline_section.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/cff_trampoline_writer.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/state_reg_picker.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/dispatcher_gen.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/bogus_flow.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/map_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/cfg/mba_transition_gen.cpp
)

# Analysis module sources needed by analysis-level unit tests (currently
# the marker scanner + trace_hints sidecar serializer — adding more if
# future tests require).
set(ANALYSIS_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/marker_scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/trace_hints.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/analysis/trace_hints_serialize.cpp
)

# CLI helpers needed by CLI-level unit tests (section name pool —
# adding more if future tests require).
set(CLI_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/cli/section_name_pool.cpp
)

# Runtime-guards module sources. The leaf emitters (page layout / VEH /
# decrypt unit / TLS installer) are covered by their own isolated tests.
# The full facade + pipeline chain is linked so pass_applicability_test
# can instantiate `GuardPass`. The TLS installer pulls in the Hell's
# Gate resolver because its body embeds the resolver bytes.
set(GUARD_SOURCES
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_page_layout.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_veh_emitter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_decrypt_unit.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_tls_installer.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_pass.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_pass_pipeline.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_collector.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_decrypt_vm_lifter.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_section_assembler.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_region_finalizer.cpp
    ${CMAKE_SOURCE_DIR}/src/builder/protection/guard/guard_handler_back_patcher.cpp
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
    ${STRING_PROTECT_SOURCES}
    ${PACKER_SOURCES}
    ${ANALYSIS_SOURCES}
    ${CLI_SOURCES}
    ${GUARD_SOURCES})

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
