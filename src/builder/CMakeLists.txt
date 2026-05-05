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
    cli/main_helpers.cpp
    cli/section_name_pool.cpp

    # Core (out-of-line context constructor — owns the layout policy)
    core/context.cpp

    # PE-модуль
    pe/pe_image.cpp
    pe/pe_parser.cpp
    pe/pe_builder.cpp
    pe/section_manager.cpp
    pe/import_table.cpp
    pe/export_table.cpp
    pe/relocation_table.cpp
    pe/section_emitter.cpp
    pe/relocation_injector.cpp
    pe/layout/standard_layout.cpp
    pe/layout/chaos_layout.cpp
    pe/layout/chaos_section_merger.cpp
    pe/layout/chaos_reference_collector.cpp
    pe/layout/chaos_atom_source_registry.cpp
    pe/refmap/rva_remapper.cpp
    pe/refmap/code_reference_scanner.cpp
    pe/refmap/structure_reference_scanner.cpp
    pe/refmap/reloc_absolute_va_scanner.cpp
    pe/refmap/import_descriptor_scanner.cpp
    pe/refmap/export_directory_scanner.cpp
    pe/refmap/delay_import_descriptor_scanner.cpp
    pe/refmap/tls_directory_scanner.cpp
    pe/refmap/load_config_directory_scanner.cpp
    pe/refmap/load_config_table_walker.cpp
    pe/refmap/resource_directory_scanner.cpp
    pe/refmap/reference_patcher.cpp
    pe/refmap/reloc_rebuilder.cpp
    pe/refmap/unwind_info_reference_scanner.cpp
    pe/refmap/switch_jump_table_scanner.cpp
    pe/refmap/vm_call_pop_trampoline_scanner.cpp
    pe/refmap/obfuscated_jt_scanner.cpp
    pe/refmap/reference_overlap_filter.cpp
    pe/chaos/chunk_planner.cpp
    pe/chaos/section_movable_block_atom_source.cpp
    pe/chaos/self_crc_refinalizer.cpp
    pe/chaos/handler_table_integrity_refinalizer.cpp
    pe/chaos/fall_through_jmp_filler.cpp
    protection/anti_static/encoder_registry.cpp
    protection/anti_static/encoders/add_offset_encoder.cpp
    protection/anti_static/encoders/xor_chain_encoder.cpp
    protection/anti_static/encoders/sub_neg_encoder.cpp
    protection/anti_static/encoders/add_chain4_encoder.cpp
    protection/anti_static/encoders/xor_chain4_encoder.cpp
    protection/anti_static/encoders/interleaved_add_sub_encoder.cpp
    protection/anti_static/encoders/add_offset_unbalanced_encoder.cpp
    protection/anti_static/indirect_call_encoder_pass.cpp
    pe/chaos/chaos_shuffler.cpp
    pe/chaos/load_config_pin_helper.cpp
    pe/chaos/atom.cpp
    pe/chaos/basic_block_atom_source.cpp
    pe/chaos/sub_block_planner.cpp
    pe/chaos/pdata_chain_emitter.cpp
    pe/chaos/chain_pdata_reader.cpp
    pe/chaos/chain_blob_builder.cpp
    pe/chaos/mxpdat_builder.cpp
    pe/chaos/instruction_atom_source.cpp
    pe/chaos/instruction_cluster_atom_source.cpp
    pe/chaos/string_atom_source.cpp
    pe/chaos/import_atom_source.cpp
    pe/chaos/pdata_atom_source.cpp
    pe/chaos/reloc_atom_source.cpp
    pe/chaos/load_config_atom_source.cpp
    pe/chaos/tls_atom_source.cpp
    pe/chaos/export_atom_source.cpp
    pe/chaos/resource_atom_source.cpp
    pe/chaos/debug_atom_source.cpp
    pe/chaos/delay_import_atom_source.cpp
    pe/chaos/volatile_metadata_atom_source.cpp
    pe/chaos/data_section_pin_atom_source.cpp
    pe/chaos/code_gap_pin_atom_source.cpp
    pe/chaos/function_atom_source.cpp
    pe/chaos/atomic_chunk_planner.cpp

    # Модуль анализа
    analysis/zydis_disassembler.cpp
    analysis/cfg_builder.cpp
    analysis/marker_scanner.cpp
    analysis/trace_hints.cpp
    analysis/trace_hints_serialize.cpp

    # Инфраструктура защиты
    protection/pass_manager.cpp

    # Фаза 2: Мутация
    protection/mutation/mutation_pass.cpp
    protection/mutation/mutation_engine.cpp
    protection/mutation/instruction_substitution.cpp
    protection/mutation/padding_filler.cpp
    protection/mutation/overflow/jmp_emit.cpp
    protection/mutation/overflow/extend_in_place_sink.cpp
    protection/mutation/overflow/separate_overflow_sink.cpp
    protection/mutation/overflow/grow_source_section_sink.cpp
    protection/mutation/overflow/fallback_expansion_sink.cpp
    protection/mutation/rules/opcode_swap_rule.cpp
    protection/mutation/rules/direction_flip_rule.cpp
    protection/mutation/rules/imm8_negation_rule.cpp
    protection/mutation/rules/shift_add_rules.cpp
    protection/mutation/rules/semantic_transform_rules.cpp
    protection/mutation/rules/inc_dec_rules.cpp
    protection/mutation/register_reassignment.cpp
    protection/mutation/junk_generator.cpp

    # Фаза 2: Обфускация
    protection/obfuscation/obfuscation_pass.cpp
    protection/obfuscation/opaque_predicates.cpp
    protection/obfuscation/constant_unfolding.cpp
    protection/obfuscation/mba_transform.cpp
    protection/obfuscation/hash_opaque_predicate.cpp

    # Phase 3: Mutation Strengthening
    protection/mutation/instruction_splitter.cpp

    # Phase 3: Assembler / Code Emitter
    analysis/x86_code_emitter.cpp

    # Phase 3: CFG Flattening
    protection/cfg/cfg_flattening_pass.cpp
    protection/cfg/cfg_flattening_pipeline.cpp
    protection/cfg/cfg_flattener.cpp
    protection/cfg/cff_function_source.cpp
    protection/cfg/cff_relocation_fixup.cpp
    protection/cfg/cff_safety_filters.cpp
    protection/cfg/cff_trampoline_section.cpp
    protection/cfg/cff_trampoline_writer.cpp
    protection/cfg/state_reg_picker.cpp
    protection/cfg/dispatcher_gen.cpp
    protection/cfg/bogus_flow.cpp
    protection/cfg/map_parser.cpp
    protection/cfg/mba_transition_gen.cpp

    # Phase 4: Virtualization (VM engine)
    protection/vm/vm_lifter.cpp
    protection/vm/vm_stack_layout.cpp
    protection/vm/vm_runtime_gen.cpp
    protection/vm/virtualization_pass.cpp
    protection/vm/virtualization_pipeline.cpp

    # Runtime guards — MX_GUARD_BEGIN/END relocation + VEH dispatcher
    protection/guard/guard_pass.cpp
    protection/guard/guard_pass_pipeline.cpp
    protection/guard/guard_collector.cpp
    protection/guard/guard_decrypt_vm_lifter.cpp
    protection/guard/guard_section_assembler.cpp
    protection/guard/guard_region_finalizer.cpp
    protection/guard/guard_handler_back_patcher.cpp
    protection/guard/guard_page_layout.cpp
    protection/guard/guard_veh_emitter.cpp
    protection/guard/guard_decrypt_unit.cpp
    protection/guard/guard_tls_installer.cpp

    # Phase 4: x64 VM backend (split out of vm_runtime_gen.cpp)
    protection/vm/x64/x64_emitters.cpp
    protection/vm/x64/x64_vflags.cpp
    protection/vm/x64/x64_handlers.cpp
    protection/vm/x64/x64_inner_vm.cpp
    protection/vm/x64/x64_inner_vm_wrappers.cpp
    protection/vm/x64/x64_blob_patcher.cpp
    protection/vm/x64/x64_bytecode_encoder.cpp
    protection/vm/x64/x64_entry_stub.cpp
    protection/vm/x64/x64_handler_emitter.cpp
    protection/vm/x64/x64_vm_backend.cpp

    # Phase 5: Self-unpacking packer (multi-section XOR + anti-debug + IAT wipe)
    protection/packer/packer_pass.cpp
    protection/packer/packer_ksa_vm_lifter.cpp
    protection/packer/packer_stub_artifacts.cpp
    protection/packer/packer_stub_patcher.cpp
    protection/packer/packer_tls_finalizer.cpp
    protection/packer/packer_section_encryptor.cpp
    protection/packer/packer_setup.cpp
    protection/packer/cipher_body.cpp
    protection/packer/driver_cipher_body.cpp
    protection/packer/reloc_applier.cpp
    protection/packer/reloc_partition.cpp
    protection/packer/rc4.cpp
    protection/packer/stolen_bytes.cpp
    protection/packer/stub_emitter.cpp
    protection/packer/stub_self_hash.cpp
    protection/packer/tls_callback.cpp
    protection/packer/veh_int3_trap.cpp

    # S2: String protection — scanner / xref / encryptor / runtime emitter / pass
    protection/string/string_scanner.cpp
    protection/string/string_xref_finder.cpp
    protection/string/string_encryptor.cpp
    protection/string/string_decryptor_codegen.cpp
    protection/string/string_protection_pass.cpp
    protection/string/string_protection_pipeline.cpp
    protection/string/string_candidate_gather.cpp
    protection/string/string_artifact_builder.cpp
    protection/string/string_section_assembler.cpp
    protection/string/string_section_committer.cpp

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
