/**
 * @file load_config_field_offsets.hpp
 * @brief Hand-encoded byte offsets inside `IMAGE_LOAD_CONFIG_DIRECTORY64`.
 *
 * The `IMAGE_LOAD_CONFIG_DIRECTORY64` struct grew across SDK
 * versions, so the only stable contract is "offset of field X is N
 * bytes from the start of the struct." We bind those offsets here as
 * `constexpr` constants and consume them from `load_config_directory_
 * scanner.cpp` and `load_config_table_walker.cpp`.
 *
 * Internal to the refmap module — not part of the public include
 * surface.
 */

#pragma once

#include <cstdint>

namespace mx::pe::refmap::lcfg {

constexpr std::uint32_t kOffSize                            = 0;

constexpr std::uint32_t kOffSEHandlerTable                  = 96;
constexpr std::uint32_t kOffSEHandlerCount                  = 104;

constexpr std::uint32_t kOffGuardCFFunctionTable            = 128;
constexpr std::uint32_t kOffGuardCFFunctionCount            = 136;
constexpr std::uint32_t kOffGuardFlags                      = 144;

constexpr std::uint32_t kOffGuardAddressTakenIatEntryTable  = 160;
constexpr std::uint32_t kOffGuardAddressTakenIatEntryCount  = 168;
constexpr std::uint32_t kOffGuardLongJumpTargetTable        = 176;
constexpr std::uint32_t kOffGuardLongJumpTargetCount        = 184;

constexpr std::uint32_t kOffGuardEHContinuationTable        = 264;
constexpr std::uint32_t kOffGuardEHContinuationCount        = 272;

} // namespace mx::pe::refmap::lcfg
