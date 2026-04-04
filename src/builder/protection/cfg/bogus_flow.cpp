/**
 * @file bogus_flow.cpp
 * @brief [BUILDER] Реализация генератора ложного потока управления.
 *
 * @details Создаёт bogus-блоки: opaque predicate + junk code.
 *          Always-true предикат обеспечивает, что junk-код никогда не выполняется,
 *          но статический анализатор не может это определить.
 *
 *          Для каждого bogus-блока:
 *          1. Генерируется opaque predicate (always-true JCC).
 *          2. True-ветвь JCC перескакивает мусорный код.
 *          3. False-ветвь (dead) содержит реалистичный junk-код.
 *          4. После junk — безусловный JMP обратно в диспетчер (или INT3).
 */

#include "mxprotector/protection/cfg/bogus_flow.hpp"

#include <algorithm>

namespace mx {

BogusFlowGenerator::BogusFlowGenerator(Architecture arch)
    : arch_(arch)
    , pred_gen_(arch)
    , junk_gen_(arch)
{}

BogusBlock BogusFlowGenerator::generate(uint32_t junk_size, Randomizer& rng) {
    BogusBlock result;

    if (junk_size < 4) junk_size = 4;
    if (junk_size > 64) junk_size = 64;

    auto predicate = pred_gen_.generate_always_true(rng, 0);
    if (predicate.code.empty()) {
        return result;
    }

    // Patch the JCC offset to skip over the junk code
    if (predicate.true_branch_offset + 1 < predicate.code.size()) {
        if (junk_size <= 127) {
            predicate.code[predicate.true_branch_offset + 1] =
                static_cast<uint8_t>(junk_size);
        } else {
            // For larger junk, we'd need JCC near (6-byte form).
            // For now, clamp junk size to fit in rel8.
            junk_size = 127;
            predicate.code[predicate.true_branch_offset + 1] =
                static_cast<uint8_t>(junk_size);
        }
    }

    result.predicate_code = std::move(predicate.code);

    // Generate junk code for the dead path
    result.junk_code = junk_gen_.generate(junk_size, rng);

    result.total_size = static_cast<uint32_t>(
        result.predicate_code.size() + result.junk_code.size());

    return result;
}

std::vector<BogusBlock> BogusFlowGenerator::generate_for_function(
    uint32_t block_count,
    double bogus_probability,
    Randomizer& rng)
{
    std::vector<BogusBlock> results;
    results.reserve(block_count);

    for (uint32_t i = 0; i < block_count; ++i) {
        if (rng.next_bool(bogus_probability)) {
            const auto junk_size = rng.next_range(8, 32);
            results.push_back(generate(junk_size, rng));
        } else {
            results.emplace_back();
        }
    }

    return results;
}

} // namespace mx
