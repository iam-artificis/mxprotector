/**
 * @file context.hpp
 * @brief [BUILDER] Контекст пайплайна защиты — разделяемое мутабельное состояние.
 *
 * @details ProtectionContext объединяет все данные, необходимые проходам защиты:
 *          PE-образ (PeImage), конфигурацию, найденные маркеры, дизассемблер,
 *          CFG (опционально) и журнал сообщений. Передаётся в каждый IProtectionPass
 *          при выполнении. Проходы читают и модифицируют контекст.
 *
 * @note ProtectionContext владеет PeImage через unique_ptr, дизассемблером через
 *       shared_ptr (разделяется с CfgBuilder и другими модулями).
 *       CFG хранится в optional — строится по необходимости.
 */

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/config/protection_config.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/target/target_info.hpp"

namespace mx {

/**
 * @brief Runtime names of the sections MxProtector adds to the target PE.
 *
 * Names are generated per-build (randomized or hand-picked via --debug-sections)
 * and stored here so that every pass agrees on what to write and what to look
 * for. Later passes reference these when they need to locate sections added
 * by earlier passes (e.g. PackerPass needs to encrypt the VM blob and CFF
 * trampolines without hardcoding .mxvm / .mxprot1).
 */
struct SectionNameMap {
    std::string vm;       ///< Virtualization blob section
    std::string cff;      ///< CFG-flattening trampoline section
    std::string packer;   ///< Self-unpacking stub section
    std::string str;      ///< S2 string-protection section (mx_str_get + trampolines + desc table + ciphertext)
    std::string guard;    ///< Runtime-guards page table (MX_GUARD_BEGIN/END relocated bodies)
};

/**
 * @brief Контекст пайплайна защиты — агрегирует все разделяемые данные.
 *
 * @details Создаётся один раз в main, наполняется данными (PeImage, маркеры,
 *          конфигурация, дизассемблер) и передаётся последовательно в каждый
 *          проход защиты через PassManager.
 *
 *          SOLID (SRP): контекст только хранит данные и предоставляет доступ.
 *          Логика обработки — в проходах (IProtectionPass).
 */
class ProtectionContext final {
public:
    /**
     * @brief Конструктор с обязательными компонентами.
     * @param image PE-образ (владение передаётся).
     * @param config Конфигурация защиты.
     * @param disasm Дизассемблер (разделяемый).
     */
    ProtectionContext(std::unique_ptr<PeImage> image,
                      ProtectionConfig config,
                      std::shared_ptr<analysis::IDisassembler> disasm)
        : image_(std::move(image))
        , config_(std::move(config))
        , disasm_(std::move(disasm))
    {}

    ~ProtectionContext() = default;

    ProtectionContext(const ProtectionContext&) = delete;
    ProtectionContext& operator=(const ProtectionContext&) = delete;
    ProtectionContext(ProtectionContext&&) noexcept = default;
    ProtectionContext& operator=(ProtectionContext&&) noexcept = default;

    // ====================================================================
    // PE-образ
    // ====================================================================

    /// @brief Константный доступ к PE-образу.
    [[nodiscard]] const PeImage& pe_image() const noexcept { return *image_; }

    /// @brief Изменяемый доступ к PE-образу.
    [[nodiscard]] PeImage& pe_image() noexcept { return *image_; }

    // ====================================================================
    // Конфигурация
    // ====================================================================

    /// @brief Константный доступ к конфигурации защиты.
    [[nodiscard]] const ProtectionConfig& config() const noexcept { return config_; }

    /// @brief Изменяемый доступ к конфигурации защиты.
    [[nodiscard]] ProtectionConfig& config() noexcept { return config_; }

    // ====================================================================
    // Маркеры
    // ====================================================================

    /// @brief Константный доступ к маркированным регионам.
    [[nodiscard]] const std::vector<MarkedRegion>& markers() const noexcept { return markers_; }

    /// @brief Изменяемый доступ к маркированным регионам.
    [[nodiscard]] std::vector<MarkedRegion>& markers() noexcept { return markers_; }

    /**
     * @brief Устанавливает список маркированных регионов.
     * @param markers Вектор маркированных регионов.
     */
    void set_markers(std::vector<MarkedRegion> markers) { markers_ = std::move(markers); }

    // ====================================================================
    // Дизассемблер
    // ====================================================================

    /// @brief Константный доступ к дизассемблеру.
    [[nodiscard]] const std::shared_ptr<analysis::IDisassembler>& disassembler() const noexcept {
        return disasm_;
    }

    /// @brief Изменяемый доступ к дизассемблеру.
    [[nodiscard]] std::shared_ptr<analysis::IDisassembler>& disassembler() noexcept {
        return disasm_;
    }

    // ====================================================================
    // Граф потока управления (опциональный)
    // ====================================================================

    /// @brief Проверяет, построен ли CFG.
    [[nodiscard]] bool has_cfg() const noexcept { return cfg_.has_value(); }

    /// @brief Константный доступ к CFG (UB если не построен — проверяйте has_cfg()).
    [[nodiscard]] const analysis::ControlFlowGraph& cfg() const noexcept { return *cfg_; }

    /// @brief Изменяемый доступ к CFG.
    [[nodiscard]] analysis::ControlFlowGraph& cfg() noexcept { return *cfg_; }

    /**
     * @brief Устанавливает CFG.
     * @param cfg Построенный граф потока управления.
     */
    void set_cfg(analysis::ControlFlowGraph cfg) { cfg_ = std::move(cfg); }

    // ====================================================================
    // Target platform (OS × container × arch)
    // ====================================================================

    /// @brief Read-only target descriptor for this build. Set by main()
    ///        after the binary is parsed.
    [[nodiscard]] const target::TargetInfo& target() const noexcept {
        return target_;
    }

    /// @brief Установить дескриптор target платформы.
    void set_target(target::TargetInfo info) noexcept { target_ = info; }

    // ====================================================================
    // Имена добавляемых секций (рандомизированные per-build)
    // ====================================================================

    /// @brief Константный доступ к map имён добавленных MxProtector секций.
    [[nodiscard]] const SectionNameMap& section_names() const noexcept {
        return section_names_;
    }

    /// @brief Изменяемый доступ к map имён.
    [[nodiscard]] SectionNameMap& section_names() noexcept { return section_names_; }

    /**
     * @brief Устанавливает map имён секций.
     */
    void set_section_names(SectionNameMap names) { section_names_ = std::move(names); }

    // ====================================================================
    // Extra TLS callbacks injected by upstream passes
    // ====================================================================

    /**
     * @brief TLS callback absolute VA that an earlier pass registered
     *        for the packer to inherit.
     *
     * Set by `GuardPass::execute` to the runtime VA of the
     * `guard_tls_installer` thunk (which installs the runtime-guards
     * VEH at `DLL_PROCESS_ATTACH`). `PackerPass::execute` reads this
     * during its TLS callback array build-up and — if non-zero —
     * appends the VA to the array right after its own anti-debug
     * callback so every guarded binary gets the VEH installed before
     * user code runs.
     *
     * A value of zero means "no extra callback" — normal pipeline
     * path when no `MX_GUARD_BEGIN` markers exist.
     *
     * Only ONE extra callback slot exists on purpose — the
     * runtime-guards design puts every late-binding initialisation
     * behind a single installer thunk, which keeps the packer's
     * TLS directory shape deterministic (exactly
     * `1 + has_guard + existing_user_cbs + NULL` entries) and
     * avoids the polymorphism / sizing churn that a variable-length
     * callback list would add.
     */
    [[nodiscard]] uint64_t extra_tls_callback_va() const noexcept {
        return extra_tls_callback_va_;
    }

    void set_extra_tls_callback_va(uint64_t va) noexcept {
        extra_tls_callback_va_ = va;
    }

    // ====================================================================
    // Журнал сообщений
    // ====================================================================

    /// @brief Константный доступ к журналу сообщений.
    [[nodiscard]] const std::vector<std::string>& log_messages() const noexcept {
        return log_messages_;
    }

    /**
     * @brief Добавляет сообщение в журнал.
     * @param message Текст сообщения.
     */
    void log(std::string_view message) {
        log_messages_.emplace_back(message);
    }

    /**
     * @brief Добавляет форматированное сообщение в журнал.
     * @tparam Args Типы аргументов форматирования.
     * @param fmt Строка формата.
     * @param args Аргументы.
     */
    template <typename... Args>
    void log_fmt(std::format_string<Args...> fmt, Args&&... args) {
        log_messages_.push_back(std::format(fmt, std::forward<Args>(args)...));
    }

private:
    std::unique_ptr<PeImage>                         image_;        ///< PE-образ
    ProtectionConfig                                 config_;       ///< Конфигурация
    std::vector<MarkedRegion>                        markers_;      ///< Маркированные регионы
    std::shared_ptr<analysis::IDisassembler>         disasm_;       ///< Дизассемблер
    std::optional<analysis::ControlFlowGraph>        cfg_;          ///< CFG (опционально)
    target::TargetInfo                               target_ =
        target::TargetInfo::windows_pe_x64();                       ///< Target platform
    SectionNameMap                                   section_names_;///< Имена добавленных секций
    uint64_t                                         extra_tls_callback_va_ = 0;  ///< GuardPass → PackerPass TLS callback hand-off
    std::vector<std::string>                         log_messages_; ///< Журнал
};

} // namespace mx
