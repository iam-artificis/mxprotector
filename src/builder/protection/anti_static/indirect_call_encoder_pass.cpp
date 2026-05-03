/**
 * @file indirect_call_encoder_pass.cpp
 * @brief Implementation — see header.
 *
 * The pass operates in three phases:
 *
 *   1. **Discovery** — walk every code section with Zydis, record
 *      every `call rel32` whose target lands inside a code
 *      section we control.
 *   2. **Layout** — for each discovered site, pick an encoder at
 *      random and reserve enough bytes in the stub buffer for its
 *      stub. Stubs are laid back-to-back; their RVAs are not
 *      known until the section is added below.
 *   3. **Emission** — add the stub section via `SectionEmitter`
 *      (which assigns a final RVA), emit each stub at its
 *      reserved offset, and rewrite the original `call rel32`
 *      disp32 so it points at the stub.
 *
 * Reference patching: each emitted stub's `lea rax, [rip+disp32]`
 * carries the standard rel32 displacement. The chaos-shuffle
 * `CodeReferenceScanner` discovers the LEA along with every other
 * RIP-relative instruction and keeps the disp32 in sync if chaos
 * later moves the target — no new scanner needed for the shipped
 * encoders.
 */

#include "mxprotector/protection/anti_static/indirect_call_encoder_pass.hpp"

#include <algorithm>
#include <cstring>
#include <utility>
#include <variant>
#include <vector>

#include <Zydis/Zydis.h>

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/anti_static/encoder_registry.hpp"

namespace mx::protection::anti_static {

namespace {

/// One discovered `call rel32` site that is eligible for rewriting.
struct CallSite {
    Rva                          call_rva;       ///< RVA of the `0xE8` byte.
    Rva                          target_rva;     ///< RVA of the call's original target.
    const IIndirectCallEncoder*  encoder = nullptr;
    std::uint32_t                stub_offset = 0; ///< Offset inside the stub buffer.
};

/// `true` when `rva` lands inside any code-flagged section's
/// `[virtual_address, virtual_address + virtual_size)` range.
[[nodiscard]] bool is_code_rva(const PeImage& image, Rva rva) noexcept {
    for (const auto& s : image.sections()) {
        if (!s.is_code()) continue;
        if (rva >= s.virtual_address &&
            rva <  s.virtual_address + s.virtual_size)
        {
            return true;
        }
    }
    return false;
}

/// One `[begin, end)` byte range carried by a `.pdata`
/// `RUNTIME_FUNCTION` entry. Walking the instruction stream from
/// `begin` keeps Zydis aligned with real instruction boundaries
/// — far safer than a section-wide byte-by-byte walk that can
/// fall out of alignment on any decode failure and start
/// interpreting operand bytes as opcodes.
struct PdataRange {
    Rva begin;
    Rva end;
};

[[nodiscard]] std::vector<PdataRange> read_pdata_ranges(
    const PeImage& image)
{
    std::vector<PdataRange> ranges;

    Rva           pdata_rva  = 0;
    std::uint32_t pdata_size = 0;
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, ::mx::pe::IMAGE_NT_HEADERS64>) {
            if (::mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    ::mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                pdata_rva  = dir.VirtualAddress;
                pdata_size = dir.Size;
            }
        }
    }, image.nt_headers());
    if (pdata_rva == 0 || pdata_size < 12) return ranges;

    const auto* sec = image.section_by_rva(pdata_rva);
    if (sec == nullptr) return ranges;
    const auto off = pdata_rva - sec->virtual_address;
    if (off + pdata_size > sec->data.size()) return ranges;

    const std::uint8_t* dir = sec->data.data() + off;
    const std::uint32_t entry_count = pdata_size / 12;
    ranges.reserve(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint32_t b = 0, e = 0;
        std::memcpy(&b, dir + i * 12 + 0, sizeof(b));
        std::memcpy(&e, dir + i * 12 + 4, sizeof(e));
        if (b == 0 && e == 0)              continue;
        if (e <= b)                        continue;
        ranges.push_back({static_cast<Rva>(b), static_cast<Rva>(e)});
    }
    return ranges;
}

/// Walk one `.pdata` range as a clean instruction stream. Aborts
/// the function on the first Zydis decode failure rather than
/// resyncing — `.pdata`-bounded code is supposed to be valid
/// from `begin` onwards, so a decode error here means the
/// function was already mutated and we cannot reason about it
/// safely.
void discover_call_sites_in_function(
    ZydisDecoder&                  decoder,
    const PeImage&                 image,
    const ::mx::pe::SectionInfo&   sec,
    const PdataRange&              fn,
    std::vector<CallSite>&         out)
{
    if (fn.begin < sec.virtual_address) return;
    const auto sec_end = sec.virtual_address + sec.virtual_size;
    if (fn.end > sec_end) return;
    const auto fn_off = fn.begin - sec.virtual_address;
    const auto fn_size = static_cast<std::size_t>(fn.end - fn.begin);
    if (fn_off + fn_size > sec.data.size()) return;

    const std::uint8_t* buf = sec.data.data() + fn_off;
    std::size_t offset = 0;
    while (offset < fn_size) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, buf + offset, fn_size - offset, &insn, ops)))
        {
            return; // bail — see comment above
        }

        // We only encode `call rel32` (opcode `E8`). Indirect
        // calls (`call r/m`, `FF /2`) are already opaque to a
        // call-graph walker, so the obfuscation gain would be
        // marginal and the rewriting much trickier.
        if (insn.mnemonic == ZYDIS_MNEMONIC_CALL && insn.length == 5 &&
            buf[offset] == 0xE8)
        {
            const Rva call_rva  = static_cast<Rva>(fn.begin + offset);
            const Rva next_inst = static_cast<Rva>(call_rva + 5);
            std::int32_t rel32 = 0;
            std::memcpy(&rel32, buf + offset + 1, sizeof(rel32));
            const std::int64_t target_signed =
                static_cast<std::int64_t>(next_inst) +
                static_cast<std::int64_t>(rel32);
            if (target_signed >= 0) {
                const auto target_rva = static_cast<Rva>(target_signed);
                if (target_rva != call_rva &&
                    is_code_rva(image, target_rva))
                {
                    out.push_back(CallSite{
                        .call_rva   = call_rva,
                        .target_rva = target_rva,
                    });
                }
            }
        }

        offset += insn.length;
    }
}

/// Gather all eligible call sites by walking only `.pdata`-bounded
/// function ranges. Code outside `.pdata` (link-time thunks,
/// pad bytes) cannot be reliably decoded byte-by-byte and is
/// skipped — encoding rewrites there would risk corrupting
/// instructions whose boundaries we cannot trust.
[[nodiscard]] std::vector<CallSite> discover_all_call_sites(const PeImage& image) {
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder,
                     ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    const auto fns = read_pdata_ranges(image);

    std::vector<CallSite> sites;
    sites.reserve(fns.size() * 2);
    for (const auto& sec : image.sections()) {
        if (!sec.is_code()) continue;
        for (const auto& fn : fns) {
            if (fn.begin < sec.virtual_address) continue;
            if (fn.end   > sec.virtual_address + sec.virtual_size) continue;
            discover_call_sites_in_function(decoder, image, sec, fn, sites);
        }
    }
    return sites;
}

/// Locate the writable section that owns `rva`; returns nullptr
/// when the RVA falls outside every section.
[[nodiscard]] ::mx::pe::SectionInfo* section_owning(PeImage& image, Rva rva) noexcept {
    for (auto& s : image.sections()) {
        if (rva >= s.virtual_address &&
            rva <  s.virtual_address + s.virtual_size)
        {
            return &s;
        }
    }
    return nullptr;
}

/// Patch the disp32 of an `E8` `call` at `call_rva` so it now
/// points at `stub_rva`. Returns `false` when the call site or
/// its disp32 slot fall outside any section's writable bytes.
[[nodiscard]] bool rewrite_call_target(
    PeImage& image, Rva call_rva, Rva stub_rva)
{
    auto* sec = section_owning(image, call_rva);
    if (sec == nullptr) return false;
    const auto off = call_rva - sec->virtual_address;
    if (off + 5 > sec->data.size()) return false;
    const std::int64_t disp =
        static_cast<std::int64_t>(stub_rva) -
        static_cast<std::int64_t>(call_rva + 5);
    const auto rel32 = static_cast<std::int32_t>(disp);
    std::memcpy(sec->data.data() + off + 1, &rel32, sizeof(rel32));
    return true;
}

} // anonymous namespace

bool IndirectCallEncoderPass::is_applicable(
    const ProtectionContext& ctx) const noexcept
{
    if (!ctx.config().enable_indirect_calls) return false;
    if (!ctx.target().is_windows_pe_x64())   return false;
    return true;
}

MxStatus IndirectCallEncoderPass::execute(ProtectionContext& ctx) {
    auto sites = discover_all_call_sites(ctx.pe_image());
    if (sites.empty()) {
        ctx.log("IndirectCallEncoderPass: no eligible call sites — skipping");
        return {};
    }
    ctx.log_fmt("IndirectCallEncoderPass: discovered {} call sites",
                sites.size());

    auto registry = make_default_registry();
    if (registry.size() == 0) {
        ctx.log("IndirectCallEncoderPass: registry is empty — skipping");
        return {};
    }

    Randomizer rng;

    // ---- Layout: pick encoder per site, sum stub sizes ------------
    std::uint32_t total_stub_bytes = 0;
    for (auto& site : sites) {
        const auto* enc = registry.pick(rng);
        if (enc == nullptr) continue;
        site.encoder     = enc;
        site.stub_offset = total_stub_bytes;
        total_stub_bytes += enc->stub_size();
    }
    if (total_stub_bytes == 0) return {};

    // ---- Reserve a fresh section for the stubs --------------------
    std::vector<std::uint8_t> section_bytes(total_stub_bytes, 0xCC);
    SectionManager      mgr{ctx.pe_image()};
    pe::SectionEmitter  emitter{mgr, ctx.layout_policy()};
    auto add = emitter.append_section(
        ".callstub",
        ByteView{section_bytes.data(), section_bytes.size()},
        pe::SectionIntent{
            pe::SectionContentType::code,
            pe::SectionPermissions::rx,
        });
    if (!add) {
        ctx.log_fmt("IndirectCallEncoderPass: section emit failed: {}",
                    add.error().message());
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            "IndirectCallEncoderPass: failed to allocate .callstub"));
    }
    const auto section_index = *add;
    auto& stub_section = ctx.pe_image().sections()[section_index];
    const Rva section_rva = stub_section.virtual_address;
    ctx.log_fmt("IndirectCallEncoderPass: .callstub @ RVA 0x{:08X} ({} bytes)",
                section_rva, total_stub_bytes);

    // ---- Emit stubs + rewrite calls -------------------------------
    std::uint32_t emitted = 0;
    std::uint32_t rewrote = 0;
    for (const auto& site : sites) {
        if (site.encoder == nullptr) continue;
        const Rva stub_rva = static_cast<Rva>(section_rva + site.stub_offset);
        const auto stub = site.encoder->emit(stub_rva, site.target_rva, rng);
        if (stub.bytes.size() != site.encoder->stub_size()) continue;
        if (site.stub_offset + stub.bytes.size() > stub_section.data.size()) continue;

        std::memcpy(stub_section.data.data() + site.stub_offset,
                    stub.bytes.data(), stub.bytes.size());
        ++emitted;

        if (rewrite_call_target(ctx.pe_image(), site.call_rva, stub_rva)) {
            ++rewrote;
        }
    }

    ctx.log_fmt("IndirectCallEncoderPass: emitted {} stubs, "
                "rewrote {} call sites",
                emitted, rewrote);
    return {};
}

} // namespace mx::protection::anti_static
