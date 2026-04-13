/**
 * @file strings.hpp
 * @brief [SDK] Compile-time string protection — strong scope-bound variant.
 *
 * MxProtector's S1 string protection: header-only, constexpr-encrypted
 * literals that decrypt into a stack buffer at first access and wipe
 * themselves when the holder goes out of scope. No plaintext bytes ever
 * appear in `.rdata`; no decoded copy outlives the holder.
 *
 * ### Threat model
 *
 * The realistic adversary runs `strings`, dumps the live process with
 * Process Hacker / Scylla, and chases plaintext patterns through IDA.
 * MX_STR defeats:
 *
 *  - **`strings` and static scans of `.rdata`**: encrypted bytes are
 *    woven into the call-site instruction stream as `mov`-immediates;
 *    they never sit contiguously anywhere statically.
 *
 *  - **Process dump after the holder dies**: the destructor zeros the
 *    stack buffer via `volatile` stores, so dead-store elimination
 *    cannot remove the wipe. The plaintext is gone before the next
 *    statement.
 *
 *  - **Mass exfiltration via a single decoder**: every call site has
 *    its own per-byte keystream derived from
 *    `FNV-1a(__FILE__) ^ __LINE__ ^ __COUNTER__`. Reverse-engineering
 *    one site reveals nothing about any other.
 *
 *  - **Constant folding by the optimiser**: the cipher bytes are
 *    pushed through a `volatile` local before the decryption reads
 *    them, so MSVC cannot prove the loaded value is the same as the
 *    constexpr-known stored value. Volatile semantics force the
 *    decryption to materialise at runtime, byte by byte.
 *
 * It does NOT defeat:
 *
 *  - **Live debuggers**: once attached, the attacker observes the
 *    decoded buffer between `MxString` construction and destruction.
 *    Use VM-protected decoders (S4) for that threat.
 *
 *  - **Memory scanning during the holder's lifetime**: the decoded
 *    buffer is on the stack and exists until the destructor fires.
 *    Keep MxString lifetimes short — pass it to one consumer and let
 *    it die.
 *
 * ### Usage
 *
 * @code
 * void connect() {
 *     auto host = MX_STR("license.example.com");   // scope-bound holder
 *     auto path = MX_WSTR(L"/api/v1/check");
 *     http_get(host, path);
 *     // host / path destructors run here, buffers zeroed
 * }
 * @endcode
 *
 * **Always bind the result to a named variable.** The holder is
 * non-copyable and non-movable; that helps catch accidental dangling
 * use, but C++17 mandatory copy elision still allows constructing a
 * temporary inside a call. Do not do this:
 *
 * @code
 * http_get(MX_STR("license.example.com"));   // ← dangling at semicolon
 * @endcode
 *
 * The buffer is zeroed at the end of the full expression — the callee
 * gets a pointer to garbage if it stores it for any later read.
 *
 * ### Per-byte encryption
 *
 * Each character is encoded with a 3-op chain whose three sub-keys
 * derive from a 64-bit splitmix-style mix of the call-site key and
 * the byte position:
 *
 *     enc[i] = rol_w( ((plain[i] ^ k1[i]) + k2[i]) , k3[i] )
 *     plain[i] = ( ror_w(enc[i], k3[i]) - k2[i] ) ^ k1[i]
 *
 * where `w` is the bit width of the character type (8 for `char`,
 * 16 for `wchar_t` on Windows). Three independent sub-keys × per-byte
 * position derivation × different shift amounts means every byte
 * decodes via a different formula, so a reverser cannot read off "the
 * decoder" — they have to reconstruct each byte's micro-circuit.
 *
 * The macro `MX_STR(LIT)` packages the encryption into an inline
 * lambda so each call site has its own constexpr cipher table and its
 * own per-call key derived from `__FILE__ × __LINE__ × __COUNTER__`.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

#if defined(_MSC_VER)
#  define MX_SDK_FORCE_INLINE __forceinline
#else
#  define MX_SDK_FORCE_INLINE inline __attribute__((always_inline))
#endif

namespace mx::sdk {

namespace detail {

// ----------------------------------------------------------------------------
// Compile-time key mixing
// ----------------------------------------------------------------------------

/// FNV-1a 64-bit hash of a null-terminated string. Used to fold the file
/// path into the per-call-site key so two sites in different files with
/// the same line and counter still get different keys.
[[nodiscard]] constexpr uint64_t fnv1a64(const char* s) noexcept {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; s[i] != '\0'; ++i) {
        h ^= static_cast<uint64_t>(static_cast<unsigned char>(s[i]));
        h *= 1099511628211ULL;
    }
    return h;
}

/// Per-call-site key. Three orthogonal compile-time inputs are folded
/// together so that adding a comment or moving code shifts the key:
///   - file path (FNV-1a) — covers cross-file collisions
///   - line number — covers same-file moves
///   - __COUNTER__ value — disambiguates multiple uses on the same line
[[nodiscard]] constexpr uint64_t call_site_key(
    const char* file, uint32_t line, uint32_t counter) noexcept
{
    uint64_t h = fnv1a64(file);
    h ^= static_cast<uint64_t>(line) * 0x9E3779B97F4A7C15ULL;
    h ^= static_cast<uint64_t>(counter + 1) * 0xBF58476D1CE4E5B9ULL;
    // splitmix64 finalizer — diffuses the low bits across the full word
    h ^= h >> 30;
    h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27;
    h *= 0x94D049BB133111EBULL;
    h ^= h >> 31;
    return h;
}

/// Per-byte sub-key derivation. Three "slots" (0, 1, 2) give us the
/// three independent sub-keys k1/k2/k3 used by the 3-op chain. The
/// formula is splitmix-style mixing of the base key, byte position,
/// and slot index. Output is a `CharT`-sized value, so the same code
/// path drives both `char` (uint8) and `wchar_t` (uint16 on Windows)
/// encryption.
template <typename CharT>
[[nodiscard]] constexpr CharT byte_subkey(
    uint64_t base, size_t pos, uint32_t slot) noexcept
{
    using U = std::make_unsigned_t<CharT>;
    uint64_t h = base;
    h ^= static_cast<uint64_t>(pos + 1) * 0x9E3779B97F4A7C15ULL;
    h ^= static_cast<uint64_t>(slot + 1) * 0xC6BC279692B5C323ULL;
    h ^= h >> 30;
    h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27;
    h *= 0x94D049BB133111EBULL;
    h ^= h >> 31;
    return static_cast<CharT>(static_cast<U>(h));
}

/// Bit width of `CharT`. `char` → 8, `wchar_t` → 16 (Windows) or 32 (Unix).
template <typename CharT>
inline constexpr int kCharBits = static_cast<int>(sizeof(CharT) * 8);

/// Compile-time width-aware rotate-left. `n` is masked into [0, bits-1].
template <typename CharT>
[[nodiscard]] constexpr CharT rol_w(CharT v, unsigned n) noexcept {
    using U = std::make_unsigned_t<CharT>;
    constexpr unsigned bits = static_cast<unsigned>(kCharBits<CharT>);
    n &= (bits - 1);
    if (n == 0) return v;
    const U u = static_cast<U>(v);
    return static_cast<CharT>(
        static_cast<U>((u << n) | (u >> (bits - n))));
}

/// Compile-time width-aware rotate-right.
template <typename CharT>
[[nodiscard]] constexpr CharT ror_w(CharT v, unsigned n) noexcept {
    using U = std::make_unsigned_t<CharT>;
    constexpr unsigned bits = static_cast<unsigned>(kCharBits<CharT>);
    n &= (bits - 1);
    if (n == 0) return v;
    const U u = static_cast<U>(v);
    return static_cast<CharT>(
        static_cast<U>((u >> n) | (u << (bits - n))));
}

/// Encode one character at position `pos` with the 3-op chain:
///     enc = rol_w( ((plain ^ k1) + k2), k3 )
template <typename CharT>
[[nodiscard]] constexpr CharT encrypt_unit(
    CharT plain, size_t pos, uint64_t key) noexcept
{
    const CharT k1 = byte_subkey<CharT>(key, pos, 0);
    const CharT k2 = byte_subkey<CharT>(key, pos, 1);
    const unsigned k3 = static_cast<unsigned>(byte_subkey<CharT>(key, pos, 2));
    using U = std::make_unsigned_t<CharT>;
    const U after_xor = static_cast<U>(plain) ^ static_cast<U>(k1);
    const U after_add = static_cast<U>(after_xor + static_cast<U>(k2));
    return rol_w<CharT>(static_cast<CharT>(after_add), k3);
}

/// Decode one character — inverse of `encrypt_unit`. Mirrors the
/// 3-op chain in reverse order. Used by the runtime constructor body.
template <typename CharT>
MX_SDK_FORCE_INLINE constexpr CharT decrypt_unit(
    CharT enc, size_t pos, uint64_t key) noexcept
{
    const CharT k1 = byte_subkey<CharT>(key, pos, 0);
    const CharT k2 = byte_subkey<CharT>(key, pos, 1);
    const unsigned k3 = static_cast<unsigned>(byte_subkey<CharT>(key, pos, 2));
    using U = std::make_unsigned_t<CharT>;
    const CharT rotated = ror_w<CharT>(enc, k3);
    const U after_sub = static_cast<U>(static_cast<U>(rotated) - static_cast<U>(k2));
    return static_cast<CharT>(after_sub ^ static_cast<U>(k1));
}

/// Consteval encoder over a literal. Returns the cipher as a
/// `std::array` so the call site can place it in constexpr storage.
template <typename CharT, size_t N>
[[nodiscard]] consteval std::array<CharT, N> encrypt_literal(
    const CharT (&plain)[N], uint64_t key) noexcept
{
    std::array<CharT, N> out{};
    for (size_t i = 0; i < N; ++i) {
        out[i] = encrypt_unit<CharT>(plain[i], i, key);
    }
    return out;
}

} // namespace detail

// ----------------------------------------------------------------------------
// Scope-bound holder
// ----------------------------------------------------------------------------

/**
 * @brief Stack-resident, scope-bound decrypted-string holder.
 *
 * Constructed from a `std::array<CharT, N>` of cipher bytes plus the
 * call-site key. Decrypts into an internal buffer at construction time
 * via `volatile` writes (so the optimiser cannot fold the decryption
 * into plaintext immediates). Destructor zeros the buffer via
 * `volatile` stores (so dead-store elimination cannot remove the wipe).
 *
 * Non-copyable, non-movable. Bind the result of `MX_STR` / `MX_WSTR`
 * to a named local; do not pass it as a temporary if the consumer
 * stores the pointer for later use.
 *
 * @tparam CharT  `char` or `wchar_t`.
 * @tparam N      Length including the trailing null terminator.
 */
template <typename CharT, size_t N>
class basic_mx_string {
public:
    using value_type = CharT;

    MX_SDK_FORCE_INLINE basic_mx_string(
        const std::array<CharT, N>& cipher_in, uint64_t key) noexcept
    {
        // Stage 1 — copy cipher bytes into a volatile local. Each
        // assignment is a volatile store, so the writes are observable
        // side effects and cannot be elided. Importantly, the SOURCE
        // of each store is a constexpr known value (a cipher byte), so
        // the byte appears as an immediate in the call-site
        // instruction stream — but it is the ENCRYPTED byte, never the
        // plaintext.
        volatile CharT cipher_local[N];
        copy_into_volatile(cipher_local, cipher_in,
                           std::make_index_sequence<N>{});

        // Stage 2 — decrypt each volatile byte into the volatile
        // output buffer. Volatile loads cannot be replaced with the
        // constexpr value the optimiser "knows" was stored, because
        // volatile semantics say "memory may have changed". The
        // decryption op chain therefore runs at runtime on a
        // runtime-loaded value, and the result is written through a
        // volatile pointer to `buf_`.
        decrypt_into_buf(cipher_local, key,
                         std::make_index_sequence<N>{});
    }

    ~basic_mx_string() noexcept {
        // Wipe the decrypted buffer through a volatile pointer so the
        // optimiser cannot eliminate the writes as dead stores.
        wipe_buf(std::make_index_sequence<N>{});
    }

    basic_mx_string(const basic_mx_string&)            = delete;
    basic_mx_string& operator=(const basic_mx_string&) = delete;
    basic_mx_string(basic_mx_string&&)                 = delete;
    basic_mx_string& operator=(basic_mx_string&&)      = delete;

    /// Pointer to the decrypted, null-terminated buffer.
    [[nodiscard]] const CharT* c_str() const noexcept { return buf_; }

    /// Implicit conversion for ergonomic use with `printf`, `wprintf`,
    /// and any C-string consumer.
    [[nodiscard]] operator const CharT*() const noexcept { return buf_; }

    /// Length in characters, NOT counting the null terminator.
    [[nodiscard]] static constexpr size_t size() noexcept { return N - 1; }

private:
    template <size_t... Is>
    MX_SDK_FORCE_INLINE void copy_into_volatile(
        volatile CharT* dst,
        const std::array<CharT, N>& src,
        std::index_sequence<Is...>) noexcept
    {
        ((dst[Is] = src[Is]), ...);
    }

    template <size_t... Is>
    MX_SDK_FORCE_INLINE void decrypt_into_buf(
        volatile CharT* cipher, uint64_t key,
        std::index_sequence<Is...>) noexcept
    {
        // `vbuf` is a volatile alias of `buf_`. Each store is a volatile
        // write, observable side effect — the optimiser must keep it.
        volatile CharT* vbuf = buf_;
        ((vbuf[Is] = detail::decrypt_unit<CharT>(
              const_cast<CharT&>(cipher[Is]), Is, key)), ...);
    }

    template <size_t... Is>
    MX_SDK_FORCE_INLINE void wipe_buf(std::index_sequence<Is...>) noexcept {
        volatile CharT* vbuf = buf_;
        ((vbuf[Is] = CharT{0}), ...);
    }

    CharT buf_[N];
};

// Convenient aliases.
template <size_t N>
using MxString  = basic_mx_string<char,    N>;

template <size_t N>
using MxWString = basic_mx_string<wchar_t, N>;

} // namespace mx::sdk

// ----------------------------------------------------------------------------
// Public macros
// ----------------------------------------------------------------------------

/**
 * @brief Compile-time-encrypted narrow string literal.
 *
 * Returns a stack-resident scope-bound holder. Bind it to a named
 * local; do not let the value escape its full-expression as a
 * temporary.
 *
 * @code
 * auto host = MX_STR("license.example.com");
 * http_get(host);
 * @endcode
 */
#define MX_STR(LIT)                                                            \
    ([]() noexcept {                                                           \
        constexpr auto _mx_key =                                               \
            ::mx::sdk::detail::call_site_key(                                  \
                __FILE__,                                                      \
                static_cast<uint32_t>(__LINE__),                               \
                static_cast<uint32_t>(__COUNTER__));                           \
        constexpr size_t _mx_n = sizeof(LIT) / sizeof((LIT)[0]);               \
        constexpr auto _mx_cipher =                                            \
            ::mx::sdk::detail::encrypt_literal<char, _mx_n>(LIT, _mx_key);     \
        return ::mx::sdk::MxString<_mx_n>(_mx_cipher, _mx_key);                \
    }())

/**
 * @brief Compile-time-encrypted wide string literal.
 *
 * Same contract as @ref MX_STR but for `wchar_t` literals.
 *
 * @code
 * auto path = MX_WSTR(L"C:\\ProgramData\\config.bin");
 * CreateFileW(path, ...);
 * @endcode
 */
#define MX_WSTR(LIT)                                                           \
    ([]() noexcept {                                                           \
        constexpr auto _mx_key =                                               \
            ::mx::sdk::detail::call_site_key(                                  \
                __FILE__,                                                      \
                static_cast<uint32_t>(__LINE__),                               \
                static_cast<uint32_t>(__COUNTER__));                           \
        constexpr size_t _mx_n = sizeof(LIT) / sizeof((LIT)[0]);               \
        constexpr auto _mx_cipher =                                            \
            ::mx::sdk::detail::encrypt_literal<wchar_t, _mx_n>(LIT, _mx_key);  \
        return ::mx::sdk::MxWString<_mx_n>(_mx_cipher, _mx_key);               \
    }())
