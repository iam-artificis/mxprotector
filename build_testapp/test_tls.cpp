// Minimal test exe that forces the linker to emit a TLS directory.
// `__declspec(thread)` variables compile into `.tls` section data
// and a `.rdata$T` callback array, giving us a target for P4's
// TLS directory merge path.

#include <cstdio>

__declspec(thread) int tls_counter = 0;
__declspec(thread) char tls_buf[64] = {};

int main() {
    tls_counter = 42;
    for (int i = 0; i < 64; ++i) tls_buf[i] = static_cast<char>(i);
    std::printf("[test_tls] counter=%d buf[0]=%d buf[63]=%d\n",
                tls_counter, tls_buf[0], tls_buf[63]);
    return 0;
}
