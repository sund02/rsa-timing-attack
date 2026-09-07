// RSA decryption oracle. Reads a hex ciphertext per line, writes back the hex
// decryption. Run it --vulnerable or --secure; the client times the responses.
//
//   ./server --port 9000 --bits 1024 --seed 1 --vulnerable
//   ./server --port 9000 --bits 1024 --seed 1 --secure
//
// Same seed => same key in both modes, so any timing difference the client sees
// is down to the exponentiation strategy and nothing else.

#include "rsa.hpp"
#include "net.hpp"
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int) { g_stop = 1; }

int main(int argc, char** argv) {
    int port = 9000;
    unsigned long bits = 1024, seed = 1;
    bool secure = false;

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--port")  && i+1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bits")  && i+1 < argc) bits = strtoul(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--seed")  && i+1 < argc) seed = strtoul(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--secure"))     secure = true;
        else if (!strcmp(argv[i], "--vulnerable")) secure = false;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }

    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN);      // don't die if the client drops mid-write

    RsaKey key;
    rsa_keygen(key, bits, seed);

    gmp_randstate_t rng;           // only used by the secure path (blinding)
    gmp_randinit_mt(rng);
    gmp_randseed_ui(rng, seed ^ 0xC0FFEE);

    // I print popcount(d) only so I can check the attack's answer against the
    // truth. A real target obviously wouldn't hand you this.
    fprintf(stderr, "[server] mode=%s bits=%lu seed=%lu popcount(d)=%lu port=%d\n",
            secure ? "SECURE" : "VULNERABLE", bits, seed, rsa_popcount_d(key), port);

    int lfd = tcp_listen(port);
    if (lfd < 0) { perror("listen"); return 1; }

    mpz_t c, m;
    mpz_inits(c, m, nullptr);

    while (!g_stop) {
        int cfd = tcp_accept(lfd);
        if (cfd < 0) continue;
        std::string line;
        while (recv_line(cfd, line)) {
            if (line == "quit") { g_stop = 1; break; }
            try {
                mpz_from_hex(c, line);
                mpz_mod(c, c, key.n);
                if (secure) rsa_decrypt_secure(m, c, key, rng);
                else        rsa_decrypt_vulnerable(m, c, key);
                send_line(cfd, mpz_to_hex(m));
            } catch (...) {
                send_line(cfd, "error");
            }
        }
        close(cfd);
    }

    mpz_clears(c, m, nullptr);
    close(lfd);
    fprintf(stderr, "[server] stopped\n");
    return 0;
}
