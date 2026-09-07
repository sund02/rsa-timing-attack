// Controlled local experiments — no network noise — that isolate each leak.
//
//   ./bench hamming  [rounds]    -> CSV: popcount, naive_us, ladder_us
//   ./bench reduction [samples]  -> CSV: input_index, extra_reductions, mont_us
//
// hamming:   sweep the exponent's Hamming weight and time both implementations.
//            I measure round-robin (naive, ladder, naive, ladder, ...) so slow
//            CPU drift hits every data point equally instead of biasing one
//            implementation. Take the min over many rounds to drop jitter.
//            Result: naive rises linearly with popcount, ladder stays flat.
//
// reduction: fix one key, vary the input, and watch the Montgomery extra-
//            reduction count (and time) change with the ciphertext.

#include "rsa.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace std::chrono;

static long long time_ns(void (*fn)(mpz_t, const mpz_t, const mpz_t, const mpz_t),
                         mpz_t o, const mpz_t b, const mpz_t e, const mpz_t n) {
    auto t0 = steady_clock::now();
    fn(o, b, e, n);
    auto t1 = steady_clock::now();
    return duration_cast<nanoseconds>(t1 - t0).count();
}

static int run_hamming(int rounds) {
    const unsigned long bits = 1024;
    RsaKey key; rsa_keygen(key, bits, 1);          // I only need this key's modulus
    gmp_randstate_t rng; gmp_randinit_mt(rng); gmp_randseed_ui(rng, 7);
    mpz_t base; mpz_init(base); mpz_urandomm(base, rng, key.n);

    // Synthetic exponents with the Hamming weight I want, same bit length.
    std::vector<int> pops;
    for (int p = 64; p <= 960; p += 64) pops.push_back(p);
    int M = (int)pops.size();

    std::vector<mpz_t> exps(M);
    for (int j = 0; j < M; ++j) {
        mpz_init(exps[j]);
        mpz_set_ui(exps[j], 0);
        mpz_setbit(exps[j], bits - 1);             // pin the top bit -> fixed width
        for (int b = 0; b < pops[j]; ++b) mpz_setbit(exps[j], b);
    }

    std::vector<long long> bn(M, (long long)4e18), bl(M, (long long)4e18);
    mpz_t o; mpz_init(o);
    for (int r = 0; r < rounds; ++r)
        for (int j = 0; j < M; ++j) {              // interleaved on purpose
            bn[j] = std::min(bn[j], time_ns(modexp_naive,  o, base, exps[j], key.n));
            bl[j] = std::min(bl[j], time_ns(modexp_ladder, o, base, exps[j], key.n));
        }

    printf("popcount,naive_us,ladder_us\n");
    for (int j = 0; j < M; ++j)
        printf("%d,%.3f,%.3f\n", pops[j], bn[j] / 1000.0, bl[j] / 1000.0);

    // Fit a line to the naive curve — the slope is µs per set bit, i.e. the cost
    // of one extra modular multiply.
    double sx=0, sy=0, sxy=0, sxx=0;
    for (int j = 0; j < M; ++j) { double x=pops[j], y=bn[j]/1000.0; sx+=x; sy+=y; sxy+=x*y; sxx+=x*x; }
    double slope = (M*sxy - sx*sy) / (M*sxx - sx*sx);
    fprintf(stderr, "\n[hamming] naive slope = %.4f us per set bit\n", slope);
    return 0;
}

static int run_reduction(int samples) {
    RsaKey key; rsa_keygen(key, 1024, 555);
    gmp_randstate_t rng; gmp_randinit_mt(rng); gmp_randseed_ui(rng, 13);
    mpz_t c, o; mpz_inits(c, o, nullptr);

    printf("input_index,extra_reductions,mont_us\n");
    for (int i = 0; i < samples; ++i) {
        mpz_urandomm(c, rng, key.n);
        uint64_t er = 0;
        long long best = (long long)4e18;
        for (int r = 0; r < 30; ++r) {             // min-filter the time
            auto t0 = steady_clock::now();
            modexp_montgomery(o, c, key.d, key.n, &er);
            auto t1 = steady_clock::now();
            best = std::min(best, (long long)duration_cast<nanoseconds>(t1 - t0).count());
        }
        printf("%d,%lu,%.3f\n", i, (unsigned long)er, best / 1000.0);
    }
    fprintf(stderr, "\n[reduction] extra-reduction count varies with the input for a fixed key.\n");
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s hamming|reduction [n]\n", argv[0]); return 2; }
    if (!strcmp(argv[1], "hamming"))   return run_hamming(argc > 2 ? atoi(argv[2]) : 300);
    if (!strcmp(argv[1], "reduction")) return run_reduction(argc > 2 ? atoi(argv[2]) : 60);
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
