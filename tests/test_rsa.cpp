// Correctness checks. All three exponentiation routines must agree with GMP's
// mpz_powm, and both decrypt paths must invert encryption. Run with `make test`.

#include "rsa.hpp"
#include <cstdio>
#include <cstdint>

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { ++failures; printf("FAIL: %s\n", msg); } } while (0)

int main() {
    RsaKey key;
    rsa_keygen(key, 512, 1);

    gmp_randstate_t rng; gmp_randinit_mt(rng); gmp_randseed_ui(rng, 99);
    mpz_t c, ref, a, b, mont, ct, pt;
    mpz_inits(c, ref, a, b, mont, ct, pt, nullptr);

    for (int t = 0; t < 50; ++t) {
        mpz_urandomm(c, rng, key.n);

        mpz_powm(ref, c, key.d, key.n);               // reference

        modexp_naive(a, c, key.d, key.n);
        CHECK(mpz_cmp(a, ref) == 0, "naive != mpz_powm");

        modexp_ladder(b, c, key.d, key.n);
        CHECK(mpz_cmp(b, ref) == 0, "ladder != mpz_powm");

        uint64_t er = 0;
        modexp_montgomery(mont, c, key.d, key.n, &er);
        CHECK(mpz_cmp(mont, ref) == 0, "montgomery != mpz_powm");

        // encrypt then decrypt should return the original
        mpz_powm(ct, c, key.e, key.n);
        rsa_decrypt_vulnerable(pt, ct, key);
        CHECK(mpz_cmp(pt, c) == 0, "vulnerable decrypt roundtrip");

        rsa_decrypt_secure(pt, ct, key, rng);
        CHECK(mpz_cmp(pt, c) == 0, "secure decrypt roundtrip");
    }

    // hex helpers should roundtrip
    std::string h = mpz_to_hex(key.n);
    mpz_t back; mpz_init(back); mpz_from_hex(back, h);
    CHECK(mpz_cmp(back, key.n) == 0, "hex roundtrip");

    mpz_clears(c, ref, a, b, mont, ct, pt, back, nullptr);

    if (failures == 0) { printf("all tests passed\n"); return 0; }
    printf("%d test(s) failed\n", failures);
    return 1;
}
