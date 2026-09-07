#include "rsa.hpp"
#include <stdexcept>

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------
void rsa_keygen(RsaKey& key, unsigned long bits, unsigned long seed) {
    key.bits = bits;

    gmp_randstate_t rng;
    gmp_randinit_mt(rng);
    gmp_randseed_ui(rng, seed);

    mpz_t p, q, p1, q1, phi, gcd;
    mpz_inits(p, q, p1, q1, phi, gcd, nullptr);

    mpz_set_ui(key.e, 65537);

    const unsigned long half = bits / 2;
    while (true) {
        // Two primes, each half the modulus width. Set the top bit before
        // nextprime so the product actually comes out to `bits` bits.
        mpz_urandomb(p, rng, half);
        mpz_setbit(p, half - 1);
        mpz_nextprime(p, p);

        mpz_urandomb(q, rng, half);
        mpz_setbit(q, half - 1);
        mpz_nextprime(q, q);

        if (mpz_cmp(p, q) == 0) continue;

        mpz_mul(key.n, p, q);
        if (mpz_sizeinbase(key.n, 2) != bits) continue;   // retry if a bit short

        mpz_sub_ui(p1, p, 1);
        mpz_sub_ui(q1, q, 1);
        mpz_mul(phi, p1, q1);

        mpz_gcd(gcd, key.e, phi);
        if (mpz_cmp_ui(gcd, 1) != 0) continue;            // e must be invertible

        mpz_invert(key.d, key.e, phi);                    // d = e^-1 mod phi
        break;
    }

    mpz_clears(p, q, p1, q1, phi, gcd, nullptr);
    gmp_randclear(rng);
}

unsigned long rsa_popcount_d(const RsaKey& key) {
    return mpz_popcount(key.d);
}

// ---------------------------------------------------------------------------
// Vulnerable: left-to-right square-and-multiply.
// The multiply only runs on set bits, so runtime leaks popcount(exp).
// ---------------------------------------------------------------------------
void modexp_naive(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t n) {
    mpz_t x, b;
    mpz_init_set_ui(x, 1);
    mpz_init(b);
    mpz_mod(b, base, n);

    long bits = mpz_sizeinbase(exp, 2);
    for (long i = bits - 1; i >= 0; --i) {
        mpz_mul(x, x, x);              // square: happens every bit
        mpz_mod(x, x, n);
        if (mpz_tstbit(exp, i)) {
            mpz_mul(x, x, b);          // multiply: only on a 1 bit
            mpz_mod(x, x, n);
        }
    }
    mpz_set(out, x);
    mpz_clears(x, b, nullptr);
}

// ---------------------------------------------------------------------------
// Hardened: Montgomery ladder. Same work every bit -> no popcount leak.
// (GMP's own mpz_powm is already hardened, which is exactly why I can't use it
//  for the vulnerable case and have to write the naive loop myself.)
// ---------------------------------------------------------------------------
void modexp_ladder(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t n) {
    mpz_t r0, r1, tmp;
    mpz_init_set_ui(r0, 1);
    mpz_init(r1);
    mpz_init(tmp);
    mpz_mod(r1, base, n);

    long bits = mpz_sizeinbase(exp, 2);
    for (long i = bits - 1; i >= 0; --i) {
        if (mpz_tstbit(exp, i) == 0) {
            mpz_mul(tmp, r0, r1); mpz_mod(r1, tmp, n);
            mpz_mul(tmp, r0, r0); mpz_mod(r0, tmp, n);
        } else {
            mpz_mul(tmp, r0, r1); mpz_mod(r0, tmp, n);
            mpz_mul(tmp, r1, r1); mpz_mod(r1, tmp, n);
        }
    }
    mpz_set(out, r0);
    mpz_clears(r0, r1, tmp, nullptr);
}

// ---------------------------------------------------------------------------
// Montgomery multiplication with the extra-reduction count exposed.
//
// Montgomery reduction ends with "if result >= N, subtract N". Whether that
// subtraction fires depends on the operands, so across a whole exponentiation
// the number of extra reductions depends on the input. That input-dependence is
// the leak Brumley & Boneh turned into a full key recovery. I keep a counter so
// it's easy to correlate against timing.
// ---------------------------------------------------------------------------
namespace {

struct Mont {
    mpz_t n, r, rinv, nprime, one_mont;
    unsigned long k;                 // r = 2^k
    uint64_t extra = 0;

    explicit Mont(const mpz_t modulus) {
        mpz_inits(n, r, rinv, nprime, one_mont, nullptr);
        mpz_set(n, modulus);
        k = mpz_sizeinbase(n, 2);
        mpz_ui_pow_ui(r, 2, k);      // smallest 2^k >= n
        mpz_invert(rinv, r, n);

        // nprime = (-n^-1) mod r
        mpz_t ninv; mpz_init(ninv);
        mpz_invert(ninv, n, r);
        mpz_sub(nprime, r, ninv);
        mpz_mod(nprime, nprime, r);
        mpz_clear(ninv);

        mpz_t one; mpz_init_set_ui(one, 1);
        to_mont(one_mont, one);      // cache 1 in the Montgomery domain
        mpz_clear(one);
    }
    ~Mont() { mpz_clears(n, r, rinv, nprime, one_mont, nullptr); }

    void to_mont(mpz_t out, const mpz_t v) {
        mpz_mul(out, v, r); mpz_mod(out, out, n);   // v*r mod n
    }

    // a*b*r^-1 mod n, counting the conditional subtraction.
    void mul(mpz_t out, const mpz_t a, const mpz_t b) {
        mpz_t t, m, u;
        mpz_inits(t, m, u, nullptr);
        mpz_mul(t, a, b);                 // t = a*b
        mpz_fdiv_r_2exp(m, t, k);         // m = t mod r
        mpz_mul(m, m, nprime);
        mpz_fdiv_r_2exp(m, m, k);         // m = t*n' mod r
        mpz_mul(u, m, n);
        mpz_add(u, u, t);
        mpz_fdiv_q_2exp(u, u, k);         // u = (t + m*n) / r
        if (mpz_cmp(u, n) >= 0) {
            mpz_sub(u, u, n);             // <-- extra reduction
            ++extra;
        }
        mpz_set(out, u);
        mpz_clears(t, m, u, nullptr);
    }
};

} // namespace

void modexp_montgomery(mpz_t out, const mpz_t base, const mpz_t exp,
                       const mpz_t n, uint64_t* extra_reductions) {
    Mont M(n);
    mpz_t x, b, bmod;
    mpz_inits(x, b, bmod, nullptr);

    mpz_mod(bmod, base, n);
    M.to_mont(b, bmod);              // base -> Montgomery domain
    mpz_set(x, M.one_mont);          // x = 1 (Montgomery domain)

    long bits = mpz_sizeinbase(exp, 2);
    for (long i = bits - 1; i >= 0; --i) {
        M.mul(x, x, x);              // square
        if (mpz_tstbit(exp, i))
            M.mul(x, x, b);         // multiply
    }

    mpz_t one; mpz_init_set_ui(one, 1);
    M.mul(x, x, one);                // pull x back out of the Montgomery domain
    mpz_set(out, x);

    if (extra_reductions) *extra_reductions = M.extra;
    mpz_clears(x, b, bmod, one, nullptr);
}

// ---------------------------------------------------------------------------
// Decryption wrappers
// ---------------------------------------------------------------------------
void rsa_decrypt_vulnerable(mpz_t out, const mpz_t c, const RsaKey& key) {
    modexp_naive(out, c, key.d, key.n);
}

void rsa_decrypt_secure(mpz_t out, const mpz_t c, const RsaKey& key,
                        gmp_randstate_t rng) {
    // Blinding: pick random r, decrypt c*r^e, then divide the result by r.
    // c' = c * r^e mod n ; m' = (c')^d ; m = m' * r^-1 mod n.
    mpz_t r, re, cb, mb, rinv;
    mpz_inits(r, re, cb, mb, rinv, nullptr);

    do {
        mpz_urandomm(r, rng, key.n);
    } while (mpz_cmp_ui(r, 2) < 0 || mpz_invert(rinv, r, key.n) == 0);

    mpz_powm(re, r, key.e, key.n);          // r^e is public, fine to use the lib
    mpz_mul(cb, c, re); mpz_mod(cb, cb, key.n);

    modexp_ladder(mb, cb, key.d, key.n);    // constant-work exponentiation

    mpz_mul(out, mb, rinv); mpz_mod(out, out, key.n);
    mpz_clears(r, re, cb, mb, rinv, nullptr);
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
std::string mpz_to_hex(const mpz_t x) {
    char* s = mpz_get_str(nullptr, 16, x);
    std::string out(s);
    void (*freefn)(void*, size_t);
    mp_get_memory_functions(nullptr, nullptr, &freefn);
    freefn(s, out.size() + 1);              // free with GMP's allocator, not free()
    return out;
}

void mpz_from_hex(mpz_t out, const std::string& hex) {
    if (mpz_set_str(out, hex.c_str(), 16) != 0)
        throw std::runtime_error("bad hex input");
}
