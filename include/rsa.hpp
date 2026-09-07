#pragma once
#include <gmp.h>
#include <cstdint>
#include <string>

// Textbook RSA, just enough to demonstrate a timing side channel.
// This is NOT real crypto: no padding, no CRT, keys are throwaway. The point is
// to show how the exponentiation is written leaks the key, not to protect data.

struct RsaKey {
    mpz_t n;   // modulus
    mpz_t e;   // public exponent (I fix this at 65537)
    mpz_t d;   // private exponent — the secret the attack goes after
    unsigned long bits;

    RsaKey()  { mpz_inits(n, e, d, nullptr); bits = 0; }
    ~RsaKey() { mpz_clears(n, e, d, nullptr); }
    RsaKey(const RsaKey&) = delete;              // owns GMP state, don't copy it
    RsaKey& operator=(const RsaKey&) = delete;
};

// seed makes keygen reproducible so I can repeat an experiment exactly.
void rsa_keygen(RsaKey& key, unsigned long bits, unsigned long seed);

// Hamming weight of d. This is the quantity the naive exponentiation leaks.
unsigned long rsa_popcount_d(const RsaKey& key);

// --- base^exp mod n, three different ways ---

// Vulnerable. Squares on every bit but multiplies only on set bits, so the
// number of modular multiplies (and the runtime) tracks popcount(exp).
void modexp_naive(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t n);

// Fix #1. Montgomery ladder — one square AND one multiply per bit no matter
// what the bit is, so the timing stops depending on popcount(exp).
void modexp_ladder(mpz_t out, const mpz_t base, const mpz_t exp, const mpz_t n);

// Montgomery-domain version that also counts the conditional final subtraction
// (the "extra reduction"). That count is input-dependent — it's the actual
// signal Brumley & Boneh exploited — so I hand it back to make the leak visible.
void modexp_montgomery(mpz_t out, const mpz_t base, const mpz_t exp,
                       const mpz_t n, uint64_t* extra_reductions);

// --- decryption wrappers ---

// The oracle we attack: naive exponent, no blinding.
void rsa_decrypt_vulnerable(mpz_t out, const mpz_t c, const RsaKey& key);

// Hardened: base blinding + ladder. Blinding randomises the operand first, so
// per-input timing carries no information about the true ciphertext.
void rsa_decrypt_secure(mpz_t out, const mpz_t c, const RsaKey& key,
                        gmp_randstate_t rng);

// --- hex helpers for the wire format ---
std::string mpz_to_hex(const mpz_t x);
void        mpz_from_hex(mpz_t out, const std::string& hex);
