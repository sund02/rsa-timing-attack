# Notes

Some background on why the code is shaped the way it is. Mostly written for
future-me, but it doubles as an explanation of the attack.

## Where the leak comes from

RSA decryption is `m = c^d mod n`. The exponent `d` is the secret. How you
compute that power decides whether the running time depends on `d`.

**Naive square-and-multiply** walks the bits of `d` from the top:

```
x = 1
for each bit of d (MSB..LSB):
    x = x^2 mod n            # every bit
    if bit == 1:
        x = x * c mod n      # only on a 1
```

So the total number of modular multiplies is `#bits + popcount(d)`. The squares
are fixed, but the multiplies scale with the number of set bits. Time therefore
carries `popcount(d)` — a chunk of information about the private key, leaked
through nothing but the clock.

**Montgomery ladder** does the same amount of work on every bit:

```
R0 = 1 ; R1 = c
for each bit of d (MSB..LSB):
    if bit == 0: R1 = R0*R1 ; R0 = R0*R0
    else:        R0 = R0*R1 ; R1 = R1*R1
```

One multiply and one square per bit regardless of its value, so the count no
longer depends on `d`. That kills the Hamming-weight leak (`bench hamming` shows
the line going flat).

## The other leak: Montgomery extra reductions

Montgomery multiplication finishes with "if the result is >= n, subtract n once".
Whether that subtraction happens depends on the operands, so over a full
exponentiation the number of extra reductions depends on the *input*. Brumley &
Boneh (2003) showed you can steer chosen ciphertexts toward a factor of `n` and
read the boundary off the timing, recovering the key bit by bit.

I didn't build the full recovery loop — I implemented Montgomery multiplication
with a counter (`modexp_montgomery`) so the input-dependence is measurable
(`bench reduction`), and left the bit-recovery search as the obvious extension.

## Why blinding is the real fix

The ladder fixes the exponent-shaped leak, but a chosen-ciphertext attack works
on the *input*. Base blinding removes that: before decrypting `c`, pick a random
`r`, decrypt `c·r^e` instead, then multiply the result by `r^-1`. The value the
exponentiation actually sees is randomised, so its timing tells the attacker
nothing about the real `c`. `rsa_decrypt_secure` does ladder + blinding together.

## Measuring without lying to myself

Two things kept biting me until I handled them:

- **Jitter only adds time.** A single slow sample means the OS scheduled
  something else, not that the crypto got slower. So I take the *minimum* RTT
  over many repetitions as the estimate of true compute time, not the mean.
- **The machine drifts.** CPU frequency scaling made a block of measurements
  taken later look uniformly faster, which faked a trend. Fix: in `bench` I
  interleave the two implementations round-robin, so any drift hits both equally
  and cancels out of the comparison.

## Honest limits

- Textbook RSA. No padding, no CRT, tiny keys. Do not use for anything real.
- The clean popcount line is from the controlled local run. Over TCP I show a
  vulnerable-vs-secure distinguisher, which is robust; recovering `popcount(d)`
  across random keys purely over the network is marginal because natural
  variation is small next to cross-process drift.
- Constant-*work* (ladder) is not the same as constant-*time* against cache and
  branch-prediction channels. This project addresses the arithmetic-level leak,
  not every microarchitectural one.

## Reference

D. Brumley, D. Boneh. *Remote Timing Attacks Are Practical.* USENIX Security 2003.
