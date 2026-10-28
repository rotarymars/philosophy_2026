# philohash

Research for philosophy class: hash functions such as SHA-256 are designed
for general use. Could a hash function specialized for one purpose do better?

As a first step we took SHA-256 apart: what happens if its bit rotations are
replaced with AND, OR and other bit operations?

---

## Report: replacing SHA-256's sigma functions

### 1. Background

SHA-256 processes a message in 64-byte blocks. For each block:

1. **Message schedule.** The 16 words `W0..W15` of the block are expanded to
   64 words. The new words use the *small sigma* functions σ0 and σ1:

   ```
   W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]      (t = 16..63)
   ```

2. **Compression.** 64 rounds update eight state words `a..h`. Round `t` uses
   `W[t]` and the *big sigma* functions Σ0 and Σ1.

All four functions are built from the same pattern:

| Function | Definition | Used in |
|---|---|---|
| σ0(x) | ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x) | message schedule |
| σ1(x) | ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x) | message schedule |
| Σ0(x) | ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x) | compression (on `a`) |
| Σ1(x) | ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x) | compression (on `e`) |

ROTRⁿ rotates the 32-bit word right by n bits (bits that fall off come back on
the left). SHRⁿ shifts right by n bits (bits that fall off are lost). ⊕ is XOR.

**Question:** are the rotations and XOR really necessary, or would other bit
operations work as well, or better?

### 2. Method

**Patterns.** We wrote 20 replacements, in three groups. `t1, t2, t3` are the
three rotated/shifted copies of `x` in the original definition.

| Group | Pattern | Replacement |
|---|---|---|
| — | `standard` | the real SHA-256 (baseline) |
| Change how t1, t2, t3 are combined | `comb-and` | t1 & t2 & t3 |
| | `comb-or` | t1 \| t2 \| t3 |
| | `comb-and-xor` | (t1 & t2) ⊕ t3 |
| | `comb-or-xor` | (t1 \| t2) ⊕ t3 |
| | `comb-maj` | majority(t1, t2, t3) |
| | `comb-ch` | t1 ? t2 : t3 (bitwise) |
| | `comb-add` | t1 + t2 + t3 (mod 2³²) |
| Change each rotation/shift | `term-shr` | right shifts only (no wrap-around) |
| | `term-shl` | left shifts only |
| | `term-rotr` | rotations only (the SHR also becomes a rotation) |
| | `term-and-self` | x & ROT(x) |
| | `term-or-self` | x \| ROT(x) |
| | `term-xor-self` | x ⊕ ROT(x) |
| | `term-not` | ¬ROT(x) |
| | `term-and-mask` | x & fixed mask (bits never move) |
| Replace the whole function | `whole-identity` | x |
| | `whole-zero` | 0 |
| | `whole-not` | ¬x |
| | `whole-mul` | x × 0x9e3779b1 (mod 2³²) |

Each pattern was applied in three **scopes**: σ only (`small`), Σ only
(`big`), and `both`. That gives 61 hash functions, including the standard
one. Each was run with the full **64 rounds**, and also with **24** and
**20** rounds to see weaknesses that full SHA-256 hides.

**Tests.**

| Test | Question | Ideal |
|---|---|---|
| Avalanche | Flip one bit of a file in `texts/`: what fraction of the 256 output bits change? | 0.5 |
| Min avalanche | The worst case of the above. 0 means two different inputs gave the same hash. | ≈100 bits |
| SAC | For each output bit, how far is its flip rate from 50%? (worst bit) | ≈0 |
| Collisions | Hash `"0"` … `"131071"`, keep 24 bits: collisions compared with a random function | 1.0× |
| Bit balance | Across the same hashes, how far is any output bit from being 1 half of the time? | ≈0 |
| Schedule mixing | Flip one bit of a block: what fraction of the bits of `W16..W63` change? | standard: 0.424 |
| One-to-one | Run σ0 on **all 2³² inputs**: how many different outputs? | 100% |
| Speed | MB/s on 8 MiB of data | — |

A pattern is marked **WEAK** with a letter for each failed test:
A avalanche, S SAC, C collisions, F a real collision found, B bit balance,
W schedule mixing below 0.40, L loses information (not one-to-one).

### 3. Results

Full output: [`results/sigma_experiment.txt`](results/sigma_experiment.txt)
(and `.csv`). Summary at 64 rounds:

| Pattern | One-to-one | Schedule mixing (σ replaced) | σ only | Σ only | both |
|---|---:|---:|---|---|---|
| **standard** | **100%** | **0.424** | ok | ok | ok |
| **term-rotr** | **100%** | **0.428** | ok | ok | ok |
| term-not | 100% | 0.424 | ok | ok | ok |
| term-xor-self | 50% | 0.433 | L | L | L |
| comb-add | 50.5% | 0.425 | L | L | L |
| comb-and-xor | 25.5% | 0.403 | L | L | L |
| comb-or-xor | 25.5% | 0.403 | L | L | L |
| term-shr | 12.5% | 0.155 | WL | L | WL |
| term-or-self | 6.5% | 0.405 | L | L | L |
| term-and-self | 6.4% | 0.406 | L | L | L |
| comb-maj | 4.9% | 0.387 | WL | L | WL |
| comb-ch | 3.4% | 0.387 | WL | L | WL |
| comb-or | 0.40% | 0.308 | WL | L | WL |
| comb-and | 0.19% | 0.209 | WL | L | WL |
| term-and-mask | 0.002% | 0.106 | WL | L | **ASCBWL** |
| term-shl | 12.5% | 0.114 | WL | SL | **ASCFBWL** |
| whole-identity | 100% | 0.110 | W | S | **ASCFBW** |
| whole-not | 100% | 0.074 | W | S | **ASCFBW** |
| whole-mul | 100% | 0.237 | W | S | **ASCFBW** |
| whole-zero | 0% | 0.021 | WL | SL | **ASCFBWL** |

#### Finding 1: Only rotation + XOR survives

Only three patterns pass every test: `standard`, `term-rotr` and `term-not`.
`term-not` is not really new: ¬a ⊕ ¬b ⊕ ¬c = ¬(a ⊕ b ⊕ c), so it is just the
standard σ with every bit inverted.

Every pattern that uses AND or OR **loses information**: many different
inputs give the same output. `comb-and` keeps only 0.19% of the possible
values, because AND of three values is mostly 0 (only 11% of its output bits
are 1). XOR is special: it keeps 0s and 1s balanced, and combined with
rotations it is one-to-one.

#### Finding 2: Full SHA-256 hides almost any damage

When only σ is replaced, **every** pattern still passes all the hash-output
tests, even `whole-zero` (σ = 0). The compression rounds with Σ are strong
enough to make the output look random anyway.

This does not mean those versions are safe. Our tests check whether the output
*looks* random. They do not simulate an attacker who chooses inputs carefully,
which is how real attacks work. The schedule test shows the damage directly.
For example, flipping the top bit of `W0`:

- standard σ: 644 of 1,536 schedule bits change (41.9%), spread over almost
  every word;
- σ = 0: only **12 bits** change (0.8%), one bit each in 12 words.

With a weak σ, a small change in the message stays small. That makes it much
easier to search for two messages whose differences cancel out: a collision.

#### Finding 3: Some operation must move bits rightward

The worst failures are the patterns that never move bits toward the lower
positions (`whole-identity`, `whole-not`, `whole-mul`, `term-shl`,
`term-and-mask`, `whole-zero`) used in both σ and Σ. Even with all 64 rounds:

- only about 25% of output bits change instead of 50%;
- 7 of the 256 output bits of `whole-identity`/both were **the same for all
  131,072 inputs**;
- 24-bit collisions were about 48× more frequent than random;
- **real collisions were found**: flipping one bit of an input gave exactly
  the same hash.

The reason is that addition only carries information *leftward* (from low bits
to high bits). Rotation is the only operation in SHA-256 that brings high bits
back down. Without it, the low output bits can never depend on the high input
bits.

#### Finding 4: Σ matters more than σ for output quality

Replacing Σ alone breaks the output statistics at 24 and 20 rounds (`whole-*`,
`term-shl`, `term-and-mask`, and `term-shr` at 20 rounds). Replacing σ alone
never does. Note that at
20 rounds σ is used for only 4 schedule words (`W16..W19`).

#### Finding 5: No pattern was faster

At 64 rounds, standard SHA-256 ran at 364 MB/s, and the patterns that passed
the output tests ran at 307–384 MB/s, the same within measurement noise.
Rotation is a single CPU instruction, so replacing it saves nothing. The only
clear speed-ups (up to 500 MB/s) came from deleting work in Σ
(`whole-identity`, `whole-zero`, `term-and-mask`), and those versions are
broken. Reducing rounds is what changes
speed: 64 → 20 rounds is about 3.8× faster (1,389 MB/s).

#### Finding 6: Checking everything beats sampling

An earlier version of the one-to-one test sampled 2²⁰ inputs. It reported
`comb-add` as 100% one-to-one; checking all 2³² inputs showed it reaches only
50.5%. The colliding inputs simply were not in the sample.

### 4. Conclusion

**No replacement beat SHA-256's original design.**

The best result was `term-rotr` (σ made of rotations only). It is one-to-one,
passes every test, mixes the schedule very slightly better (0.428 vs 0.424),
and runs at the same speed. But it removes the SHR: with only rotations,
rotating the input just rotates σ's output. That symmetry can help attackers,
and our statistical tests cannot see it. So we cannot claim it is better.

The rotations and XOR in SHA-256 are not arbitrary:

- XOR keeps the output balanced and, with rotations, one-to-one;
- rotations are the only way information moves from high bits to low bits;
- the SHR breaks rotational symmetry.

### 5. Limitations

- The tests measure statistical randomness, not resistance to attacks.
- The avalanche test uses only the files in `texts/` (about 5,800 bit flips).
- The one-to-one check was done for each pattern with σ0's amounts only, not
  for σ1, Σ0 or Σ1.
- Speed was measured on one machine that was also running other work; numbers
  vary by about ±10%.

### 6. Next steps

Changing σ alone does not make SHA-256 better *in general*. The more promising
direction is to choose a **specific purpose** and accept trade-offs that are
fine there. For example, a hash for a hash table does not need to resist
attackers, so fewer rounds could be acceptable: standard SHA-256 at 20 rounds
still passed every statistical test here, at 3.8× the speed.

---

## Building and running

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build                         # SHA-256 known-answer tests
./build/hash_texts                             # hash every file in texts/
./build/sigma_experiment --rounds 64,24,20     # the experiment (~5 minutes)
```

`sigma_experiment` writes `results/sigma_experiment.csv`. The exact
one-to-one check uses all CPU cores and about 512 MiB of memory.

| Path | Contents |
|---|---|
| `include/philohash/sha256.hpp`, `src/sha256.cpp` | SHA-256 library |
| `include/philohash/sha256_variants.hpp`, `src/sha256_variants.cpp` | SHA-256 with swappable σ/Σ and all patterns. Add a pattern by writing a `term::`, `combine::` or `whole::` struct and registering it in `all_variants()`. |
| `apps/hash_texts.cpp` | hashes the files in `texts/` (`sha256sum` format) |
| `apps/sigma_experiment.cpp` | runs and scores every pattern |
| `tests/` | known-answer tests; checks that the `standard` pattern equals real SHA-256 |
| `texts/` | input texts |
| `results/` | experiment output |
