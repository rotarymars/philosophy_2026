# philohash

Research for philosophy class: hash functions such as SHA-256 are designed
for general use. Could a hash function specialized for one purpose do better?

As a first step we took SHA-256 apart: what happens if its bit rotations are
replaced with AND, OR and other bit operations?

---

## Report 1: replacing SHA-256's sigma functions

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

What the less common operations mean. All of them work on each of the 32 bit
positions separately:

- **majority(t1, t2, t3)**: each output bit is whichever value (0 or 1) at
  least two of the three inputs have at that position. As a formula:
  (t1 & t2) ⊕ (t1 & t3) ⊕ (t2 & t3). SHA-256 itself uses this as `Maj(a, b, c)`
  in every round.
- **t1 ? t2 : t3 (bitwise)**, "choose": where t1 has a 1, the output bit is
  taken from t2; where t1 has a 0, it is taken from t3. As a formula:
  (t1 & t2) ⊕ (¬t1 & t3). SHA-256 uses this as `Ch(e, f, g)` in every round.
- **ROT(x)** stands for the original term being replaced, with the same
  amount n: ROTRⁿ(x) for a rotation term, SHRⁿ(x) for σ's shift term. For
  example, `term-and-self` turns σ0 into
  (x & ROTR⁷(x)) ⊕ (x & ROTR¹⁸(x)) ⊕ (x & SHR³(x)).

A 4-bit example:

| | bits |
|---|---|
| t1 | `1 1 0 0` |
| t2 | `1 0 1 0` |
| t3 | `0 1 1 0` |
| majority(t1, t2, t3) | `1 1 1 0` |
| t1 ? t2 : t3 | `1 0 1 0` (first two bits from t2, last two from t3) |

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

## Report 2: a different operation for each chunk

### 1. Idea

SHA-256 cuts the message into 64-byte **blocks** (chunks) and processes every
block in exactly the same way. Our idea: make each chunk's processing
different, so the work is harder to predict.

1. **By index:** the chunk's position (0, 1, 2, ...) decides the operation.
2. **By content:** the chunk's own value decides. For example, compute the
   value mod 4 and use it to pick one of 4 prepared operations.

### 2. Methods

We built 20 methods on top of SHA-256's compression function, so any
difference in the results comes only from the per-chunk choice. "mod 4" picks
one of four options:

- 4 sets of Σ rotation amounts (set 0 is SHA-256's);
- 4 starting points in the round-constant table K;
- 4 orders in which the block's 16 words are read (taken from BLAKE2);
- 4 word operations: rotate right by 7, multiply by 0x9e3779b1, `w ⊕ (w >> 13)`,
  add 0x6a09e667. Each is one-to-one on its own.

| Group | Method | What decides, and what changes |
|---|---|---|
| baseline | `sha256` | plain SHA-256 |
| index | `idx-whiten` | XOR every word with a mask made from the block index |
| | `idx-counter` | mix the block index into the round state (as BLAKE2 does) |
| | `idx-rotset` | index mod 4 picks the Σ rotation set |
| | `idx-constants` | index mod 4 picks where K starts |
| | `idx-permute` | index mod 4 picks the word order |
| | `idx-word-op` | (index + word position) mod 4 picks each word's operation |
| | `idx-all` | index mod 4 picks Σ set, K start and word order together |
| content | `cnt-rotset` | sum of the block's words mod 4 picks the Σ set |
| | `cnt-constants` | sum mod 4 picks where K starts |
| | `cnt-permute` | sum mod 4 picks the word order |
| | `cnt-all` | sum mod 4 picks all three |
| | `cnt-word-op` | **each word mod 4** picks that word's operation |
| | `cnt-word-op-safe` | same, but the operation never changes the 2 bits used to choose it |
| | `cnt-word-rot` | each word is rotated by (previous word mod 32), like the RC5 cipher |
| | `cnt-round-select` | in every round, the state's `e` mod 4 picks the Σ set |
| | `cnt-chain-select` | the result of all previous blocks, mod 4, picks the Σ set |
| index + content | `idx+cnt` | (index + sum) mod 4 picks Σ set, K start and word order |
| parallel | `par-xor` | every block hashed separately, results XORed (could use many CPU cores) |
| | `par-xor-cnt` | same, block content mod 4 picks the Σ set |
| | `par-xor-idx` | same, block index mixed in (`idx-counter`) |

**Tests.** All the tests from Report 1, plus tests aimed at multi-block
messages (most of our text files fit in one block):

| Test | Question | Ideal |
|---|---|---|
| Long avalanche | Flip one bit of a random 1 KiB (16-block) message: share of output bits that change | 0.5 |
| Swap | Does hash(A ‖ B) equal hash(B ‖ A)? (1,000 random block pairs) | never |
| Cancel | Does hash(A ‖ A ‖ C) equal hash(B ‖ B ‖ C)? (1,000 random triples) | never |
| One-to-one | For word operations: different outputs over all 2³² inputs | 100% |

New flags: M long avalanche off, X swapping blocks kept the hash, K repeated
blocks cancelled out, L the word operation loses information.

We tested 64 rounds (full) and 16 rounds. Fewer than 16 rounds cannot be
tested fairly: round t reads word t, so some words would never be read at all.

### 3. Results

Full output: [`results/chunk_experiment.txt`](results/chunk_experiment.txt)
(and `.csv`).

| Method | 64 rounds | 16 rounds | Speed at 64 rounds |
|---|---|---|---|
| `sha256` | ok | ok | 250 MB/s |
| all other index methods | ok | ok | 239–254 MB/s |
| `idx-permute`, `idx-all` | ok | ok, but see Finding 4 | 245–254 MB/s |
| `cnt-rotset`, `cnt-constants`, `cnt-word-rot`, `cnt-chain-select` | ok | ok | 246–253 MB/s |
| `cnt-permute`, `cnt-all`, `idx+cnt` | ok | **B** | 245–253 MB/s |
| `cnt-word-op` | **L: real collision** | **L** | 194 MB/s |
| `cnt-word-op-safe` | ok | ok | 176 MB/s |
| `cnt-round-select` | ok | ok | 186 MB/s |
| `par-xor`, `par-xor-cnt` | **XK** | **ASMXK** | 247–249 MB/s |
| `par-xor-idx` | ok | **ASM** | 250 MB/s |

#### Finding 1: At full strength, no method is measurably better

At 64 rounds, every sound method gives the same numbers as SHA-256 on every
test. As in Report 1, full SHA-256 already looks perfectly random to these
tests, so extra complexity cannot show up as an improvement. More complex
does not mean measurably better.

#### Finding 2: Choosing by content can create real collisions

`cnt-word-op` loses 28% of all possible words (only 71.9% of outputs are
reachable), and the experiment found a real collision of the **full 64-round
hash**. These two different 4-byte messages get the same hash:

```
00 00 00 02  ->  2 mod 4 = 2  ->  w ⊕ (w >> 13)  = 0x00000002
00 00 01 00  ->  0 mod 4 = 0  ->  rotate right 7 = 0x00000002
```

Both words become `0x00000002` before SHA-256 even starts. After that the two
messages are identical, so no number of rounds can help. The problem is that
the operation can change the very bits that chose it, so the step cannot be
undone. `cnt-word-op-safe` keeps those 2 bits unchanged, and it passes every
test.

Choosing by content has two further problems that our tests do not measure:

- **The attacker chooses the operation.** Whoever writes the message also
  controls its value mod 4, so they can force whichever operation is weakest.
  The design is only as strong as its weakest option.
- **Timing leaks.** If different operations take different time, measuring
  the time can reveal information about the data. That matters when hashing
  passwords or other secrets.

#### Finding 3: Index matters when blocks are processed separately

In SHA-256 each block's result feeds the next block, so the position of a
block already matters. Index-based choices add nothing measurable there.
`idx-rotset`, `idx-constants`, `idx-permute` and `idx-all` are even identical
to SHA-256 for one-block messages, because block 0 uses option 0 (our tests
confirm this).

The parallel designs are different. Each block is hashed on its own, so they
could use many CPU cores at once:

- `par-xor`: swapping two blocks gave the same hash in **1,000 of 1,000**
  tries, and repeated blocks cancelled out in 1,000 of 1,000. Anyone can make
  collisions without any computation.
- `par-xor-cnt`: exactly the same failures. A content-based choice does not
  help, because the same block makes the same choice wherever it is placed.
- `par-xor-idx`: 0 failures. Only the index tells the blocks' positions apart.

#### Finding 4: Fewer rounds expose two weaknesses

At 16 rounds:

- **Reordering words.** `idx-permute` and `cnt-permute` can move a word of
  real text into the position read in the **last round** of the message's
  last block. That word then gets only one round of mixing, and flipping one
  of its bits changed only **2 of 256** output bits (in
  `texts/descartes_en.txt`). Normal SHA-256 reads the length field last,
  which is the same for all messages of the same length, so this never
  happens there. The content versions also made some output bits biased (B).
- **Parallel without a final step.** All parallel designs failed avalanche,
  even `par-xor-idx`: a flip in the last word of a block changed only 3
  output bits, because nothing mixes a block's result after its compression.
  In a sequential chain, each block's result is mixed again by the next
  block's compression. A parallel design needs one extra compression at the
  end to do that job.

#### Finding 5: No method was faster; choosing an operation per word was slower

Methods that pick per block run at SHA-256's speed. Methods that choose
between different operations **for each word by its content**
(`cnt-word-op`, `cnt-word-op-safe`) are slower, because the CPU has to
branch on the data and cannot predict which operation comes next. At
64 rounds `cnt-word-op-safe` was 30% slower and `cnt-word-op` 22% slower; at
16 rounds, 65% and 51%. Rotating by a content-dependent amount
(`cnt-word-rot`) cost nothing, because it is still a single instruction.

Two more cases:

- `cnt-round-select` was 26% slower in the main run, but only 3% slower in a
  separate run on a single core, so that number is uncertain.
- At 16 rounds, `idx-whiten` and `idx-word-op` were 20% and 10% slower, just
  from the extra work done on every word.

### 4. Conclusion

- **By content:** not recommended. It created a real collision when the step
  could not be undone, it lets an attacker choose the operation, it can leak
  timing, and it was slower. It gave no measurable benefit.
- **By index:** harmless but useless in a sequential design like SHA-256. It
  is **essential** in a parallel design, where without it blocks can be
  swapped or cancelled.

The most promising direction is therefore `par-xor-idx`: a parallel hash with
the index mixed in. It is the one design where a per-chunk operation clearly
matters, and it could be much faster on large files by using several CPU
cores.

### 5. Limitations

- As in Report 1, the tests measure randomness, not resistance to attackers.
- The speeds were measured on one core. The parallel designs' main advantage,
  using several cores, has not been measured yet.
- Only "mod 4" choices were tried.

### 6. Next steps

Make `par-xor-idx` a real parallel hash. Add a final compression that mixes
the combined result, hash blocks on several threads, and measure the speed on
large files against SHA-256. That would match the original goal: a hash
specialized for one purpose (large files), possibly faster than
general-purpose SHA-256 there.

---

## Building and running

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build                         # known-answer tests
./build/hash_texts                             # hash every file in texts/
./build/sigma_experiment --rounds 64,24,20     # Report 1 (~5 minutes)
./build/chunk_experiment --rounds 64,16        # Report 2 (~2 minutes)
```

The experiments write CSV files to `results/`. The exact one-to-one check
uses all CPU cores and about 512 MiB of memory.

| Path | Contents |
|---|---|
| `include/philohash/sha256.hpp`, `src/sha256.cpp` | SHA-256 library |
| `include/philohash/sha256_variants.hpp`, `src/sha256_variants.cpp` | SHA-256 with swappable σ/Σ and all patterns. Add a pattern by writing a `term::`, `combine::` or `whole::` struct and registering it in `all_variants()`. |
| `include/philohash/chunk_methods.hpp`, `src/chunk_methods.cpp` | the per-chunk methods of Report 2. Add a method by writing a `step_` function and registering it in `all_methods()`. |
| `apps/hash_texts.cpp` | hashes the files in `texts/` (`sha256sum` format) |
| `apps/bench.hpp`, `apps/bench.cpp` | the statistical tests shared by both experiments |
| `apps/sigma_experiment.cpp` | runs and scores every pattern (Report 1) |
| `apps/chunk_experiment.cpp` | runs and scores every method (Report 2) |
| `tests/` | known-answer tests; checks that the `standard` pattern and the `sha256` method equal real SHA-256 |
| `texts/` | input texts |
| `results/` | experiment output |
