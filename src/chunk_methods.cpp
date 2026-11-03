#include "philohash/chunk_methods.hpp"

#include <cstring>

namespace philohash::chunk {
namespace {

constexpr u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr u32 H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

constexpr u32 rotr(u32 x, int n) { return (x >> n) | (x << ((32 - n) & 31)); }
constexpr u32 rotl(u32 x, int n) { return (x << n) | (x >> ((32 - n) & 31)); }

// Four sets of big-sigma rotation amounts: {Σ0: a, b, c, Σ1: a, b, c}.
// Set 0 is SHA-256's; the others are our own picks. An XOR of three
// rotations is always one-to-one, so every set is.
constexpr int kBigSigma[4][6] = {
    {2, 13, 22, 6, 11, 25},
    {5, 14, 23, 3, 12, 26},
    {7, 16, 27, 4, 9, 19},
    {1, 10, 20, 8, 15, 29},
};

// Four orders in which a block's 16 words can be read (from BLAKE2's message
// permutation table). Order 0 is the normal order.
constexpr int kPerm[4][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
};

constexpr bool perms_are_valid() {
  for (const auto &row : kPerm) {
    bool used[16] = {};
    for (int j : row) {
      if (j < 0 || j > 15 || used[j])
        return false;
      used[j] = true;
    }
  }
  return true;
}
static_assert(perms_are_valid(), "every kPerm row must be a permutation");

constexpr u32 small_sigma0(u32 x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
constexpr u32 small_sigma1(u32 x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// Per-block settings of the compression function. The defaults are SHA-256.
struct Params {
  int rounds = 64;
  int sigma_set = 0;         // which row of kBigSigma
  int k_offset = 0;          // round t uses K[(t + k_offset) % 64]
  int perm = 0;              // the block's words are read in kPerm[perm] order
  bool round_select = false; // each round picks its sigma set from e mod 4
  std::uint64_t counter = 0; // mixed into the working state, like BLAKE2
};

void compress(u32 h[8], const u32 m[16], const Params &p) {
  u32 w[64];
  for (int j = 0; j < 16; j++)
    w[j] = m[kPerm[p.perm][j]];
  for (int t = 16; t < p.rounds; t++)
    w[t] = small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) +
           w[t - 16];

  u32 s[8];
  std::memcpy(s, h, sizeof s);
  s[6] ^= (u32)p.counter;
  s[7] ^= (u32)(p.counter >> 32);
  for (int t = 0; t < p.rounds; t++) {
    const int *a = kBigSigma[p.round_select ? (s[4] & 3) : p.sigma_set];
    const u32 big1 = rotr(s[4], a[3]) ^ rotr(s[4], a[4]) ^ rotr(s[4], a[5]);
    const u32 big0 = rotr(s[0], a[0]) ^ rotr(s[0], a[1]) ^ rotr(s[0], a[2]);
    const u32 t1 = s[7] + big1 + ((s[4] & s[5]) ^ (~s[4] & s[6])) +
                   K[(t + p.k_offset) & 63] + w[t];
    const u32 t2 = big0 + ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
    s[7] = s[6];
    s[6] = s[5];
    s[5] = s[4];
    s[4] = s[3] + t1;
    s[3] = s[2];
    s[2] = s[1];
    s[1] = s[0];
    s[0] = t1 + t2;
  }
  for (int i = 0; i < 8; i++)
    h[i] += s[i];
}

Params base_params(int rounds) {
  Params p;
  p.rounds = rounds < 1 ? 1 : rounds > 64 ? 64 : rounds;
  return p;
}

// Calls f(words, index) for every block of the padded message, in order.
template <class F>
void for_each_block(const unsigned char *data, std::size_t len, F f) {
  u32 m[16];
  auto load = [&](const unsigned char *b) {
    for (int j = 0; j < 16; j++)
      m[j] = (u32)b[4 * j] << 24 | (u32)b[4 * j + 1] << 16 |
             (u32)b[4 * j + 2] << 8 | (u32)b[4 * j + 3];
  };

  const std::size_t full_blocks = len / 64;
  for (std::size_t i = 0; i < full_blocks; i++) {
    load(data + 64 * i);
    f(m, (std::uint64_t)i);
  }

  // Padding: 0x80, zeros, then the bit length as a 64-bit big-endian number.
  unsigned char tail[128] = {};
  const std::size_t rem = len % 64;
  std::memcpy(tail, data + 64 * full_blocks, rem);
  tail[rem] = 0x80;
  const std::size_t tail_len = rem < 56 ? 64 : 128;
  const std::uint64_t bits = (std::uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    tail[tail_len - 1 - i] = (unsigned char)(bits >> (8 * i));
  load(tail);
  f(m, (std::uint64_t)full_blocks);
  if (tail_len == 128) {
    load(tail + 64);
    f(m, (std::uint64_t)full_blocks + 1);
  }
}

Digest to_digest(const u32 h[8]) {
  Digest out;
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 4; j++)
      out[4 * i + j] = (unsigned char)(h[i] >> (24 - 8 * j));
  return out;
}

// One step processes one block: updates the chaining value h from the
// block's words m (which it may modify) and the block's index.
using Step = void (*)(u32 h[8], u32 m[16], std::uint64_t index, int rounds);

// Sequential (Merkle-Damgard) chaining, like SHA-256: block i's result feeds
// block i+1.
template <Step step>
Digest chain(const unsigned char *data, std::size_t len, int rounds) {
  u32 h[8];
  std::memcpy(h, H0, sizeof h);
  for_each_block(data, len, [&](u32 m[16], std::uint64_t i) {
    step(h, m, i, rounds);
  });
  return to_digest(h);
}

// Parallel: every block is compressed on its own, starting from H0, and the
// results are XORed together. Blocks could be hashed on different cores.
template <Step step>
Digest parallel(const unsigned char *data, std::size_t len, int rounds) {
  u32 acc[8] = {};
  for_each_block(data, len, [&](u32 m[16], std::uint64_t i) {
    u32 h[8];
    std::memcpy(h, H0, sizeof h);
    step(h, m, i, rounds);
    for (int k = 0; k < 8; k++)
      acc[k] ^= h[k];
  });
  return to_digest(acc);
}

u32 word_sum(const u32 m[16]) {
  u32 sum = 0;
  for (int j = 0; j < 16; j++)
    sum += m[j];
  return sum;
}

// A different 32-bit mask for every (block index, word position).
u32 index_mask(std::uint64_t index, int j) {
  std::uint64_t z = index * 16 + (std::uint64_t)j + 1;
  z ^= z >> 33;
  z *= 0xff51afd7ed558ccdull;
  z ^= z >> 33;
  z *= 0xc4ceb9fe1a85ec53ull;
  z ^= z >> 33;
  return (u32)z;
}

// Four word operations; each one alone is one-to-one.
u32 word_op(int k, u32 w) {
  switch (k) {
  case 0:
    return rotr(w, 7);
  case 1:
    return w * 0x9e3779b1u;
  case 2:
    return w ^ (w >> 13);
  default:
    return w + 0x6a09e667u;
  }
}

// The same four operations, restricted to 30 bits.
constexpr u32 kMask30 = 0x3fffffff;
u32 word_op30(int k, u32 x) {
  switch (k) {
  case 0:
    return ((x >> 7) | (x << 23)) & kMask30;
  case 1:
    return (x * 0x9e3779b1u) & kMask30;
  case 2:
    return x ^ (x >> 13);
  default:
    return (x + 0x2a09e667u) & kMask30;
  }
}

// The word's own value mod 4 picks the operation. The operation may change
// those 2 bits, so two different words can end up equal.
u32 word_op_by_content(u32 w) { return word_op(w & 3, w); }

// Same idea, but the operation only touches the upper 30 bits. The 2 selector
// bits survive, so the original word can always be recovered.
u32 word_op_by_content_safe(u32 w) {
  return word_op30(w & 3, w >> 2) << 2 | (w & 3);
}

// ---- Steps -----------------------------------------------------------------

void step_plain(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  compress(h, m, base_params(rounds));
}

// Index-based.
void step_idx_whiten(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  for (int j = 0; j < 16; j++)
    m[j] ^= index_mask(i, j);
  compress(h, m, base_params(rounds));
}
void step_idx_counter(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  Params p = base_params(rounds);
  p.counter = i + 1;
  compress(h, m, p);
}
void step_idx_rotset(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  Params p = base_params(rounds);
  p.sigma_set = (int)(i & 3);
  compress(h, m, p);
}
void step_idx_constants(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  Params p = base_params(rounds);
  p.k_offset = 16 * (int)(i & 3);
  compress(h, m, p);
}
void step_idx_permute(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  Params p = base_params(rounds);
  p.perm = (int)(i & 3);
  compress(h, m, p);
}
void step_idx_word_op(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  for (int j = 0; j < 16; j++)
    m[j] = word_op((int)((i + j) & 3), m[j]);
  compress(h, m, base_params(rounds));
}
void step_idx_all(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  Params p = base_params(rounds);
  const int sel = (int)(i & 3);
  p.sigma_set = sel;
  p.k_offset = 16 * sel;
  p.perm = sel;
  compress(h, m, p);
}

// Content-based.
void step_cnt_rotset(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  Params p = base_params(rounds);
  p.sigma_set = (int)(word_sum(m) & 3);
  compress(h, m, p);
}
void step_cnt_constants(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  Params p = base_params(rounds);
  p.k_offset = 16 * (int)(word_sum(m) & 3);
  compress(h, m, p);
}
void step_cnt_permute(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  Params p = base_params(rounds);
  p.perm = (int)(word_sum(m) & 3);
  compress(h, m, p);
}
void step_cnt_all(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  Params p = base_params(rounds);
  const int sel = (int)(word_sum(m) & 3);
  p.sigma_set = sel;
  p.k_offset = 16 * sel;
  p.perm = sel;
  compress(h, m, p);
}
void step_cnt_word_op(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  for (int j = 0; j < 16; j++)
    m[j] = word_op_by_content(m[j]);
  compress(h, m, base_params(rounds));
}
void step_cnt_word_op_safe(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  for (int j = 0; j < 16; j++)
    m[j] = word_op_by_content_safe(m[j]);
  compress(h, m, base_params(rounds));
}
// Like RC5: each word is rotated by an amount taken from the previous
// (original) word. Going from the end keeps m[j-1] unmodified when used.
void step_cnt_word_rot(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  for (int j = 15; j >= 1; j--)
    m[j] = rotl(m[j], (int)(m[j - 1] & 31));
  compress(h, m, base_params(rounds));
}
void step_cnt_round_select(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  Params p = base_params(rounds);
  p.round_select = true;
  compress(h, m, p);
}
// The selector comes from the chaining value (the result of all previous
// blocks) instead of this block.
void step_cnt_chain_select(u32 h[8], u32 m[16], std::uint64_t, int rounds) {
  Params p = base_params(rounds);
  p.sigma_set = (int)(h[0] & 3);
  compress(h, m, p);
}

// Index + content.
void step_idx_cnt(u32 h[8], u32 m[16], std::uint64_t i, int rounds) {
  Params p = base_params(rounds);
  const int sel = (int)((i + word_sum(m)) & 3);
  p.sigma_set = sel;
  p.k_offset = 16 * sel;
  p.perm = sel;
  compress(h, m, p);
}

} // namespace

std::vector<Method> all_methods() {
  return {
      {"sha256", "baseline", "plain SHA-256", &chain<step_plain>, nullptr},

      {"idx-whiten", "index", "XOR every word with a mask made from the index",
       &chain<step_idx_whiten>, nullptr},
      {"idx-counter", "index", "mix the index into the working state (BLAKE2)",
       &chain<step_idx_counter>, nullptr},
      {"idx-rotset", "index", "index mod 4 picks the Σ rotation amounts",
       &chain<step_idx_rotset>, nullptr},
      {"idx-constants", "index", "index mod 4 picks where K starts",
       &chain<step_idx_constants>, nullptr},
      {"idx-permute", "index", "index mod 4 picks the word order",
       &chain<step_idx_permute>, nullptr},
      {"idx-word-op", "index", "(index + position) mod 4 picks a word op",
       &chain<step_idx_word_op>, nullptr},
      {"idx-all", "index", "index mod 4 picks Σ set, K start and word order",
       &chain<step_idx_all>, nullptr},

      {"cnt-rotset", "content", "sum of words mod 4 picks the Σ amounts",
       &chain<step_cnt_rotset>, nullptr},
      {"cnt-constants", "content", "sum of words mod 4 picks where K starts",
       &chain<step_cnt_constants>, nullptr},
      {"cnt-permute", "content", "sum of words mod 4 picks the word order",
       &chain<step_cnt_permute>, nullptr},
      {"cnt-all", "content", "sum mod 4 picks Σ set, K start and word order",
       &chain<step_cnt_all>, nullptr},
      {"cnt-word-op", "content", "each word mod 4 picks an op for that word",
       &chain<step_cnt_word_op>, &word_op_by_content},
      {"cnt-word-op-safe", "content",
       "same, but the op keeps the 2 selector bits",
       &chain<step_cnt_word_op_safe>, &word_op_by_content_safe},
      {"cnt-word-rot", "content", "rotate each word by the previous word mod 32",
       &chain<step_cnt_word_rot>, nullptr},
      {"cnt-round-select", "content", "every round: e mod 4 picks the Σ amounts",
       &chain<step_cnt_round_select>, nullptr},
      {"cnt-chain-select", "content",
       "previous blocks' result mod 4 picks the Σ amounts",
       &chain<step_cnt_chain_select>, nullptr},

      {"idx+cnt", "index+content", "(index + sum) mod 4 picks Σ, K, order",
       &chain<step_idx_cnt>, nullptr},

      {"par-xor", "parallel", "blocks hashed separately, results XORed",
       &parallel<step_plain>, nullptr},
      {"par-xor-cnt", "parallel", "same, block's sum mod 4 picks the Σ amounts",
       &parallel<step_cnt_rotset>, nullptr},
      {"par-xor-idx", "parallel", "same, index mixed in (counter)",
       &parallel<step_idx_counter>, nullptr},
  };
}

} // namespace philohash::chunk
