#include "philohash/sha256_variants.hpp"

#include <cstring>

namespace philohash::variant {
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

// The three amounts of one sigma function; shift[i] marks a SHR term
// (the rest are ROTR).
struct Spec {
  int n[3];
  bool shift[3];
};
constexpr Spec kSmall0{{7, 18, 3}, {false, false, true}};
constexpr Spec kSmall1{{17, 19, 10}, {false, false, true}};
constexpr Spec kBig0{{2, 13, 22}, {false, false, false}};
constexpr Spec kBig1{{6, 11, 25}, {false, false, false}};

constexpr u32 rotr(u32 x, int n) { return (x >> n) | (x << ((32 - n) & 31)); }

// Term patterns: what each ROTR(x, n) / SHR(x, n) is replaced with.
namespace term {
struct Standard {
  static constexpr u32 f(u32 x, int n, bool shift) {
    return shift ? x >> n : rotr(x, n);
  }
};
struct ShrOnly {
  static constexpr u32 f(u32 x, int n, bool) { return x >> n; }
};
struct ShlOnly {
  static constexpr u32 f(u32 x, int n, bool) { return x << n; }
};
struct RotrOnly {
  static constexpr u32 f(u32 x, int n, bool) { return rotr(x, n); }
};
struct AndSelf {
  static constexpr u32 f(u32 x, int n, bool s) {
    return x & Standard::f(x, n, s);
  }
};
struct OrSelf {
  static constexpr u32 f(u32 x, int n, bool s) {
    return x | Standard::f(x, n, s);
  }
};
struct XorSelf {
  static constexpr u32 f(u32 x, int n, bool s) {
    return x ^ Standard::f(x, n, s);
  }
};
struct Not {
  static constexpr u32 f(u32 x, int n, bool s) { return ~Standard::f(x, n, s); }
};
// Bits stay where they are; only a fixed subset of them is kept.
struct AndMask {
  static constexpr u32 f(u32 x, int n, bool) {
    return x & rotr(0x0f0f0f0f, n);
  }
};
} // namespace term

// Combiners: how the three terms are merged into one word.
namespace combine {
struct Xor {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return a ^ b ^ c; }
};
struct And {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return a & b & c; }
};
struct Or {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return a | b | c; }
};
struct AndXor {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return (a & b) ^ c; }
};
struct OrXor {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return (a | b) ^ c; }
};
struct Maj {
  static constexpr u32 f(u32 a, u32 b, u32 c) {
    return (a & b) ^ (a & c) ^ (b & c);
  }
};
struct Ch {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return (a & b) ^ (~a & c); }
};
struct Add {
  static constexpr u32 f(u32 a, u32 b, u32 c) { return a + b + c; }
};
} // namespace combine

template <class Term, class Comb> struct Pattern {
  static constexpr u32 f(u32 x, const Spec &s) {
    return Comb::f(Term::f(x, s.n[0], s.shift[0]),
                   Term::f(x, s.n[1], s.shift[1]),
                   Term::f(x, s.n[2], s.shift[2]));
  }
};

// Whole-function replacements that ignore the amounts.
namespace whole {
struct Identity {
  static constexpr u32 f(u32 x, const Spec &) { return x; }
};
struct Zero {
  static constexpr u32 f(u32, const Spec &) { return 0; }
};
struct Not {
  static constexpr u32 f(u32 x, const Spec &) { return ~x; }
};
struct Mul {
  static constexpr u32 f(u32 x, const Spec &) { return x * 0x9e3779b1u; }
};
} // namespace whole

using Std = Pattern<term::Standard, combine::Xor>;

// Fills w[16..rounds-1] from w[0..15] (the message schedule).
template <class Small> void expand(u32 w[64], int rounds) {
  for (int t = 16; t < rounds; t++)
    w[t] = Small::f(w[t - 2], kSmall1) + w[t - 7] +
           Small::f(w[t - 15], kSmall0) + w[t - 16];
}

template <class Small> void schedule_of(const u32 block[16], u32 w[64]) {
  std::memcpy(w, block, 16 * sizeof(u32));
  expand<Small>(w, 64);
}

template <class Small, class Big>
Digest hash(const unsigned char *data, std::size_t len, int rounds) {
  if (rounds < 1)
    rounds = 1;
  if (rounds > 64)
    rounds = 64;

  u32 h[8];
  std::memcpy(h, H0, sizeof h);

  auto compress = [&](const unsigned char *block) {
    u32 w[64];
    for (int t = 0; t < 16; t++)
      w[t] = (u32)block[4 * t] << 24 | (u32)block[4 * t + 1] << 16 |
             (u32)block[4 * t + 2] << 8 | (u32)block[4 * t + 3];
    expand<Small>(w, rounds);

    u32 s[8];
    std::memcpy(s, h, sizeof s);
    for (int t = 0; t < rounds; t++) {
      u32 t1 = s[7] + Big::f(s[4], kBig1) + ((s[4] & s[5]) ^ (~s[4] & s[6])) +
               K[t] + w[t];
      u32 t2 = Big::f(s[0], kBig0) +
               ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
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
  };

  const std::size_t full_blocks = len / 64;
  for (std::size_t i = 0; i < full_blocks; i++)
    compress(data + 64 * i);

  // Padding: 0x80, zeros, then the bit length as a 64-bit big-endian number.
  unsigned char tail[128] = {};
  const std::size_t rem = len % 64;
  std::memcpy(tail, data + 64 * full_blocks, rem);
  tail[rem] = 0x80;
  const std::size_t tail_len = rem < 56 ? 64 : 128;
  const std::uint64_t bits = (std::uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    tail[tail_len - 1 - i] = (unsigned char)(bits >> (8 * i));
  compress(tail);
  if (tail_len == 128)
    compress(tail + 64);

  Digest out;
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 4; j++)
      out[4 * i + j] = (unsigned char)(h[i] >> (24 - 8 * j));
  return out;
}

template <class P> u32 sigma0_of(u32 x) { return P::f(x, kSmall0); }

template <class P>
void add(std::vector<Variant> &out, const char *pattern, const char *formula) {
  out.push_back({pattern, "small", formula, &hash<P, Std>, &sigma0_of<P>,
                 &schedule_of<P>});
  out.push_back({pattern, "big", formula, &hash<Std, P>, &sigma0_of<P>,
                 &schedule_of<Std>});
  out.push_back({pattern, "both", formula, &hash<P, P>, &sigma0_of<P>,
                 &schedule_of<P>});
}

} // namespace

std::vector<Variant> all_variants() {
  using namespace combine;
  std::vector<Variant> v;
  v.push_back({"standard", "standard", "ROTR(x,a) ^ ROTR(x,b) ^ ROTR/SHR(x,c)",
               &hash<Std, Std>, &sigma0_of<Std>, &schedule_of<Std>});

  // Keep the three rotations/shifts, change how they are combined.
  add<Pattern<term::Standard, And>>(v, "comb-and", "t1 & t2 & t3");
  add<Pattern<term::Standard, Or>>(v, "comb-or", "t1 | t2 | t3");
  add<Pattern<term::Standard, AndXor>>(v, "comb-and-xor", "(t1 & t2) ^ t3");
  add<Pattern<term::Standard, OrXor>>(v, "comb-or-xor", "(t1 | t2) ^ t3");
  add<Pattern<term::Standard, Maj>>(v, "comb-maj", "majority(t1, t2, t3)");
  add<Pattern<term::Standard, Ch>>(v, "comb-ch", "t1 ? t2 : t3 (bitwise)");
  add<Pattern<term::Standard, Add>>(v, "comb-add", "t1 + t2 + t3 (mod 2^32)");

  // Keep XOR, replace each rotation/shift term with something else.
  add<Pattern<term::ShrOnly, Xor>>(v, "term-shr", "SHR only (no wrap-around)");
  add<Pattern<term::ShlOnly, Xor>>(v, "term-shl", "SHL only (left shifts)");
  add<Pattern<term::RotrOnly, Xor>>(v, "term-rotr", "ROTR only (no SHR)");
  add<Pattern<term::AndSelf, Xor>>(v, "term-and-self", "x & ROT/SHR(x,n)");
  add<Pattern<term::OrSelf, Xor>>(v, "term-or-self", "x | ROT/SHR(x,n)");
  add<Pattern<term::XorSelf, Xor>>(v, "term-xor-self", "x ^ ROT/SHR(x,n)");
  add<Pattern<term::Not, Xor>>(v, "term-not", "~ROT/SHR(x,n)");
  add<Pattern<term::AndMask, Xor>>(v, "term-and-mask",
                                   "x & ROTR(0x0f0f0f0f,n) (bits never move)");

  // Replace the whole function.
  add<whole::Identity>(v, "whole-identity", "x");
  add<whole::Zero>(v, "whole-zero", "0");
  add<whole::Not>(v, "whole-not", "~x");
  add<whole::Mul>(v, "whole-mul", "x * 0x9e3779b1 (mod 2^32)");
  return v;
}

} // namespace philohash::variant
