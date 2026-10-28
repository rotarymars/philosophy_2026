#ifndef PHILOHASH_SHA256_VARIANTS_HPP
#define PHILOHASH_SHA256_VARIANTS_HPP
// Experimental SHA-256 in which the sigma functions are replaced by other bit
// operations, and the number of rounds can be reduced.
//
//   small sigma (σ0, σ1): used in the message schedule
//   big sigma   (Σ0, Σ1): used in the compression rounds
//
// Each Variant applies one replacement pattern to σ only, Σ only, or both.
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace philohash::variant {

using u32 = std::uint32_t;
using Digest = std::array<unsigned char, 32>;

struct Variant {
  std::string pattern; // e.g. "comb-and"
  std::string scope;   // "standard", "small" (σ only), "big" (Σ only), "both"
  std::string formula; // how the replacement is computed
  // Hashes `len` bytes using the first `rounds` rounds (1..64; 64 = full).
  Digest (*hash)(const unsigned char *data, std::size_t len, int rounds);
  // The pattern applied with σ0's amounts (7, 18, 3), for inspecting it alone.
  u32 (*sigma0)(u32 x);
  // Expands one block (16 words) into the 64-word message schedule W.
  void (*schedule)(const u32 block[16], u32 w[64]);
};

// The real SHA-256 first, then every pattern in every scope.
std::vector<Variant> all_variants();

} // namespace philohash::variant

#endif
