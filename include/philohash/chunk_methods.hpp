#ifndef PHILOHASH_CHUNK_METHODS_HPP
#define PHILOHASH_CHUNK_METHODS_HPP
// Experimental SHA-256-based hashes in which each chunk (64-byte block, or
// 32-bit word) is processed with a different operation, chosen
//   - by the chunk's index (position in the message), or
//   - by the chunk's content (e.g. its value mod 4 picks one of 4 operations),
// plus "parallel" designs that hash every block independently.
//
// All methods share SHA-256's compression function, so differences in the
// results come only from the per-chunk choices.
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace philohash::chunk {

using u32 = std::uint32_t;
using Digest = std::array<unsigned char, 32>;

struct Method {
  std::string name;  // e.g. "idx-rotset"
  std::string group; // "baseline", "index", "content", "index+content",
                     // "parallel"
  std::string description;
  // Hashes `len` bytes using `rounds` compression rounds (1..64; 64 = full).
  Digest (*hash)(const unsigned char *data, std::size_t len, int rounds);
  // For methods that transform every 32-bit message word on its own: that
  // transform, so it can be checked on all 2^32 inputs. nullptr otherwise.
  u32 (*word_map)(u32 w);
};

// Plain SHA-256 first, then every method.
std::vector<Method> all_methods();

} // namespace philohash::chunk

#endif
