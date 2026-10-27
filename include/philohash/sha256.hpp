#ifndef PHILOHASH_SHA256_HPP
#define PHILOHASH_SHA256_HPP
// SHA-256, copied from atcoder-competitive_programming/template/sha256.hpp and
// split into a header/source pair so it can be built as a library.
#include <array>
#include <string>

namespace philohash {

class hash_functions {
protected:
  typedef unsigned char register_8;
  typedef unsigned int register_32;
  typedef unsigned long long register_64;

  const static register_32 hash_keys[];
  static const unsigned int BLOCK_SIZE_of_256 = (512 / 8);

public:
  void stateregister();
  void adjust_digest(const unsigned char *text, register_64 text_len);
  void digest_final(unsigned char *digest);
  static const unsigned int PADD_SIZE = (256 / 8);

protected:
  void compress(const unsigned char *message, register_64 block_nb);
  register_64 s_r_totlen;
  unsigned int s_r_len;
  unsigned char s_r_block[2 * BLOCK_SIZE_of_256];
  register_32 s_r[8];
};

// Raw 32-byte digest.
std::array<unsigned char, hash_functions::PADD_SIZE>
sha256_digest(const std::string &input);

// Lowercase hex string (64 characters), same as `sha256sum`.
std::string sha256(const std::string &input);

} // namespace philohash

#endif
