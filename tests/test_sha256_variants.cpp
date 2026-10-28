// The "standard" variant at 64 rounds must be exactly SHA-256, otherwise the
// experiment framework itself is wrong and its comparisons mean nothing.
#include "philohash/sha256.hpp"
#include "philohash/sha256_variants.hpp"

#include <iostream>
#include <string>

int main() {
  const auto variants = philohash::variant::all_variants();
  const auto &standard = variants.front();
  if (standard.pattern != "standard") {
    std::cerr << "FAIL first variant is not the standard one\n";
    return 1;
  }

  int failures = 0;
  for (std::size_t len = 0; len <= 300; len++) {
    std::string input;
    for (std::size_t i = 0; i < len; i++)
      input += (char)(i * 31 + len);

    const auto expected = philohash::sha256_digest(input);
    const auto actual = standard.hash(
        (const unsigned char *)input.data(), input.size(), 64);
    if (actual != expected) {
      std::cerr << "FAIL length " << len << '\n';
      failures++;
    }
  }
  std::cout << (failures == 0 ? "ok   " : "FAIL ")
            << "standard variant == sha256 for lengths 0..300\n";
  return failures == 0 ? 0 : 1;
}
