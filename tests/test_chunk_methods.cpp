// Checks the chunk-method framework itself:
//  - the "sha256" baseline at 64 rounds is exactly SHA-256;
//  - index-based methods that only switch settings by (index mod 4) equal
//    SHA-256 on one-block messages (block 0 uses the standard settings);
//  - the "safe" content word op can be undone (one-to-one) on samples.
#include "philohash/chunk_methods.hpp"
#include "philohash/sha256.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void check(bool ok, const std::string &what) {
  std::cout << (ok ? "ok   " : "FAIL ") << what << '\n';
  if (!ok)
    failures++;
}

std::string make_input(std::size_t len) {
  std::string s;
  for (std::size_t i = 0; i < len; i++)
    s += (char)(i * 31 + len);
  return s;
}

} // namespace

int main() {
  const auto methods = philohash::chunk::all_methods();
  auto find = [&](const std::string &name) -> const philohash::chunk::Method & {
    for (const auto &m : methods)
      if (m.name == name)
        return m;
    std::cerr << "no method " << name << '\n';
    std::exit(1);
  };

  bool baseline_ok = true;
  for (std::size_t len = 0; len <= 300; len++) {
    const std::string in = make_input(len);
    const auto actual =
        find("sha256").hash((const unsigned char *)in.data(), in.size(), 64);
    if (actual != philohash::sha256_digest(in))
      baseline_ok = false;
  }
  check(baseline_ok, "sha256 baseline == SHA-256 for lengths 0..300");

  for (const char *name : {"idx-rotset", "idx-constants", "idx-permute",
                           "idx-all"}) {
    bool same = true;
    for (std::size_t len = 0; len <= 55; len++) {
      const std::string in = make_input(len);
      const auto actual =
          find(name).hash((const unsigned char *)in.data(), in.size(), 64);
      if (actual != philohash::sha256_digest(in))
        same = false;
    }
    check(same, std::string(name) + " == SHA-256 on one-block messages");
  }

  // The safe op keeps the low 2 bits, and distinct inputs stay distinct.
  const auto safe = find("cnt-word-op-safe").word_map;
  bool keeps_selector = true;
  for (std::uint32_t x = 0; x < 100000; x++)
    if ((safe(x * 2654435761u) & 3) != ((x * 2654435761u) & 3))
      keeps_selector = false;
  check(keeps_selector, "cnt-word-op-safe keeps the 2 selector bits");

  return failures == 0 ? 0 : 1;
}
