// Checks the SHA-256 implementation against the NIST test vectors plus a few
// lengths around the 64-byte block / 56-byte padding boundaries.
#include "philohash/sha256.hpp"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(const std::string &name, const std::string &input,
            const std::string &expected) {
  const std::string actual = philohash::sha256(input);
  if (actual != expected) {
    std::cerr << "FAIL " << name << "\n  expected " << expected
              << "\n  actual   " << actual << '\n';
    ++failures;
  } else {
    std::cout << "ok   " << name << '\n';
  }
}

} // namespace

int main() {
  expect("empty", "",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  expect("abc", "abc",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  expect("448-bit", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  expect("896-bit",
         "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklm"
         "nopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
  expect("55 x 'a'", std::string(55, 'a'),
         "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
  expect("56 x 'a'", std::string(56, 'a'),
         "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
  expect("64 x 'a'", std::string(64, 'a'),
         "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
  expect("1,000,000 x 'a'", std::string(1000000, 'a'),
         "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

  return failures == 0 ? 0 : 1;
}
