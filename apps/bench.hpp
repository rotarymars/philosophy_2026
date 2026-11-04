#ifndef PHILOHASH_BENCH_HPP
#define PHILOHASH_BENCH_HPP
// Statistical tests shared by the experiment programs. Every hash under test
// is a function (data, len, rounds) -> 256-bit digest.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace bench {

using u32 = std::uint32_t;
using Digest = std::array<unsigned char, 32>;
using HashFn = Digest (*)(const unsigned char *data, std::size_t len,
                          int rounds);

std::uint64_t splitmix64(std::uint64_t &state);

// Non-empty regular files in `dir`, sorted by name.
std::vector<std::string> load_texts(const std::filesystem::path &dir);

Digest run(HashFn hash, const std::string &s, int rounds);

int hamming(const Digest &a, const Digest &b);

struct OutputStats {
  double aval_mean = 0;   // flip one bit of a text: share of output bits flipped
  int aval_min = 256;     // worst case of the above (0 = a real collision)
  double sac_dev = 0;     // worst output bit's distance from flipping 50%
  double coll_ratio = 0;  // 24-bit collisions on "0".."131071" vs random
  long full_coll = 0;     // full 256-bit collisions in that set
  double balance_dev = 0; // worst output bit's distance from being 1 50%
};

void avalanche(HashFn hash, int rounds, const std::vector<std::string> &texts,
               OutputStats &r);
void counter_inputs(HashFn hash, int rounds, OutputStats &r);

// Flags: A avalanche, S SAC, C truncated collisions, F a real collision found
// (in the counter set, or a one-bit flip that changed nothing), B bit balance.
// Thresholds are roughly 3-4 standard deviations from ideal.
std::string output_flags(const OutputStats &r);

// MB/s, best of several runs over `buf`.
double speed(HashFn hash, int rounds, const std::vector<unsigned char> &buf);

// MB/s for each hash: the median over `passes` passes, where every pass
// measures all hashes in turn. Interleaving keeps slow periods of the machine
// from landing on just one hash.
std::vector<double> speeds_interleaved(const std::vector<HashFn> &hashes,
                                       int rounds,
                                       const std::vector<unsigned char> &buf,
                                       int passes = 7);

// Makes the CPU reach its full clock before speed measurements.
void warm_up(HashFn hash, const std::vector<unsigned char> &buf);

// Pseudo-random bytes for speed measurements.
std::vector<unsigned char> random_bytes(std::size_t n, std::uint64_t seed);

struct MapStats {
  double ones; // share of 1 bits over all outputs
  double uniq; // distinct outputs / 2^32, in percent
};

// Evaluates a 32-bit function on every one of the 2^32 inputs, marking each
// output in `seen` (2^26 words = 512 MiB), split across all CPU cores.
// (Sampling is not enough: a 2^20 sample once reported a function as
// one-to-one when it reaches only 50% of outputs.)
MapStats exact_map(u32 (*f)(u32), std::vector<std::atomic<std::uint64_t>> &seen);

} // namespace bench

#endif
