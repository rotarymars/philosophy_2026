#include "bench.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iterator>
#include <thread>

namespace fs = std::filesystem;

namespace bench {
namespace {

constexpr int kMaxFlipsPerText = 4096;
constexpr std::size_t kCounterInputs = 1 << 17;
constexpr int kTruncBits = 24;
constexpr int kSpeedRuns = 5;

} // namespace

std::uint64_t splitmix64(std::uint64_t &state) {
  std::uint64_t z = (state += 0x9e3779b97f4a7c15ull);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

std::vector<std::string> load_texts(const fs::path &dir) {
  std::vector<fs::path> paths;
  for (const auto &entry : fs::directory_iterator(dir))
    if (entry.is_regular_file())
      paths.push_back(entry.path());
  std::sort(paths.begin(), paths.end());

  std::vector<std::string> texts;
  for (const auto &p : paths) {
    std::ifstream in(p, std::ios::binary);
    std::string s((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
    if (!s.empty())
      texts.push_back(std::move(s));
  }
  return texts;
}

Digest run(HashFn hash, const std::string &s, int rounds) {
  return hash((const unsigned char *)s.data(), s.size(), rounds);
}

int hamming(const Digest &a, const Digest &b) {
  int dist = 0;
  for (int i = 0; i < 32; i++)
    dist += __builtin_popcount(a[i] ^ b[i]);
  return dist;
}

void avalanche(HashFn hash, int rounds, const std::vector<std::string> &texts,
               OutputStats &r) {
  long trials = 0, flipped_total = 0;
  std::vector<long> flips_per_bit(256, 0);
  for (std::string text : texts) {
    const Digest base = run(hash, text, rounds);
    const long bits = (long)text.size() * 8;
    const long step = std::max(1L, bits / kMaxFlipsPerText);
    for (long b = 0; b < bits; b += step) {
      text[b / 8] ^= (char)(1 << (b % 8));
      const Digest d = run(hash, text, rounds);
      text[b / 8] ^= (char)(1 << (b % 8));

      int dist = 0;
      for (int i = 0; i < 32; i++) {
        const unsigned diff = base[i] ^ d[i];
        dist += __builtin_popcount(diff);
        for (int j = 0; j < 8; j++)
          if (diff >> (7 - j) & 1)
            flips_per_bit[8 * i + j]++;
      }
      flipped_total += dist;
      r.aval_min = std::min(r.aval_min, dist);
      trials++;
    }
  }
  r.aval_mean = (double)flipped_total / (256.0 * trials);
  for (long c : flips_per_bit)
    r.sac_dev = std::max(r.sac_dev, std::fabs((double)c / trials - 0.5));
}

void counter_inputs(HashFn hash, int rounds, OutputStats &r) {
  std::vector<Digest> digests(kCounterInputs);
  std::vector<u32> truncated(kCounterInputs);
  std::vector<long> ones(256, 0);
  for (std::size_t i = 0; i < kCounterInputs; i++) {
    const Digest d = run(hash, std::to_string(i), rounds);
    digests[i] = d;
    truncated[i] = ((u32)d[0] << 16 | (u32)d[1] << 8 | d[2]);
    for (int b = 0; b < 256; b++)
      ones[b] += d[b / 8] >> (7 - b % 8) & 1;
  }

  auto colliding_pairs = [](auto &xs) {
    std::sort(xs.begin(), xs.end());
    long pairs = 0, run_len = 1;
    for (std::size_t i = 1; i <= xs.size(); i++) {
      if (i < xs.size() && xs[i] == xs[i - 1]) {
        run_len++;
      } else {
        pairs += run_len * (run_len - 1) / 2;
        run_len = 1;
      }
    }
    return pairs;
  };
  const double n = (double)kCounterInputs;
  const double expected = n * (n - 1) / 2 / std::pow(2.0, kTruncBits);
  r.coll_ratio = colliding_pairs(truncated) / expected;
  r.full_coll = colliding_pairs(digests);
  for (long c : ones)
    r.balance_dev = std::max(r.balance_dev, std::fabs(c / n - 0.5));
}

std::string output_flags(const OutputStats &r) {
  std::string flags;
  if (std::fabs(r.aval_mean - 0.5) > 0.01)
    flags += 'A';
  if (r.sac_dev > 0.04)
    flags += 'S';
  if (std::fabs(r.coll_ratio - 1.0) > 0.15)
    flags += 'C';
  if (r.full_coll > 0 || r.aval_min == 0)
    flags += 'F';
  if (r.balance_dev > 0.01)
    flags += 'B';
  return flags;
}

double speed(HashFn hash, int rounds, const std::vector<unsigned char> &buf) {
  double best = 1e30;
  for (int run = 0; run < kSpeedRuns; run++) {
    const auto start = std::chrono::steady_clock::now();
    volatile unsigned char sink = hash(buf.data(), buf.size(), rounds)[0];
    (void)sink;
    const std::chrono::duration<double> sec =
        std::chrono::steady_clock::now() - start;
    best = std::min(best, sec.count());
  }
  return buf.size() / 1e6 / best;
}

void warm_up(HashFn hash, const std::vector<unsigned char> &buf) {
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < std::chrono::seconds(2))
    hash(buf.data(), buf.size(), 64);
}

std::vector<unsigned char> random_bytes(std::size_t n, std::uint64_t seed) {
  std::vector<unsigned char> buf(n);
  for (auto &c : buf)
    c = (unsigned char)splitmix64(seed);
  return buf;
}

MapStats exact_map(u32 (*f)(u32),
                   std::vector<std::atomic<std::uint64_t>> &seen) {
  for (auto &word : seen)
    word.store(0, std::memory_order_relaxed);

  const unsigned n_threads = std::max(1u, std::thread::hardware_concurrency());
  const std::uint64_t total = 1ull << 32;
  std::vector<std::uint64_t> ones(n_threads, 0);
  std::vector<std::thread> threads;
  for (unsigned t = 0; t < n_threads; t++) {
    threads.emplace_back([&, t] {
      const std::uint64_t lo = total * t / n_threads;
      const std::uint64_t hi = total * (t + 1) / n_threads;
      std::uint64_t local_ones = 0;
      for (std::uint64_t x = lo; x < hi; x++) {
        const u32 y = f((u32)x);
        seen[y >> 6].fetch_or(1ull << (y & 63), std::memory_order_relaxed);
        local_ones += __builtin_popcount(y);
      }
      ones[t] = local_ones;
    });
  }
  for (auto &th : threads)
    th.join();

  std::uint64_t distinct = 0, all_ones = 0;
  for (const auto &word : seen)
    distinct += __builtin_popcountll(word.load(std::memory_order_relaxed));
  for (std::uint64_t o : ones)
    all_ones += o;
  return {(double)all_ones / (32.0 * total), 100.0 * distinct / total};
}

} // namespace bench
