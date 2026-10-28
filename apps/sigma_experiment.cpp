// Scores every sigma-replacement variant (see sha256_variants.hpp) on:
//   avalanche  flip one bit of a texts/ file -> fraction of output bits that
//              change (ideal 0.5), and the worst single case
//   SAC        per output bit, how far its flip rate is from 0.5 (ideal ~0)
//   coll       24-bit-truncated collisions among hashes of "0".."131071",
//              relative to what a random function gives (ideal 1.0)
//   full       full 256-bit collisions in the same set (must be 0)
//   balance    how far any output bit's share of 1s is from 0.5 (ideal ~0)
//   sched      flip one bit of a 16-word block -> fraction of bits of the
//              message schedule W[16..63] that change. This is σ's job, and
//              is invisible in the hash-level tests above.
//   σ0 ones    share of 1 bits in the pattern's own output (ideal 0.5)
//   σ0 uniq    distinct outputs of the pattern on 2^20 distinct words
//              (100% = no information lost)
//   MB/s       hashing speed (best of several runs)
//
// Usage: sigma_experiment [--rounds 64,24] [--texts DIR] [--csv FILE]
#include "philohash/sha256_variants.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using philohash::variant::Digest;
using philohash::variant::u32;
using philohash::variant::Variant;

namespace {

constexpr int kMaxFlipsPerText = 4096;
constexpr std::size_t kCounterInputs = 1 << 17;
constexpr int kTruncBits = 24;
constexpr std::size_t kSigmaSamples = 1 << 20;
constexpr int kScheduleBlocks = 256;
constexpr std::size_t kSpeedBytes = 8 << 20;
constexpr int kSpeedRuns = 5;

struct Result {
  double aval_mean = 0;
  int aval_min = 256;
  double sac_dev = 0;
  double coll_ratio = 0;
  long full_coll = 0;
  double balance_dev = 0;
  double sched_mean = 0;
  double sigma_ones = 0;
  double sigma_uniq = 0;
  double mbps = 0;
  std::string verdict;
};

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

Digest run(const Variant &v, const std::string &s, int rounds) {
  return v.hash((const unsigned char *)s.data(), s.size(), rounds);
}

void avalanche(const Variant &v, int rounds,
               const std::vector<std::string> &texts, Result &r) {
  long trials = 0, flipped_total = 0;
  std::vector<long> flips_per_bit(256, 0);
  for (std::string text : texts) {
    const Digest base = run(v, text, rounds);
    const long bits = (long)text.size() * 8;
    const long step = std::max(1L, bits / kMaxFlipsPerText);
    for (long b = 0; b < bits; b += step) {
      text[b / 8] ^= (char)(1 << (b % 8));
      const Digest d = run(v, text, rounds);
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

void counter_inputs(const Variant &v, int rounds, Result &r) {
  std::vector<Digest> digests(kCounterInputs);
  std::vector<u32> truncated(kCounterInputs);
  std::vector<long> ones(256, 0);
  for (std::size_t i = 0; i < kCounterInputs; i++) {
    const Digest d = run(v, std::to_string(i), rounds);
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

void schedule_avalanche(const Variant &v, Result &r) {
  std::uint64_t state = 777;
  long trials = 0, changed = 0;
  for (int blk = 0; blk < kScheduleBlocks; blk++) {
    u32 block[16], base[64], w[64];
    for (u32 &x : block)
      x = (u32)splitmix64(state);
    v.schedule(block, base);
    for (int bit = 0; bit < 512; bit++) {
      block[bit / 32] ^= 1u << (bit % 32);
      v.schedule(block, w);
      block[bit / 32] ^= 1u << (bit % 32);
      for (int t = 16; t < 64; t++)
        changed += __builtin_popcount(base[t] ^ w[t]);
      trials++;
    }
  }
  r.sched_mean = (double)changed / (trials * 48.0 * 32.0);
}

void sigma_alone(const Variant &v, Result &r) {
  std::vector<u32> out(kSigmaSamples);
  long ones = 0;
  for (std::size_t i = 0; i < kSigmaSamples; i++) {
    // i -> i * odd constant is one-to-one, so all inputs are distinct.
    out[i] = v.sigma0((u32)i * 0x9e3779b1u + 0x7f4a7c15u);
    ones += __builtin_popcount(out[i]);
  }
  r.sigma_ones = (double)ones / (32.0 * kSigmaSamples);
  std::sort(out.begin(), out.end());
  const auto uniq = std::unique(out.begin(), out.end()) - out.begin();
  r.sigma_uniq = 100.0 * uniq / kSigmaSamples;
}

void speed(const Variant &v, int rounds, const std::vector<unsigned char> &buf,
           Result &r) {
  double best = 1e30;
  for (int run = 0; run < kSpeedRuns; run++) {
    const auto start = std::chrono::steady_clock::now();
    volatile unsigned char sink = v.hash(buf.data(), buf.size(), rounds)[0];
    (void)sink;
    const std::chrono::duration<double> sec =
        std::chrono::steady_clock::now() - start;
    best = std::min(best, sec.count());
  }
  r.mbps = buf.size() / 1e6 / best;
}

// Flags: A avalanche, S SAC, C truncated collisions, F a real collision found
// (in the counter set, or a one-bit flip that changed nothing), B bit balance,
// W message schedule clearly less mixed than standard SHA-256's 0.424.
// Thresholds are roughly 3-4 standard deviations from ideal.
std::string verdict(const Result &r) {
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
  if (r.sched_mean < 0.40)
    flags += 'W';
  return flags.empty() ? "ok" : "WEAK:" + flags;
}

std::vector<int> parse_rounds(const std::string &arg) {
  std::vector<int> rounds;
  std::stringstream ss(arg);
  std::string item;
  while (std::getline(ss, item, ','))
    rounds.push_back(std::stoi(item));
  return rounds;
}

} // namespace

int main(int argc, char **argv) {
  std::vector<int> rounds_list = {64, 24};
  fs::path texts_dir = PHILOHASH_TEXTS_DIR;
  fs::path csv_path = PHILOHASH_RESULTS_DIR "/sigma_experiment.csv";
  for (int i = 1; i + 1 < argc; i += 2) {
    const std::string opt = argv[i];
    if (opt == "--rounds")
      rounds_list = parse_rounds(argv[i + 1]);
    else if (opt == "--texts")
      texts_dir = argv[i + 1];
    else if (opt == "--csv")
      csv_path = argv[i + 1];
    else {
      std::cerr << "unknown option " << opt << '\n';
      return 1;
    }
  }

  const auto texts = load_texts(texts_dir);
  if (texts.empty()) {
    std::cerr << "no non-empty files in " << texts_dir << '\n';
    return 1;
  }
  std::vector<unsigned char> speed_buf(kSpeedBytes);
  std::uint64_t state = 1;
  for (auto &c : speed_buf)
    c = (unsigned char)splitmix64(state);

  fs::create_directories(csv_path.parent_path());
  std::ofstream csv(csv_path);
  csv << "rounds,pattern,scope,formula,avalanche_mean,avalanche_min,sac_dev,"
         "coll_ratio,full_coll,balance_dev,sched_mean,sigma0_ones,"
         "sigma0_uniq_pct,mbps,verdict\n";

  const auto variants = philohash::variant::all_variants();
  // Warm up the CPU (clock ramp-up) so the first variant's speed is not
  // understated.
  const auto warmup_start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - warmup_start <
         std::chrono::seconds(2))
    variants.front().hash(speed_buf.data(), speed_buf.size(), 64);

  for (int rounds : rounds_list) {
    std::printf("\n=== %d rounds ===\n", rounds);
    std::printf("%-15s %-8s %6s %4s %6s %6s %5s %6s %6s %7s %8s %7s  %s\n",
                "pattern", "scope", "aval", "min", "SAC", "coll", "full",
                "bal", "sched", "σ0ones", "σ0uniq%", "MB/s", "verdict");
    for (const auto &v : variants) {
      Result r;
      avalanche(v, rounds, texts, r);
      counter_inputs(v, rounds, r);
      schedule_avalanche(v, r);
      sigma_alone(v, r);
      speed(v, rounds, speed_buf, r);
      r.verdict = verdict(r);

      std::printf("%-15s %-8s %6.4f %4d %6.4f %6.3f %5ld %6.4f %6.4f %7.4f "
                  "%8.3f %7.1f  %s\n",
                  v.pattern.c_str(), v.scope.c_str(), r.aval_mean, r.aval_min,
                  r.sac_dev, r.coll_ratio, r.full_coll, r.balance_dev,
                  r.sched_mean, r.sigma_ones, r.sigma_uniq, r.mbps,
                  r.verdict.c_str());
      std::fflush(stdout);
      csv << rounds << ',' << v.pattern << ',' << v.scope << ",\""
          << v.formula << "\"," << r.aval_mean << ',' << r.aval_min << ','
          << r.sac_dev << ',' << r.coll_ratio << ',' << r.full_coll << ','
          << r.balance_dev << ',' << r.sched_mean << ',' << r.sigma_ones << ','
          << r.sigma_uniq << ',' << r.mbps << ',' << r.verdict << '\n';
    }
  }
  std::printf("\nCSV written to %s\n", csv_path.string().c_str());
  return 0;
}
