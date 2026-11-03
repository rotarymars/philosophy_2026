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
//   σ0 uniq    distinct outputs of the pattern over all 2^32 inputs
//              (100% = one-to-one, no information lost). Exact, not sampled.
//   MB/s       hashing speed (best of several runs)
//
// Usage: sigma_experiment [--rounds 64,24] [--texts DIR] [--csv FILE]
#include "bench.hpp"
#include "philohash/sha256_variants.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using bench::u32;
using philohash::variant::Variant;

namespace {

constexpr int kScheduleBlocks = 256;
constexpr std::size_t kSpeedBytes = 8 << 20;

double schedule_avalanche(const Variant &v) {
  std::uint64_t state = 777;
  long trials = 0, changed = 0;
  for (int blk = 0; blk < kScheduleBlocks; blk++) {
    u32 block[16], base[64], w[64];
    for (u32 &x : block)
      x = (u32)bench::splitmix64(state);
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
  return (double)changed / (trials * 48.0 * 32.0);
}

// Output flags (see bench.hpp) plus:
// W message schedule clearly less mixed than standard SHA-256's 0.424,
// L the pattern itself loses information (not one-to-one on 32-bit words).
std::string verdict(const bench::OutputStats &r, double sched_mean,
                    double sigma_uniq) {
  std::string flags = bench::output_flags(r);
  if (sched_mean < 0.40)
    flags += 'W';
  if (sigma_uniq < 100.0)
    flags += 'L';
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

  const auto texts = bench::load_texts(texts_dir);
  if (texts.empty()) {
    std::cerr << "no non-empty files in " << texts_dir << '\n';
    return 1;
  }
  const auto speed_buf = bench::random_bytes(kSpeedBytes, 1);

  fs::create_directories(csv_path.parent_path());
  std::ofstream csv(csv_path);
  csv << "rounds,pattern,scope,formula,avalanche_mean,avalanche_min,sac_dev,"
         "coll_ratio,full_coll,balance_dev,sched_mean,sigma0_ones,"
         "sigma0_uniq_pct,mbps,verdict\n";

  const auto variants = philohash::variant::all_variants();

  // The pattern's own properties do not depend on scope or rounds, so the
  // exhaustive check runs once per pattern, before any speed measurement.
  std::map<std::string, bench::MapStats> sigma_stats;
  {
    std::vector<std::atomic<std::uint64_t>> seen(1ull << 26);
    for (const auto &v : variants) {
      if (sigma_stats.count(v.pattern))
        continue;
      std::fprintf(stderr, "checking %s on all 2^32 inputs...\n",
                   v.pattern.c_str());
      sigma_stats[v.pattern] = bench::exact_map(v.sigma0, seen);
    }
  }

  bench::warm_up(variants.front().hash, speed_buf);

  for (int rounds : rounds_list) {
    std::printf("\n=== %d rounds ===\n", rounds);
    std::printf("%-15s %-8s %6s %4s %6s %6s %5s %6s %6s %7s %8s %7s  %s\n",
                "pattern", "scope", "aval", "min", "SAC", "coll", "full",
                "bal", "sched", "σ0ones", "σ0uniq%", "MB/s", "verdict");
    for (const auto &v : variants) {
      bench::OutputStats r;
      bench::avalanche(v.hash, rounds, texts, r);
      bench::counter_inputs(v.hash, rounds, r);
      const double sched = schedule_avalanche(v);
      const auto &sig = sigma_stats[v.pattern];
      const double mbps = bench::speed(v.hash, rounds, speed_buf);
      const std::string verd = verdict(r, sched, sig.uniq);

      std::printf("%-15s %-8s %6.4f %4d %6.4f %6.3f %5ld %6.4f %6.4f %7.4f "
                  "%8.3f %7.1f  %s\n",
                  v.pattern.c_str(), v.scope.c_str(), r.aval_mean, r.aval_min,
                  r.sac_dev, r.coll_ratio, r.full_coll, r.balance_dev, sched,
                  sig.ones, sig.uniq, mbps, verd.c_str());
      std::fflush(stdout);
      csv << rounds << ',' << v.pattern << ',' << v.scope << ",\""
          << v.formula << "\"," << r.aval_mean << ',' << r.aval_min << ','
          << r.sac_dev << ',' << r.coll_ratio << ',' << r.full_coll << ','
          << r.balance_dev << ',' << sched << ',' << sig.ones << ','
          << sig.uniq << ',' << mbps << ',' << verd << '\n';
    }
  }
  std::printf("\nCSV written to %s\n", csv_path.string().c_str());
  return 0;
}
