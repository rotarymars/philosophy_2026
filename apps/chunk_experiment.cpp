// Scores every chunk method (see chunk_methods.hpp).
//
// Output tests (same as sigma_experiment, see bench.hpp):
//   aval, min, SAC, coll, full, bal
// Multi-block tests (most methods only differ from SHA-256 once a message has
// more than one block, and most texts/ files fit in one block):
//   long       flip one random bit of a random 1 KiB message (16 blocks):
//              share of output bits that change (ideal 0.5)
//   lmin       worst case of the above (0 = a real collision)
//   swap       hash(A|B) == hash(B|A) for random blocks A != B, out of 1000
//              (must be 0: reordering blocks must change the hash)
//   cancel     hash(A|A|C) == hash(B|B|C) for random A != B, out of 1000
//              (must be 0: repeated blocks must not cancel out)
// Word-op tests (only methods that transform each 32-bit word on its own):
//   uniq%      distinct outputs of that transform over all 2^32 inputs
//              (100% = one-to-one). If below 100%, the program also builds
//              two different messages with the same hash and verifies it.
//   MB/s       hashing speed: median of 7 passes over all methods in turn
//              (each pass: best of 5 runs), measured after the other tests
//
// Usage: chunk_experiment [--rounds 64,16] [--texts DIR] [--csv FILE]
#include "bench.hpp"
#include "philohash/chunk_methods.hpp"

#include <cmath>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using bench::Digest;
using bench::u32;
using philohash::chunk::Method;

namespace {

constexpr int kLongMessages = 64;
constexpr std::size_t kLongBytes = 1024;
constexpr int kFlipsPerLong = 128;
constexpr int kPairTrials = 1000;
constexpr std::size_t kSpeedBytes = 8 << 20;

struct BlockStats {
  double long_mean = 0;
  int long_min = 256;
  int swap_equal = 0;
  int cancel_equal = 0;
};

Digest run(const Method &m, const std::vector<unsigned char> &msg,
           int rounds) {
  return m.hash(msg.data(), msg.size(), rounds);
}

void multi_block(const Method &m, int rounds, BlockStats &r) {
  std::uint64_t state = 2024;
  long trials = 0, flipped = 0;
  for (int k = 0; k < kLongMessages; k++) {
    auto msg = bench::random_bytes(kLongBytes, bench::splitmix64(state));
    const Digest base = run(m, msg, rounds);
    for (int f = 0; f < kFlipsPerLong; f++) {
      const std::size_t bit = bench::splitmix64(state) % (kLongBytes * 8);
      msg[bit / 8] ^= (unsigned char)(1 << (bit % 8));
      const int dist = bench::hamming(base, run(m, msg, rounds));
      msg[bit / 8] ^= (unsigned char)(1 << (bit % 8));
      flipped += dist;
      r.long_min = std::min(r.long_min, dist);
      trials++;
    }
  }
  r.long_mean = (double)flipped / (256.0 * trials);

  for (int k = 0; k < kPairTrials; k++) {
    const auto a = bench::random_bytes(64, bench::splitmix64(state));
    const auto b = bench::random_bytes(64, bench::splitmix64(state));
    const auto c = bench::random_bytes(64, bench::splitmix64(state));
    auto cat = [](std::initializer_list<const std::vector<unsigned char> *> xs) {
      std::vector<unsigned char> out;
      for (const auto *x : xs)
        out.insert(out.end(), x->begin(), x->end());
      return out;
    };
    if (run(m, cat({&a, &b}), rounds) == run(m, cat({&b, &a}), rounds))
      r.swap_equal++;
    if (run(m, cat({&a, &a, &c}), rounds) == run(m, cat({&b, &b, &c}), rounds))
      r.cancel_equal++;
  }
}

// Finds two different words that the word transform maps to the same value,
// then checks that the one-word messages made from them really get the same
// full hash.
void collision_demo(const Method &m) {
  std::vector<std::uint64_t> seen(1ull << 26, 0);
  u32 x2 = 0, target = 0;
  bool found = false;
  for (std::uint64_t x = 0; x < (1ull << 32) && !found; x++) {
    const u32 y = m.word_map((u32)x);
    if (seen[y >> 6] >> (y & 63) & 1) {
      x2 = (u32)x;
      target = y;
      found = true;
    }
    seen[y >> 6] |= 1ull << (y & 63);
  }
  if (!found)
    return;
  u32 x1 = 0;
  while (m.word_map(x1) != target || x1 == x2)
    x1++;

  auto bytes = [](u32 x) {
    return std::vector<unsigned char>{(unsigned char)(x >> 24),
                                      (unsigned char)(x >> 16),
                                      (unsigned char)(x >> 8), (unsigned char)x};
  };
  const Digest d1 = run(m, bytes(x1), 64);
  const Digest d2 = run(m, bytes(x2), 64);
  std::printf("  %s collision: messages %08x and %08x -> ", m.name.c_str(),
              x1, x2);
  for (int i = 0; i < 8; i++)
    std::printf("%02x", d1[i]);
  std::printf("... %s\n", d1 == d2 ? "SAME full 64-round hash (verified)"
                                   : "different hashes (not a collision)");
}

// Output flags (see bench.hpp) plus:
// M multi-block avalanche off by more than 0.01 (F if a flip changed nothing),
// X swapping two blocks gave the same hash, K repeated blocks cancelled out,
// L the word transform loses information.
std::string verdict(const bench::OutputStats &o, const BlockStats &b,
                    double uniq) {
  std::string flags = bench::output_flags(o);
  if (std::fabs(b.long_mean - 0.5) > 0.01)
    flags += 'M';
  if (b.long_min == 0 && flags.find('F') == std::string::npos)
    flags += 'F';
  if (b.swap_equal > 0)
    flags += 'X';
  if (b.cancel_equal > 0)
    flags += 'K';
  if (uniq < 100.0)
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
  std::vector<int> rounds_list = {64, 16};
  fs::path texts_dir = PHILOHASH_TEXTS_DIR;
  fs::path csv_path = PHILOHASH_RESULTS_DIR "/chunk_experiment.csv";
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
  const auto methods = philohash::chunk::all_methods();

  // Word transforms: exact check on all 2^32 inputs, before speed tests.
  std::map<std::string, double> uniq;
  {
    std::vector<std::atomic<std::uint64_t>> seen(1ull << 26);
    for (const auto &m : methods) {
      uniq[m.name] = 100.0;
      if (!m.word_map)
        continue;
      std::fprintf(stderr, "checking %s on all 2^32 inputs...\n",
                   m.name.c_str());
      uniq[m.name] = bench::exact_map(m.word_map, seen).uniq;
    }
  }
  std::printf("Word transforms that lose information:\n");
  for (const auto &m : methods)
    if (m.word_map && uniq[m.name] < 100.0)
      collision_demo(m);

  fs::create_directories(csv_path.parent_path());
  std::ofstream csv(csv_path);
  csv << "rounds,method,group,description,avalanche_mean,avalanche_min,"
         "sac_dev,coll_ratio,full_coll,balance_dev,long_mean,long_min,"
         "swap_equal,cancel_equal,word_uniq_pct,mbps,verdict\n";

  std::vector<bench::HashFn> hashes;
  for (const auto &m : methods)
    hashes.push_back(m.hash);

  for (int rounds : rounds_list) {
    std::fprintf(stderr, "testing %d rounds...\n", rounds);
    std::vector<bench::OutputStats> outputs(methods.size());
    std::vector<BlockStats> blocks(methods.size());
    for (std::size_t i = 0; i < methods.size(); i++) {
      bench::avalanche(methods[i].hash, rounds, texts, outputs[i]);
      bench::counter_inputs(methods[i].hash, rounds, outputs[i]);
      multi_block(methods[i], rounds, blocks[i]);
    }
    bench::warm_up(methods.front().hash, speed_buf);
    const auto speeds = bench::speeds_interleaved(hashes, rounds, speed_buf);

    std::printf("\n=== %d rounds ===\n", rounds);
    std::printf("%-17s %-8s %6s %4s %6s %6s %4s %6s %6s %4s %4s %6s %7s %6s  "
                "%s\n",
                "method", "group", "aval", "min", "SAC", "coll", "full", "bal",
                "long", "lmin", "swap", "cancel", "uniq%", "MB/s", "verdict");
    for (std::size_t i = 0; i < methods.size(); i++) {
      const auto &m = methods[i];
      const auto &o = outputs[i];
      const auto &b = blocks[i];
      const double mbps = speeds[i];
      const std::string verd = verdict(o, b, uniq[m.name]);
      const std::string group = m.group.substr(0, 8);

      std::printf("%-17s %-8s %6.4f %4d %6.4f %6.3f %4ld %6.4f %6.4f %4d %4d "
                  "%6d %7.3f %6.1f  %s\n",
                  m.name.c_str(), group.c_str(), o.aval_mean, o.aval_min,
                  o.sac_dev, o.coll_ratio, o.full_coll, o.balance_dev,
                  b.long_mean, b.long_min, b.swap_equal, b.cancel_equal,
                  uniq[m.name], mbps, verd.c_str());
      std::fflush(stdout);
      csv << rounds << ',' << m.name << ',' << m.group << ",\""
          << m.description << "\"," << o.aval_mean << ',' << o.aval_min << ','
          << o.sac_dev << ',' << o.coll_ratio << ',' << o.full_coll << ','
          << o.balance_dev << ',' << b.long_mean << ',' << b.long_min << ','
          << b.swap_equal << ',' << b.cancel_equal << ',' << uniq[m.name]
          << ',' << mbps << ',' << verd << '\n';
    }
  }
  std::printf("\nCSV written to %s\n", csv_path.string().c_str());
  return 0;
}
