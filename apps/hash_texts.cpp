#include "philohash/sha256.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string read_file(const fs::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    throw std::runtime_error("cannot open " + path.string());
  return std::string(std::istreambuf_iterator<char>(in),
                     std::istreambuf_iterator<char>());
}

std::vector<fs::path> collect_inputs(const std::vector<fs::path> &args) {
  std::vector<fs::path> files;
  for (const auto &arg : args) {
    if (fs::is_directory(arg)) {
      std::vector<fs::path> in_dir;
      for (const auto &entry : fs::directory_iterator(arg))
        if (entry.is_regular_file())
          in_dir.push_back(entry.path());
      std::sort(in_dir.begin(), in_dir.end());
      files.insert(files.end(), in_dir.begin(), in_dir.end());
    } else {
      files.push_back(arg);
    }
  }
  return files;
}

} // namespace

int main(int argc, char **argv) {
  std::vector<fs::path> args(argv + 1, argv + argc);
  if (args.empty())
    args.push_back(PHILOHASH_TEXTS_DIR);

  int status = 0;
  for (const auto &path : collect_inputs(args)) {
    try {
      std::cout << philohash::sha256(read_file(path)) << "  " << path.string()
                << '\n';
    } catch (const std::exception &e) {
      std::cerr << "hash_texts: " << e.what() << '\n';
      status = 1;
    }
  }
  return status;
}
