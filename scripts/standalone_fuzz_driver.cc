// standalone_fuzz_driver.cc — AFL driver for libFuzzer-style harnesses.
//
// Links against an OSS-Fuzz target that exposes:
//     extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
//
// The driver reads the test input from the first CLI argument (AFL `@@`) or,
// if no argument is given, from stdin, then forwards it to the harness.
//
// Compile together with the harness (and your library), e.g.:
//   afl-clang-fast++ -fsanitize=address -g -O1 \
//       harness.cc standalone_fuzz_driver.cc <lib sources/lib.a> -o target

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static bool read_stream(FILE* f, std::vector<uint8_t>& out) {
  char tmp[4096];
  size_t n;
  while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) {
    out.insert(out.end(), tmp, tmp + n);
  }
  return !out.empty() || feof(f);
}

int main(int argc, char** argv) {
  std::vector<uint8_t> buf;

  if (argc > 1) {
    FILE* f = fopen(argv[1], "rb");
    if (f == nullptr) {
      return 0;
    }
    read_stream(f, buf);
    fclose(f);
  } else {
    read_stream(stdin, buf);
  }

  LLVMFuzzerTestOneInput(buf.data(), buf.size());
  return 0;
}
