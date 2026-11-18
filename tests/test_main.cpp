#include <cstring>

#include "test_framework.h"

namespace tt {
std::vector<TestCase> &registry() {
  static std::vector<TestCase> r;
  return r;
}
int &failure_count() {
  static int n = 0;
  return n;
}
}  // namespace tt

int main(int argc, char **argv) {
  const char *filter = argc > 1 ? argv[1] : nullptr;
  int ran = 0;
  int failed_tests = 0;
  for (const auto &t : tt::registry()) {
    if (filter != nullptr && std::strstr(t.name, filter) == nullptr) {
      continue;
    }
    const int before = tt::failure_count();
    std::printf("[ RUN  ] %s\n", t.name);
    std::fflush(stdout);
    t.fn();
    ++ran;
    if (tt::failure_count() != before) {
      ++failed_tests;
      std::printf("[ FAIL ] %s\n", t.name);
    } else {
      std::printf("[  OK  ] %s\n", t.name);
    }
  }
  std::printf("%d tests run, %d failed\n", ran, failed_tests);
  if (ran == 0) {
    std::fprintf(stderr, "no tests matched\n");
    return 2;
  }
  return failed_tests == 0 ? 0 : 1;
}
