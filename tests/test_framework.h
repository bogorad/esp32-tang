#pragma once

// Minimal test framework: no dependencies, fails loudly.

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

namespace tt {

struct TestCase {
  const char *name;
  std::function<void()> fn;
};

std::vector<TestCase> &registry();
int &failure_count();

struct Registrar {
  Registrar(const char *name, std::function<void()> fn) {
    registry().push_back({name, std::move(fn)});
  }
};

}  // namespace tt

#define TEST(name)                                         \
  static void test_##name();                               \
  static tt::Registrar registrar_##name(#name, test_##name); \
  static void test_##name()

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "  CHECK failed: %s (%s:%d)\n", #cond,       \
                   __FILE__, __LINE__);                                 \
      ++tt::failure_count();                                            \
    }                                                                   \
  } while (0)

#define CHECK_EQ(a, b)                                                  \
  do {                                                                  \
    const auto &va_ = (a);                                              \
    const auto &vb_ = (b);                                              \
    if (!(va_ == vb_)) {                                                \
      std::fprintf(stderr, "  CHECK_EQ failed: %s == %s (%s:%d)\n", #a, \
                   #b, __FILE__, __LINE__);                             \
      ++tt::failure_count();                                            \
    }                                                                   \
  } while (0)

// Abort the current test (not the process) on a fatal precondition failure.
#define REQUIRE(cond)                                                   \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "  REQUIRE failed: %s (%s:%d)\n", #cond,     \
                   __FILE__, __LINE__);                                 \
      ++tt::failure_count();                                            \
      return;                                                           \
    }                                                                   \
  } while (0)
