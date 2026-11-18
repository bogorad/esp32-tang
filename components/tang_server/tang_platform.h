#pragma once

#include <cstdint>

class TangClock {
 public:
  virtual ~TangClock() = default;
  // Monotonic milliseconds since boot. 64-bit so key lifetimes never wrap
  // (a 32-bit counter wraps after 49.7 days).
  virtual uint64_t millis() const = 0;
};

class TangLogger {
 public:
  virtual ~TangLogger() = default;
  virtual void debug(const char *message) = 0;
  virtual void warn(const char *message) = 0;
  virtual void error(const char *message) = 0;
};
