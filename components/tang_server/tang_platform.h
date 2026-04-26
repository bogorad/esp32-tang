#pragma once

#include <cstdint>

class TangClock {
 public:
  virtual ~TangClock() = default;
  virtual uint32_t millis() const = 0;
};

class TangLogger {
 public:
  virtual ~TangLogger() = default;
  virtual void debug(const char *message) = 0;
  virtual void warn(const char *message) = 0;
};
