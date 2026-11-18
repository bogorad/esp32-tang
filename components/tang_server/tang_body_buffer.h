#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Accumulates an HTTP request body delivered in chunks (ESPHome's
// AsyncWebHandler::handleBody). Plain C++ so it can be tested on the host.
//
// ESPHome builds the request object on the stack, so its address is reused by
// consecutive requests. A client that aborts an upload leaves a half-filled
// buffer behind; chunk index 0 always starts a fresh body so that state never
// leaks into the next request.
constexpr size_t kTangMaxBodySize = 4096;

class TangBodyBuffer {
 public:
  enum class Status { kOk, kTooLarge, kMalformed, kIncomplete };

  void on_chunk(const uint8_t *data, size_t len, size_t index, size_t total);

  // Verdict for a request that declared `content_length` bytes.
  Status status(size_t content_length) const;

  // Move the body out (only valid when status() == kOk).
  std::string take();

 private:
  void reset();

  std::string body_;
  size_t expected_{0};
  bool complete_{false};
  bool malformed_{false};
  bool too_large_{false};
};
