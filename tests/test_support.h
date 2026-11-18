#pragma once

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "tang_core.h"
#include "tang_crypto.h"
#include "tang_record.h"
#include "test_framework.h"
#include "test_util.h"

namespace tt {

class MockClock : public TangClock {
 public:
  uint64_t now{1000};
  uint64_t millis() const override { return now; }
};

// Thread-safe: the concurrency test logs from several threads at once.
class MockLogger : public TangLogger {
 public:
  std::vector<std::string> debug_lines, warn_lines, error_lines;
  void debug(const char *m) override { add(&debug_lines, m); }
  void warn(const char *m) override { add(&warn_lines, m); }
  void error(const char *m) override { add(&error_lines, m); }

 private:
  void add(std::vector<std::string> *v, const char *m) {
    std::lock_guard<std::mutex> lock(mutex_);
    v->push_back(m);
  }
  std::mutex mutex_;
};

// Storage mock that counts every call, so tests can assert "no storage use".
class MockStorage : public TangStorage {
 public:
  std::vector<uint8_t> blob;
  bool has_blob{false};
  uint32_t token{0};
  bool has_token{false};
  int reads{0}, writes{0}, wipes{0}, token_reads{0}, token_writes{0};

  int total_calls() const {
    return reads + writes + wipes + token_reads + token_writes;
  }

  TangStorageStatus read_state(uint8_t *buf, size_t cap, size_t *len) override {
    ++reads;
    if (!has_blob) return TangStorageStatus::kEmpty;
    if (blob.size() > cap) return TangStorageStatus::kError;
    std::memcpy(buf, blob.data(), blob.size());
    *len = blob.size();
    return TangStorageStatus::kOk;
  }
  bool write_state(const uint8_t *buf, size_t len) override {
    ++writes;
    blob.assign(buf, buf + len);
    has_blob = true;
    return true;
  }
  TangStorageStatus read_reset_token(uint32_t *t) override {
    ++token_reads;
    if (!has_token) return TangStorageStatus::kEmpty;
    *t = token;
    return TangStorageStatus::kOk;
  }
  bool write_reset_token(uint32_t t) override {
    ++token_writes;
    token = t;
    has_token = true;
    return true;
  }
  bool wipe() override {
    ++wipes;
    blob.clear();
    has_blob = false;
    has_token = false;
    return true;
  }
};

inline TangRequest make_request(const std::string &method,
                                const std::string &path,
                                const std::string &body = "") {
  TangRequest r;
  r.method = method;
  r.path = path;
  r.body = body;
  return r;
}

// Seeds used in tests (64 hex chars each, all different).
inline const char *seed_a() {
  return "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
}
inline const char *seed_b() {
  return "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
}
inline const char *seed_c() {
  return "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
}

std::string b64url(const uint8_t *d, size_t n);
std::string public_jwk_json(const uint8_t pub[64]);
std::string private_jwk_json(const uint8_t pub[64], const uint8_t priv[32]);

struct DerivedKeys {
  uint8_t sign_priv[32], sign_pub[64], ex_priv[32], ex_pub[64];
};
bool derive_keys(const char *seed_hex, DerivedKeys *out);

// JSON value extraction helper (first occurrence of "key":"value").
std::string json_string_field(const std::string &json, const std::string &key);

}  // namespace tt
