#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "tang_crypto.h"
#include "tang_platform.h"
#include "tang_record.h"
#include "tang_request.h"
#include "tang_response.h"
#include "tang_storage.h"

struct TangConfig {
  // Unattended mode: keys are derived from `seed_hex` at every boot, the server
  // is active from boot, and nothing is written to storage.
  bool unattended = false;
  const char *seed_hex = nullptr;
  // Rotation: exchange keys of these seeds stay valid for /rec but are not
  // advertised; their signing keys may co-sign /adv/<thp>.
  std::vector<std::string> old_seeds_hex;

  // Password mode.
  const char *initial_password = nullptr;
  uint32_t reset_token = 0;
  uint64_t key_lifetime_ms = 3600000;
};

class TangServerCore {
 public:
  static constexpr uint64_t kDefaultKeyLifetimeMs = 3600000;
  // /activate failed-attempt back-off: 1 s after the first failure, doubling,
  // capped at kMaxBackoffMs. RAM only; a reboot clears it.
  static constexpr uint64_t kMaxBackoffMs = 300000;

  TangServerCore(TangStorage *storage, TangClock *clock, TangLogger *logger);

  // Returns false (and logs an error) if the server cannot run. A false return
  // leaves the server inactive; it never silently falls back.
  bool setup(const TangConfig &config);
  // Convenience for the standalone build: password mode, defaults.
  bool setup(const char *initial_password);

  // Call from the main loop. Returns true if the key expired during this call.
  bool loop();

  TangResponse handle_request(const TangRequest &request);

  bool is_active() const;
  bool is_ready() const;
  bool is_unattended() const;
  // RFC 7638 SHA-256 thumbprint (base64url, no padding) of the signing key
  // that /adv advertises. False until setup() succeeded. In unattended mode
  // the key exists from boot; in password mode it is the admin key.
  bool signing_thumbprint(std::string *out) const;

 private:
  struct KeyPair {
    uint8_t priv[tang::kEcPrivateKeySize];
    uint8_t pub[tang::kEcPublicKeySize];
  };

  TangResponse fail(int status, const char *body);
  TangResponse fail_json(int status, const char *error, const char *message);

  TangResponse handle_adv(const std::string &path);
  TangResponse handle_pub();
  TangResponse handle_activate(const TangRequest &request);
  TangResponse handle_deactivate(const TangRequest &request);
  TangResponse handle_recovery(const TangRequest &request);

  bool setup_unattended(const TangConfig &config);
  bool setup_password(const TangConfig &config);
  bool initialize_storage(const char *initial_password, uint32_t reset_token);
  bool derive_keypairs(const char *seed_hex, KeyPair *signing,
                       KeyPair *exchange);
  bool verify_password(const std::string &password);
  void note_password_failure_locked();
  void deactivate_locked();

  TangStorage *storage_;
  TangClock *clock_;
  TangLogger *logger_;
  tang::TangRngContext rng_;

  mutable std::mutex mutex_;  // guards everything below
  bool ready_;
  bool unattended_;
  bool active_;
  uint64_t key_lifetime_ms_;
  uint64_t activation_ms_;
  uint32_t failed_attempts_;
  uint64_t next_attempt_ms_;
  TangEncryptedKeyRecord record_;  // password mode: copy of stored record
  KeyPair signing_;                // admin key (password) / signing key
  KeyPair exchange_;               // valid only while active_
  std::vector<KeyPair> old_signing_;
  std::vector<KeyPair> old_exchange_;
};
