#pragma once

#include <cstddef>
#include <cstdint>

// Persistent storage used by password mode only. Unattended mode never calls
// any of these methods (keys are derived in RAM from the seed).
//
// The core stores one opaque, self-describing blob (see tang_record.h) and one
// small reset token. Backends do not interpret the blob.
enum class TangStorageStatus {
  kEmpty,  // nothing has ever been stored
  kOk,     // data returned
  kError,  // backend failure (not the same as empty)
};

class TangStorage {
 public:
  virtual ~TangStorage() = default;

  // Read the stored blob into buf (capacity cap). Returns kEmpty when nothing
  // was stored, kOk with *len set, or kError.
  virtual TangStorageStatus read_state(uint8_t *buf, size_t cap,
                                       size_t *len) = 0;
  virtual bool write_state(const uint8_t *buf, size_t len) = 0;

  // Reset token: the last `reset_token` value the device was initialized with.
  virtual TangStorageStatus read_reset_token(uint32_t *token) = 0;
  virtual bool write_reset_token(uint32_t token) = 0;

  // Erase the blob and the token.
  virtual bool wipe() = 0;
};
