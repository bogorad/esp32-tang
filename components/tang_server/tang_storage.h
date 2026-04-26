#pragma once

#include <cstdint>

struct TangEncryptedKeyRecord {
  uint8_t ciphertext[32];
  uint8_t tag[16];
  uint8_t iv[12];
  uint8_t version = 1;
};

class TangStorage {
 public:
  virtual ~TangStorage() = default;

  virtual bool is_initialized() = 0;
  virtual bool load_admin_private_key(uint8_t out[32]) = 0;
  virtual bool save_admin_private_key(const uint8_t key[32]) = 0;
  virtual bool load_tang_key_record(TangEncryptedKeyRecord *out) = 0;
  virtual bool save_tang_key_record(const TangEncryptedKeyRecord &record) = 0;
  virtual bool mark_initialized() = 0;
  virtual bool wipe() = 0;
};
