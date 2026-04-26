#pragma once

#include <cstdint>

#include "../src/tang_storage.h"

class EEPROMTangStorage : public TangStorage {
 public:
  static constexpr int kEepromSize = 4096;
  static constexpr int kEepromMagicAddr = 0;
  static constexpr int kEepromAdminKeyAddr = 4;
  static constexpr int kEepromTangKeyAddr = kEepromAdminKeyAddr + 32;
  static constexpr int kGcmTagSize = 16;
  static constexpr int kEepromTangTagAddr = kEepromTangKeyAddr + 32;
  static constexpr int kGcmIvSize = 12;
  static constexpr int kEepromTangIvAddr = kEepromTangTagAddr + kGcmTagSize;
  static constexpr int kEepromTangVersionAddr = kEepromTangIvAddr + kGcmIvSize;
  static constexpr uint8_t kTangKeyRecordVersion = 1;
  static constexpr uint32_t kEepromMagicValue = 0xCAFEDEAD;

  bool is_initialized() override;
  bool load_admin_private_key(uint8_t out[32]) override;
  bool save_admin_private_key(const uint8_t key[32]) override;
  bool load_tang_key_record(TangEncryptedKeyRecord *out) override;
  bool save_tang_key_record(const TangEncryptedKeyRecord &record) override;
  bool mark_initialized() override;
  bool wipe() override;

 private:
  bool ensure_started_();

  bool started_ = false;
};
