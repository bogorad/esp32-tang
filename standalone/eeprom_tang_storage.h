#pragma once

#include <cstdint>

#include "../src/tang_record.h"
#include "../src/tang_storage.h"

// EEPROM backend for the standalone (Arduino) build. Layout:
//   [0]   uint32 slot magic
//   [4]   uint16 blob length (0 = empty)
//   [6]   blob (self-describing record, see tang_record.h)
//   [..]  uint32 reset token present flag, uint32 reset token
// Data written by older firmware uses a different layout and magic; it is
// reported as an unrecognized record and never interpreted.
class EEPROMTangStorage : public TangStorage {
 public:
  static constexpr int kEepromSize = 4096;
  static constexpr uint32_t kSlotMagic = 0x54414E53;  // "TANS"
  static constexpr int kMagicAddr = 0;
  static constexpr int kLengthAddr = 4;
  static constexpr int kBlobAddr = 6;
  static constexpr int kTokenFlagAddr = kBlobAddr + static_cast<int>(kTangRecordEncodedSize);
  static constexpr int kTokenAddr = kTokenFlagAddr + 4;
  // Magic used by the previous layout (unsalted key derivation).
  static constexpr uint32_t kLegacyMagic = 0xCAFEDEAD;

  TangStorageStatus read_state(uint8_t *buf, size_t cap, size_t *len) override;
  bool write_state(const uint8_t *buf, size_t len) override;
  TangStorageStatus read_reset_token(uint32_t *token) override;
  bool write_reset_token(uint32_t token) override;
  bool wipe() override;

 private:
  bool ensure_started_();

  bool started_ = false;
};
