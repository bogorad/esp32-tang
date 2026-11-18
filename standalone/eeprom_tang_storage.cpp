#include "eeprom_tang_storage.h"

#include <EEPROM.h>

#include <cstring>

bool EEPROMTangStorage::ensure_started_() {
  if (started_) {
    return true;
  }

  started_ = EEPROM.begin(kEepromSize);
  return started_;
}

TangStorageStatus EEPROMTangStorage::read_state(uint8_t *buf, size_t cap,
                                                size_t *len) {
  if (buf == nullptr || len == nullptr || !ensure_started_()) {
    return TangStorageStatus::kError;
  }

  uint32_t magic = 0;
  EEPROM.get(kMagicAddr, magic);
  if (magic == kLegacyMagic) {
    // Old layout: hand the bytes to the core, which rejects them with a clear
    // "unrecognized format" error instead of misreading them.
    static const uint8_t kLegacyMarker[4] = {0xDE, 0xAD, 0xFE, 0xCA};
    if (cap < sizeof(kLegacyMarker)) {
      return TangStorageStatus::kError;
    }
    std::memcpy(buf, kLegacyMarker, sizeof(kLegacyMarker));
    *len = sizeof(kLegacyMarker);
    return TangStorageStatus::kOk;
  }
  if (magic != kSlotMagic) {
    return TangStorageStatus::kEmpty;
  }

  uint16_t length = 0;
  EEPROM.get(kLengthAddr, length);
  if (length == 0) {
    return TangStorageStatus::kEmpty;
  }
  if (length > cap || length > kTangRecordEncodedSize) {
    return TangStorageStatus::kError;
  }
  for (uint16_t i = 0; i < length; ++i) {
    buf[i] = EEPROM.read(kBlobAddr + i);
  }
  *len = length;
  return TangStorageStatus::kOk;
}

bool EEPROMTangStorage::write_state(const uint8_t *buf, size_t len) {
  if (buf == nullptr || len == 0 || len > kTangRecordEncodedSize ||
      !ensure_started_()) {
    return false;
  }

  for (size_t i = 0; i < len; ++i) {
    EEPROM.write(kBlobAddr + static_cast<int>(i), buf[i]);
  }
  EEPROM.put(kLengthAddr, static_cast<uint16_t>(len));
  EEPROM.put(kMagicAddr, kSlotMagic);
  return EEPROM.commit();
}

TangStorageStatus EEPROMTangStorage::read_reset_token(uint32_t *token) {
  if (token == nullptr || !ensure_started_()) {
    return TangStorageStatus::kError;
  }

  uint32_t magic = 0;
  EEPROM.get(kMagicAddr, magic);
  uint32_t present = 0;
  EEPROM.get(kTokenFlagAddr, present);
  if (magic != kSlotMagic || present != 1) {
    return TangStorageStatus::kEmpty;
  }
  EEPROM.get(kTokenAddr, *token);
  return TangStorageStatus::kOk;
}

bool EEPROMTangStorage::write_reset_token(uint32_t token) {
  if (!ensure_started_()) {
    return false;
  }

  EEPROM.put(kTokenAddr, token);
  EEPROM.put(kTokenFlagAddr, static_cast<uint32_t>(1));
  EEPROM.put(kMagicAddr, kSlotMagic);
  return EEPROM.commit();
}

bool EEPROMTangStorage::wipe() {
  if (!ensure_started_()) {
    return false;
  }

  for (int i = 0; i < kEepromSize; ++i) {
    EEPROM.write(i, 0);
  }
  return EEPROM.commit();
}
