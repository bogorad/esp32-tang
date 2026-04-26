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

bool EEPROMTangStorage::is_initialized() {
  if (!ensure_started_()) {
    return false;
  }

  uint32_t magic = 0;
  EEPROM.get(kEepromMagicAddr, magic);
  return magic == kEepromMagicValue;
}

bool EEPROMTangStorage::load_admin_private_key(uint8_t out[32]) {
  if (out == nullptr || !ensure_started_() || !is_initialized()) {
    return false;
  }

  for (int i = 0; i < 32; ++i) {
    out[i] = EEPROM.read(kEepromAdminKeyAddr + i);
  }
  return true;
}

bool EEPROMTangStorage::save_admin_private_key(const uint8_t key[32]) {
  if (key == nullptr || !ensure_started_()) {
    return false;
  }

  for (int i = 0; i < 32; ++i) {
    EEPROM.write(kEepromAdminKeyAddr + i, key[i]);
  }
  return EEPROM.commit();
}

bool EEPROMTangStorage::load_tang_key_record(TangEncryptedKeyRecord *out) {
  if (out == nullptr || !ensure_started_() || !is_initialized()) {
    return false;
  }

  for (int i = 0; i < 32; ++i) {
    out->ciphertext[i] = EEPROM.read(kEepromTangKeyAddr + i);
  }
  for (int i = 0; i < kGcmTagSize; ++i) {
    out->tag[i] = EEPROM.read(kEepromTangTagAddr + i);
  }

  uint8_t version = EEPROM.read(kEepromTangVersionAddr);
  if (version == kTangKeyRecordVersion) {
    for (int i = 0; i < kGcmIvSize; ++i) {
      out->iv[i] = EEPROM.read(kEepromTangIvAddr + i);
    }
    out->version = version;
  } else {
    // Legacy EEPROM records used an all-zero local AES-GCM IV and did not persist it.
    std::memset(out->iv, 0, sizeof(out->iv));
    out->version = 0;
  }
  return true;
}

bool EEPROMTangStorage::save_tang_key_record(
    const TangEncryptedKeyRecord &record) {
  if (!ensure_started_()) {
    return false;
  }

  for (int i = 0; i < 32; ++i) {
    EEPROM.write(kEepromTangKeyAddr + i, record.ciphertext[i]);
  }
  for (int i = 0; i < kGcmTagSize; ++i) {
    EEPROM.write(kEepromTangTagAddr + i, record.tag[i]);
  }
  for (int i = 0; i < kGcmIvSize; ++i) {
    EEPROM.write(kEepromTangIvAddr + i, record.iv[i]);
  }
  EEPROM.write(kEepromTangVersionAddr, record.version);
  return EEPROM.commit();
}

bool EEPROMTangStorage::mark_initialized() {
  if (!ensure_started_()) {
    return false;
  }

  EEPROM.put(kEepromMagicAddr, kEepromMagicValue);
  return EEPROM.commit();
}

bool EEPROMTangStorage::wipe() {
  if (!ensure_started_()) {
    return false;
  }

  EEPROM.put(kEepromMagicAddr, static_cast<uint32_t>(0));
  return EEPROM.commit();
}
