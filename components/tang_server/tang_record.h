#pragma once

#include <cstddef>
#include <cstdint>

#include "tang_crypto.h"

// Persistent state for password mode, with a self-describing on-flash format:
//
//   offset size  field
//   0      4     magic "TNGS"
//   4      1     format version (kTangRecordVersion)
//   5      1     reserved, 0
//   6      2     payload length, little endian
//   8      n     payload
//   8+n    32    SHA-256 over bytes [0, 8+n)
//
// payload: admin private key (32) | ciphertext (32) | tag (16) | iv (12) |
//          pbkdf2 salt (16) | pbkdf2 iterations (4, little endian)
//
// Records written by older firmware (unsalted SHA-256 key derivation, other
// magic or layout) never decode: they return kBadMagic or kUnsupportedVersion
// and are never interpreted.

struct TangEncryptedKeyRecord {
  uint8_t ciphertext[tang::kEcPrivateKeySize];
  uint8_t tag[tang::kGcmTagSize];
  uint8_t iv[tang::kGcmIvSize];
  uint8_t salt[tang::kPasswordSaltSize];
  uint32_t iterations;
};

struct TangStoredState {
  uint8_t admin_private_key[tang::kEcPrivateKeySize];
  TangEncryptedKeyRecord record;
};

constexpr uint8_t kTangRecordVersion = 1;
constexpr size_t kTangRecordPayloadSize =
    tang::kEcPrivateKeySize + tang::kEcPrivateKeySize + tang::kGcmTagSize +
    tang::kGcmIvSize + tang::kPasswordSaltSize + 4;
constexpr size_t kTangRecordEncodedSize =
    8 + kTangRecordPayloadSize + tang::kSha256DigestSize;

enum class TangDecodeStatus {
  kOk,
  kEmpty,
  kBadMagic,
  kUnsupportedVersion,
  kBadLength,
  kBadChecksum,
};

const char *tang_decode_status_name(TangDecodeStatus status);

void tang_encode_state(const TangStoredState &state,
                       uint8_t out[kTangRecordEncodedSize]);
TangDecodeStatus tang_decode_state(const uint8_t *data, size_t len,
                                   TangStoredState *out);
