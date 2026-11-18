#include "tang_record.h"

#include <cstring>

namespace {

constexpr uint8_t kMagic[4] = {'T', 'N', 'G', 'S'};

void put_u32le(uint8_t *p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

uint32_t get_u32le(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

const char *tang_decode_status_name(TangDecodeStatus status) {
  switch (status) {
    case TangDecodeStatus::kOk:
      return "ok";
    case TangDecodeStatus::kEmpty:
      return "empty";
    case TangDecodeStatus::kBadMagic:
      return "unrecognized format (bad magic; legacy or foreign data)";
    case TangDecodeStatus::kUnsupportedVersion:
      return "unsupported record version";
    case TangDecodeStatus::kBadLength:
      return "bad record length";
    case TangDecodeStatus::kBadChecksum:
      return "checksum mismatch (corrupt record)";
  }
  return "unknown";
}

void tang_encode_state(const TangStoredState &state,
                       uint8_t out[kTangRecordEncodedSize]) {
  std::memset(out, 0, kTangRecordEncodedSize);
  std::memcpy(out, kMagic, sizeof(kMagic));
  out[4] = kTangRecordVersion;
  out[5] = 0;
  out[6] = static_cast<uint8_t>(kTangRecordPayloadSize & 0xFF);
  out[7] = static_cast<uint8_t>(kTangRecordPayloadSize >> 8);

  uint8_t *p = out + 8;
  std::memcpy(p, state.admin_private_key, sizeof(state.admin_private_key));
  p += sizeof(state.admin_private_key);
  std::memcpy(p, state.record.ciphertext, sizeof(state.record.ciphertext));
  p += sizeof(state.record.ciphertext);
  std::memcpy(p, state.record.tag, sizeof(state.record.tag));
  p += sizeof(state.record.tag);
  std::memcpy(p, state.record.iv, sizeof(state.record.iv));
  p += sizeof(state.record.iv);
  std::memcpy(p, state.record.salt, sizeof(state.record.salt));
  p += sizeof(state.record.salt);
  put_u32le(p, state.record.iterations);
  p += 4;

  tang::sha256_digest(out, static_cast<size_t>(p - out), p);
}

TangDecodeStatus tang_decode_state(const uint8_t *data, size_t len,
                                   TangStoredState *out) {
  if (out == nullptr) {
    return TangDecodeStatus::kBadLength;
  }
  if (data == nullptr || len == 0) {
    return TangDecodeStatus::kEmpty;
  }
  if (len < sizeof(kMagic) || std::memcmp(data, kMagic, sizeof(kMagic)) != 0) {
    return TangDecodeStatus::kBadMagic;
  }
  if (len < 8) {
    return TangDecodeStatus::kBadLength;
  }
  if (data[4] != kTangRecordVersion) {
    return TangDecodeStatus::kUnsupportedVersion;
  }
  const size_t payload_len = static_cast<size_t>(data[6]) |
                             (static_cast<size_t>(data[7]) << 8);
  if (payload_len != kTangRecordPayloadSize ||
      len != kTangRecordEncodedSize) {
    return TangDecodeStatus::kBadLength;
  }

  uint8_t digest[tang::kSha256DigestSize];
  if (!tang::sha256_digest(data, 8 + payload_len, digest)) {
    return TangDecodeStatus::kBadChecksum;
  }
  // Not a secret comparison: the checksum protects against corruption only.
  if (std::memcmp(digest, data + 8 + payload_len, sizeof(digest)) != 0) {
    return TangDecodeStatus::kBadChecksum;
  }

  const uint8_t *p = data + 8;
  TangStoredState state;
  std::memcpy(state.admin_private_key, p, sizeof(state.admin_private_key));
  p += sizeof(state.admin_private_key);
  std::memcpy(state.record.ciphertext, p, sizeof(state.record.ciphertext));
  p += sizeof(state.record.ciphertext);
  std::memcpy(state.record.tag, p, sizeof(state.record.tag));
  p += sizeof(state.record.tag);
  std::memcpy(state.record.iv, p, sizeof(state.record.iv));
  p += sizeof(state.record.iv);
  std::memcpy(state.record.salt, p, sizeof(state.record.salt));
  p += sizeof(state.record.salt);
  state.record.iterations = get_u32le(p);
  if (state.record.iterations == 0) {
    return TangDecodeStatus::kBadLength;
  }
  *out = state;
  return TangDecodeStatus::kOk;
}
