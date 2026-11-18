// Seed derivation, HKDF/PBKDF2 vectors, record codec, body buffer.
#include <cstring>

#include "tang_body_buffer.h"
#include "tang_crypto.h"
#include "tang_record.h"
#include "test_support.h"

namespace {

std::string thp(const uint8_t pub[64], tang::ThumbprintHash h) {
  char out[64];
  size_t len = 0;
  if (!tang::compute_ec_jwk_thumbprint(pub, h, out, sizeof(out), &len)) return "";
  return std::string(out, len);
}

}  // namespace

TEST(hkdf_rfc5869_case1) {
  uint8_t ikm[22];
  std::memset(ikm, 0x0b, sizeof(ikm));
  const auto salt = tt::hex_decode("000102030405060708090a0b0c");
  const auto info = tt::hex_decode("f0f1f2f3f4f5f6f7f8f9");
  uint8_t prk[32];
  REQUIRE(tang::hkdf_sha256_extract(salt.data(), salt.size(), ikm, sizeof(ikm), prk));
  CHECK_EQ(tt::hex_encode(prk, 32),
           std::string("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
  uint8_t okm[42];
  REQUIRE(tang::hkdf_sha256_expand(prk, info.data(), info.size(), okm, sizeof(okm)));
  CHECK_EQ(tt::hex_encode(okm, 42),
           std::string("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}

TEST(pbkdf2_known_answers) {
  const char *pw = "password";
  const char *salt = "salt";
  uint8_t out[32];
  auto run = [&](uint32_t iters) -> std::string {
    if (!tang::pbkdf2_hmac_sha256(
            reinterpret_cast<const uint8_t *>(pw), 8,
            reinterpret_cast<const uint8_t *>(salt), 4, iters, out, 32)) {
      return "pbkdf2 failed";
    }
    return tt::hex_encode(out, 32);
  };
  CHECK_EQ(run(1), std::string("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
  CHECK_EQ(run(2), std::string("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"));
  CHECK_EQ(run(4096), std::string("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
}

// Pinned values: cross-checked with the independent Go reference in
// tests/ref/derive.go. A change here means every deployed identity changes.
TEST(seed_derivation_known_answer) {
  tt::DerivedKeys k;
  REQUIRE(tt::derive_keys(tt::seed_a(), &k));
  CHECK_EQ(tt::hex_encode(k.sign_priv, 32),
           std::string("c6948964e9520a3ccfc6373687eacac3278c0968340b0a8b688f2948a52e342e"));
  CHECK_EQ(tt::hex_encode(k.ex_priv, 32),
           std::string("e3a0c5f9f5e237cf3c4beb7649ba447e94a09256fbc34437aa411d4e22c9f859"));
  CHECK_EQ(thp(k.sign_pub, tang::ThumbprintHash::kSha256),
           std::string("V-UCOWj-XdflqBPu-vZHIhZlJ6eThQ2pWHCo-nu5oPI"));
  CHECK_EQ(thp(k.sign_pub, tang::ThumbprintHash::kSha1),
           std::string("17jvBLzbE5AKcoQ35T6xQWXBaMk"));
  CHECK_EQ(thp(k.ex_pub, tang::ThumbprintHash::kSha256),
           std::string("gufGivW1KaP_REkAUWcAJOTopy-V2t6JxcJhUZtvdc0"));
  CHECK_EQ(thp(k.ex_pub, tang::ThumbprintHash::kSha1),
           std::string("IwrxicL-4pD_PhKa968WQUDIeBk"));
}

TEST(seed_derivation_deterministic_and_distinct) {
  tt::DerivedKeys a1, a2, b;
  REQUIRE(tt::derive_keys(tt::seed_a(), &a1));
  REQUIRE(tt::derive_keys(tt::seed_a(), &a2));
  REQUIRE(tt::derive_keys(tt::seed_b(), &b));
  CHECK(std::memcmp(&a1, &a2, sizeof(a1)) == 0);
  CHECK(std::memcmp(a1.sign_priv, b.sign_priv, 32) != 0);
  CHECK(std::memcmp(a1.ex_priv, b.ex_priv, 32) != 0);
  CHECK(std::memcmp(a1.sign_priv, a1.ex_priv, 32) != 0);
  // Upper-case hex gives the same bytes, hence the same keys.
  tt::DerivedKeys up;
  std::string upper = tt::seed_a();
  for (char &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  REQUIRE(tt::derive_keys(upper.c_str(), &up));
  CHECK(std::memcmp(&a1, &up, sizeof(a1)) == 0);
}

TEST(seed_validation_rejects_bad_seeds) {
  uint8_t out[tang::kMaxSeedBytes];
  size_t len = 0;
  const std::string good = tt::seed_a();
  CHECK(tang::decode_seed_hex(good.c_str(), out, sizeof(out), &len));
  CHECK_EQ(len, static_cast<size_t>(32));
  CHECK(!tang::decode_seed_hex("", out, sizeof(out), &len));
  CHECK(!tang::decode_seed_hex(good.substr(0, 62).c_str(), out, sizeof(out), &len));  // 31 bytes
  CHECK(!tang::decode_seed_hex(good.substr(0, 63).c_str(), out, sizeof(out), &len));  // odd
  std::string nonhex = good;
  nonhex[10] = 'g';
  CHECK(!tang::decode_seed_hex(nonhex.c_str(), out, sizeof(out), &len));
  CHECK(!tang::decode_seed_hex(std::string(64, '0').c_str(), out, sizeof(out), &len));
  CHECK(!tang::decode_seed_hex(std::string(64, 'a').c_str(), out, sizeof(out), &len));
  CHECK(!tang::decode_seed_hex("0011001100110011001100110011001100110011001100110011001100110011",
                               out, sizeof(out), &len));  // 2 distinct bytes
}

TEST(record_codec_round_trip_and_corruption) {
  TangStoredState s{};
  for (size_t i = 0; i < 32; ++i) s.admin_private_key[i] = static_cast<uint8_t>(i + 1);
  for (size_t i = 0; i < 32; ++i) s.record.ciphertext[i] = static_cast<uint8_t>(0x40 + i);
  s.record.iterations = 20000;
  uint8_t blob[kTangRecordEncodedSize];
  tang_encode_state(s, blob);

  TangStoredState d{};
  CHECK(tang_decode_state(blob, sizeof(blob), &d) == TangDecodeStatus::kOk);
  CHECK(std::memcmp(&d, &s, sizeof(s)) == 0);
  CHECK(tang_decode_state(nullptr, 0, &d) == TangDecodeStatus::kEmpty);
  CHECK(tang_decode_state(blob, sizeof(blob) - 1, &d) == TangDecodeStatus::kBadLength);

  // Flip every single byte: nothing may decode as OK.
  for (size_t i = 0; i < sizeof(blob); ++i) {
    uint8_t copy[kTangRecordEncodedSize];
    std::memcpy(copy, blob, sizeof(copy));
    copy[i] ^= 0x01;
    CHECK(tang_decode_state(copy, sizeof(copy), &d) != TangDecodeStatus::kOk);
  }

  // Valid checksum but a different version: unsupported, not misread.
  uint8_t v[kTangRecordEncodedSize];
  std::memcpy(v, blob, sizeof(v));
  v[4] = 2;
  tang::sha256_digest(v, kTangRecordEncodedSize - 32, v + kTangRecordEncodedSize - 32);
  CHECK(tang_decode_state(v, sizeof(v), &d) == TangDecodeStatus::kUnsupportedVersion);

  // Legacy-looking data (other magic).
  uint8_t legacy[100];
  std::memset(legacy, 0x5a, sizeof(legacy));
  CHECK(tang_decode_state(legacy, sizeof(legacy), &d) == TangDecodeStatus::kBadMagic);
}

TEST(body_buffer_happy_path_and_limits) {
  TangBodyBuffer b;
  const uint8_t part1[] = {'a', 'b', 'c'};
  const uint8_t part2[] = {'d', 'e'};
  b.on_chunk(part1, 3, 0, 5);
  CHECK(b.status(5) == TangBodyBuffer::Status::kIncomplete);
  b.on_chunk(part2, 2, 3, 5);
  CHECK(b.status(5) == TangBodyBuffer::Status::kOk);
  CHECK_EQ(b.take(), std::string("abcde"));

  // Chunk out of order.
  TangBodyBuffer o;
  o.on_chunk(part2, 2, 3, 5);
  CHECK(o.status(5) == TangBodyBuffer::Status::kMalformed);

  // Too large: cap is 4096.
  TangBodyBuffer big;
  big.on_chunk(part1, 3, 0, kTangMaxBodySize + 1);
  CHECK(big.status(kTangMaxBodySize + 1) == TangBodyBuffer::Status::kTooLarge);
}

TEST(body_buffer_resets_on_index_zero_after_abort) {
  // An aborted upload (declared 10 bytes, delivered 4) must not poison the
  // next request that reuses the same request address.
  TangBodyBuffer b;
  const uint8_t junk[] = {'j', 'u', 'n', 'k'};
  b.on_chunk(junk, 4, 0, 10);
  CHECK(b.status(10) == TangBodyBuffer::Status::kIncomplete);

  const uint8_t fresh[] = {'o', 'k'};
  b.on_chunk(fresh, 2, 0, 2);
  CHECK(b.status(2) == TangBodyBuffer::Status::kOk);
  CHECK_EQ(b.take(), std::string("ok"));

  // Aborted upload that had gone malformed or too large is also cleared.
  TangBodyBuffer m;
  m.on_chunk(junk, 4, 2, 10);  // out of order -> malformed, sticky
  CHECK(m.status(10) == TangBodyBuffer::Status::kMalformed);
  m.on_chunk(fresh, 2, 0, 2);
  CHECK(m.status(2) == TangBodyBuffer::Status::kOk);

  TangBodyBuffer t;
  t.on_chunk(junk, 4, 0, kTangMaxBodySize + 5);
  CHECK(t.status(kTangMaxBodySize + 5) == TangBodyBuffer::Status::kTooLarge);
  t.on_chunk(fresh, 2, 0, 2);
  CHECK(t.status(2) == TangBodyBuffer::Status::kOk);

  // A declared length that differs from what was buffered is malformed.
  TangBodyBuffer mismatch;
  mismatch.on_chunk(fresh, 2, 0, 2);
  CHECK(mismatch.status(3) == TangBodyBuffer::Status::kMalformed);
}
