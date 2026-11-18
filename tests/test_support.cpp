#include "test_support.h"

namespace tt {

std::string b64url(const uint8_t *d, size_t n) {
  char out[256];
  size_t len = 0;
  if (!tang::base64_url_encode(d, n, out, sizeof(out), &len)) return "";
  return std::string(out, len);
}

std::string public_jwk_json(const uint8_t pub[64]) {
  return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + b64url(pub, 32) +
         "\",\"y\":\"" + b64url(pub + 32, 32) + "\"}";
}

std::string private_jwk_json(const uint8_t pub[64], const uint8_t priv[32]) {
  return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + b64url(pub, 32) +
         "\",\"y\":\"" + b64url(pub + 32, 32) + "\",\"d\":\"" +
         b64url(priv, 32) + "\"}";
}

bool derive_keys(const char *seed_hex, DerivedKeys *out) {
  uint8_t seed[tang::kMaxSeedBytes];
  size_t len = 0;
  if (!tang::decode_seed_hex(seed_hex, seed, sizeof(seed), &len)) return false;
  static tang::TangRngContext rng;
  return tang::derive_p256_private_key(seed, len, tang::kSeedRoleSigning,
                                       out->sign_priv) &&
         tang::compute_ec_public_key(&rng, out->sign_priv, out->sign_pub) &&
         tang::derive_p256_private_key(seed, len, tang::kSeedRoleExchange,
                                       out->ex_priv) &&
         tang::compute_ec_public_key(&rng, out->ex_priv, out->ex_pub);
}

std::string json_string_field(const std::string &json, const std::string &key) {
  const std::string needle = "\"" + key + "\":\"";
  const size_t p = json.find(needle);
  if (p == std::string::npos) return "";
  const size_t s = p + needle.size();
  const size_t e = json.find('"', s);
  if (e == std::string::npos) return "";
  return json.substr(s, e - s);
}

}  // namespace tt
