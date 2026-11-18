#include <cstring>
#include <string>

#include "tang_crypto.h"
#include "test_framework.h"
#include "test_util.h"

namespace {

std::string b64(const uint8_t *d, size_t n) {
  char out[128];
  size_t len = 0;
  if (!tang::base64_url_encode(d, n, out, sizeof(out), &len)) return "";
  return std::string(out, len);
}

std::string public_jwk_json(const uint8_t pub[64]) {
  return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + b64(pub, 32) +
         "\",\"y\":\"" + b64(pub + 32, 32) + "\"}";
}

std::string our_thumbprint(const uint8_t pub[64], tang::ThumbprintHash hash) {
  char out[64];
  size_t len = 0;
  if (!tang::compute_ec_jwk_thumbprint(pub, hash, out, sizeof(out), &len)) {
    return "";
  }
  return std::string(out, len);
}

}  // namespace

TEST(thumbprints_match_jose) {
  REQUIRE(tt::have_tool("jose"));
  tang::TangRngContext rng;
  for (int i = 0; i < 5; ++i) {
    uint8_t pub[64];
    uint8_t priv[32];
    REQUIRE(tang::generate_ec_keypair(&rng, pub, priv));
    const std::string jwk = public_jwk_json(pub);
    int status = -1;
    const std::string s256 =
        tt::trim(tt::run_command("jose jwk thp -a S256 -i-", jwk, &status));
    CHECK_EQ(status, 0);
    const std::string s1 =
        tt::trim(tt::run_command("jose jwk thp -a S1 -i-", jwk, &status));
    CHECK_EQ(status, 0);
    CHECK(!s256.empty());
    CHECK(!s1.empty());
    CHECK_EQ(s256.size(), static_cast<size_t>(43));
    CHECK_EQ(s1.size(), static_cast<size_t>(27));
    CHECK_EQ(our_thumbprint(pub, tang::ThumbprintHash::kSha256), s256);
    CHECK_EQ(our_thumbprint(pub, tang::ThumbprintHash::kSha1), s1);
  }
}
