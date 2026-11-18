#include "tang_crypto.h"

#include <cstring>
#include <string>

#if defined(USE_ESP_IDF)
#include <mbedtls/esp_config.h>
#endif

#include <mbedtls/base64.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

namespace tang {
namespace {

constexpr char kRngPersonalization[] = "esp32_tang_server";

void write_be32(uint8_t *buf, uint32_t val) {
  buf[0] = (val >> 24) & 0xFF;
  buf[1] = (val >> 16) & 0xFF;
  buf[2] = (val >> 8) & 0xFF;
  buf[3] = val & 0xFF;
}

}  // namespace

TangRngContext::TangRngContext() : initialized(false) {
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
}

TangRngContext::~TangRngContext() {
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  initialized = false;
}

int rng_callback(void *ctx, unsigned char *output, size_t len) {
  TangRngContext *rng = static_cast<TangRngContext *>(ctx);
  if (rng == nullptr || !rng->initialized) {
    return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
  }
  // mbedtls_ctr_drbg is not thread safe; httpd and main-loop tasks may both
  // reach this.
  std::lock_guard<std::mutex> lock(rng->mutex);
  return mbedtls_ctr_drbg_random(&rng->ctr_drbg, output, len);
}

int init_rng(TangRngContext *rng) {
  if (rng == nullptr) {
    return -1;
  }

  std::lock_guard<std::mutex> lock(rng->mutex);
  if (rng->initialized) {
    return 0;
  }

  int ret = mbedtls_ctr_drbg_seed(
      &rng->ctr_drbg, mbedtls_entropy_func, &rng->entropy,
      reinterpret_cast<const unsigned char *>(kRngPersonalization),
      std::strlen(kRngPersonalization));
  if (ret != 0) {
    return ret;
  }

  rng->initialized = true;
  return 0;
}

void cleanup_rng(TangRngContext *rng) {
  if (rng == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> lock(rng->mutex);

  mbedtls_ctr_drbg_free(&rng->ctr_drbg);
  mbedtls_entropy_free(&rng->entropy);
  mbedtls_entropy_init(&rng->entropy);
  mbedtls_ctr_drbg_init(&rng->ctr_drbg);
  rng->initialized = false;
}

int get_rng_context(TangRngContext *rng, TangRandomFunc *rng_func,
                    void **rng_ctx) {
  if (rng_func == nullptr || rng_ctx == nullptr) {
    return -1;
  }

  int ret = init_rng(rng);
  if (ret != 0) {
    return ret;
  }

  *rng_func = rng_callback;
  *rng_ctx = rng;
  return 0;
}

void secure_zero(void *ptr, size_t len) {
  volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
  while (len > 0) {
    *p++ = 0;
    --len;
  }
}

bool base64_url_encode(const uint8_t *data, size_t data_len, char *output,
                       size_t output_size, size_t *output_len) {
  if ((data == nullptr && data_len != 0) || output == nullptr ||
      output_size == 0) {
    return false;
  }

  if (data_len == 0) {
    output[0] = '\0';
    if (output_len != nullptr) {
      *output_len = 0;
    }
    return true;
  }

  size_t encoded_len = 0;
  int ret = mbedtls_base64_encode(nullptr, 0, &encoded_len, data, data_len);
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    return false;
  }

  std::string encoded(encoded_len, '\0');
  ret = mbedtls_base64_encode(
      reinterpret_cast<unsigned char *>(&encoded[0]), encoded.size(),
      &encoded_len, data, data_len);
  if (ret != 0) {
    return false;
  }
  encoded.resize(encoded_len);

  for (char &ch : encoded) {
    if (ch == '+') {
      ch = '-';
    } else if (ch == '/') {
      ch = '_';
    }
  }

  size_t padding = 0;
  while (padding < encoded.size() && encoded[encoded.size() - padding - 1] == '=') {
    ++padding;
  }
  encoded.resize(encoded.size() - padding);

  if (encoded.size() + 1 > output_size) {
    if (output_len != nullptr) {
      *output_len = encoded.size();
    }
    return false;
  }

  std::memcpy(output, encoded.data(), encoded.size());
  output[encoded.size()] = '\0';
  if (output_len != nullptr) {
    *output_len = encoded.size();
  }

  return true;
}

bool base64_url_decode(const char *input, size_t input_len, uint8_t *output,
                       size_t output_size, size_t *output_len) {
  if ((input == nullptr && input_len != 0) || output == nullptr) {
    return false;
  }

  if (input_len == 0) {
    if (output_len != nullptr) {
      *output_len = 0;
    }
    return true;
  }

  std::string b64(input, input_len);
  for (char &ch : b64) {
    if (ch == '-') {
      ch = '+';
    } else if (ch == '_') {
      ch = '/';
    }
  }
  while ((b64.size() % 4) != 0) {
    b64.push_back('=');
  }

  size_t decoded_len = 0;
  int ret = mbedtls_base64_decode(
      output, output_size, &decoded_len,
      reinterpret_cast<const unsigned char *>(b64.data()), b64.size());
  if (ret != 0) {
    return false;
  }

  if (output_len != nullptr) {
    *output_len = decoded_len;
  }
  return true;
}

bool sha256_digest(const uint8_t *data, size_t data_len,
                   uint8_t digest[kSha256DigestSize]) {
  if ((data == nullptr && data_len != 0) || digest == nullptr) {
    return false;
  }

  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);

  int ret = mbedtls_sha256_starts(&sha_ctx, 0);
  if (ret == 0 && data_len != 0) {
    ret = mbedtls_sha256_update(&sha_ctx, data, data_len);
  }
  if (ret == 0) {
    ret = mbedtls_sha256_finish(&sha_ctx, digest);
  }

  mbedtls_sha256_free(&sha_ctx);
  return ret == 0;
}

bool generate_ec_keypair(TangRngContext *rng, uint8_t pub_key[kEcPublicKeySize],
                         uint8_t priv_key[kEcPrivateKeySize]) {
  if (pub_key == nullptr || priv_key == nullptr || init_rng(rng) != 0) {
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) {
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, rng_callback, rng);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&d, priv_key, kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key,
                                   kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y),
                                   pub_key + kEcPrivateKeySize,
                                   kEcPrivateKeySize);
  }

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  return ret == 0;
}

bool compute_ec_public_key(TangRngContext *rng,
                           const uint8_t priv_key[kEcPrivateKeySize],
                           uint8_t pub_key[kEcPublicKeySize]) {
  if (priv_key == nullptr || pub_key == nullptr || init_rng(rng) != 0) {
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&d, priv_key, kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, rng_callback, rng);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key,
                                   kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y),
                                   pub_key + kEcPrivateKeySize,
                                   kEcPrivateKeySize);
  }

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  return ret == 0;
}

bool compute_ecdh_shared_secret(TangRngContext *rng,
                                 const uint8_t peer_pub_key[kEcPublicKeySize],
                                 const uint8_t priv_key[kEcPrivateKeySize],
                                 uint8_t shared_secret[kEcPrivateKeySize]) {
  if (peer_pub_key == nullptr || priv_key == nullptr || shared_secret == nullptr ||
      init_rng(rng) != 0) {
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&d, priv_key, kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), peer_pub_key,
                                  kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y),
                                  peer_pub_key + kEcPrivateKeySize,
                                  kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
  }
  if (ret == 0) {
    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
  }
  if (ret == 0) {
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, rng_callback, rng);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), shared_secret,
                                   kEcPrivateKeySize);
  }

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  return ret == 0;
}

bool compute_ec_point_multiply(TangRngContext *rng,
                               const uint8_t peer_pub_key[kEcPublicKeySize],
                               const uint8_t priv_key[kEcPrivateKeySize],
                               uint8_t output_pub_key[kEcPublicKeySize]) {
  if (peer_pub_key == nullptr || priv_key == nullptr ||
      output_pub_key == nullptr || init_rng(rng) != 0) {
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point input;
  mbedtls_ecp_point output;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&input);
  mbedtls_ecp_point_init(&output);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&d, priv_key, kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&input.MBEDTLS_PRIVATE(X), peer_pub_key,
                                  kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&input.MBEDTLS_PRIVATE(Y),
                                  peer_pub_key + kEcPrivateKeySize,
                                  kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_lset(&input.MBEDTLS_PRIVATE(Z), 1);
  }
  if (ret == 0) {
    ret = mbedtls_ecp_check_pubkey(&grp, &input);
  }
  if (ret == 0) {
    ret = mbedtls_ecp_mul(&grp, &output, &d, &input, rng_callback, rng);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&output.MBEDTLS_PRIVATE(X), output_pub_key,
                                   kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&output.MBEDTLS_PRIVATE(Y),
                                   output_pub_key + kEcPrivateKeySize,
                                   kEcPrivateKeySize);
  }

  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&output);
  mbedtls_ecp_point_free(&input);
  mbedtls_ecp_group_free(&grp);
  return ret == 0;
}

bool compute_ec_jwk_thumbprint(const uint8_t pub_key[kEcPublicKeySize],
                               ThumbprintHash hash, char *output,
                               size_t output_size, size_t *output_len) {
  if (pub_key == nullptr || output == nullptr || output_size == 0) {
    return false;
  }

  char x[48];
  char y[48];
  size_t x_len = 0;
  size_t y_len = 0;
  uint8_t digest[kSha256DigestSize];
  size_t digest_len = 0;
  bool ok = base64_url_encode(pub_key, kEcPrivateKeySize, x, sizeof(x),
                              &x_len) &&
            base64_url_encode(pub_key + kEcPrivateKeySize, kEcPrivateKeySize, y,
                              sizeof(y), &y_len);
  if (ok) {
    // RFC 7638 canonical form: required members only, sorted, no spaces.
    const std::string canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" +
                                  std::string(x, x_len) + "\",\"y\":\"" +
                                  std::string(y, y_len) + "\"}";
    const uint8_t *data = reinterpret_cast<const uint8_t *>(canonical.data());
    if (hash == ThumbprintHash::kSha1) {
      // SHA-1 is used only as a key identifier (tangd accepts it). It is not
      // used for signatures or key derivation.
      digest_len = kSha1DigestSize;
      ok = mbedtls_sha1(data, canonical.size(), digest) == 0;
    } else {
      digest_len = kSha256DigestSize;
      ok = sha256_digest(data, canonical.size(), digest);
    }
  }
  if (ok) {
    ok = base64_url_encode(digest, digest_len, output, output_size,
                           output_len);
  }

  secure_zero(digest, sizeof(digest));
  return ok;
}

bool sign_es256(TangRngContext *rng, const uint8_t priv_key[kEcPrivateKeySize],
                const uint8_t *data, size_t data_len,
                uint8_t signature[kEcPublicKeySize]) {
  if (priv_key == nullptr || (data == nullptr && data_len != 0) ||
      signature == nullptr || init_rng(rng) != 0) {
    return false;
  }

  uint8_t digest[kSha256DigestSize];
  if (!sha256_digest(data, data_len, digest)) {
    secure_zero(digest, sizeof(digest));
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_mpi r;
  mbedtls_mpi s;

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) {
    ret = mbedtls_mpi_read_binary(&d, priv_key, kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, digest, sizeof(digest),
                             rng_callback, rng);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&r, signature, kEcPrivateKeySize);
  }
  if (ret == 0) {
    ret = mbedtls_mpi_write_binary(&s, signature + kEcPrivateKeySize,
                                   kEcPrivateKeySize);
  }

  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  secure_zero(digest, sizeof(digest));
  return ret == 0;
}

bool concat_kdf(uint8_t *output_key, size_t output_key_len_bytes,
                const uint8_t *shared_secret, size_t shared_secret_len,
                const char *alg_id, size_t alg_id_len) {
  if (output_key == nullptr || shared_secret == nullptr || alg_id == nullptr ||
      output_key_len_bytes > kSha256DigestSize) {
    return false;
  }

  mbedtls_sha256_context sha_ctx;
  uint8_t round_counter[4];
  uint8_t field_len_be[4];
  const uint8_t zeros[4] = {0};
  uint8_t digest[kSha256DigestSize];

  mbedtls_sha256_init(&sha_ctx);
  if (mbedtls_sha256_starts(&sha_ctx, 0) != 0) {
    mbedtls_sha256_free(&sha_ctx);
    return false;
  }

  write_be32(round_counter, 1);
  int ret = mbedtls_sha256_update(&sha_ctx, round_counter, sizeof(round_counter));
  if (ret == 0) {
    ret = mbedtls_sha256_update(&sha_ctx, shared_secret, shared_secret_len);
  }
  if (ret == 0) {
    write_be32(field_len_be, alg_id_len);
    ret = mbedtls_sha256_update(&sha_ctx, field_len_be, sizeof(field_len_be));
  }
  if (ret == 0) {
    ret = mbedtls_sha256_update(
        &sha_ctx, reinterpret_cast<const uint8_t *>(alg_id), alg_id_len);
  }
  if (ret == 0) {
    ret = mbedtls_sha256_update(&sha_ctx, zeros, sizeof(zeros));
  }
  if (ret == 0) {
    ret = mbedtls_sha256_update(&sha_ctx, zeros, sizeof(zeros));
  }
  if (ret == 0) {
    write_be32(field_len_be, output_key_len_bytes * 8);
    ret = mbedtls_sha256_update(&sha_ctx, field_len_be, sizeof(field_len_be));
  }
  if (ret == 0) {
    ret = mbedtls_sha256_finish(&sha_ctx, digest);
  }

  mbedtls_sha256_free(&sha_ctx);
  if (ret == 0) {
    std::memcpy(output_key, digest, output_key_len_bytes);
  }
  secure_zero(digest, sizeof(digest));
  return ret == 0;
}

bool jwe_gcm_decrypt(uint8_t *plaintext, const uint8_t *ciphertext,
                     size_t ciphertext_len, const uint8_t *cek, size_t cek_len,
                     const uint8_t *iv, size_t iv_len, const uint8_t *tag,
                     size_t tag_len, const uint8_t *aad, size_t aad_len) {
  if (plaintext == nullptr || ciphertext == nullptr || cek == nullptr ||
      iv == nullptr || tag == nullptr || (aad == nullptr && aad_len != 0)) {
    return false;
  }

  mbedtls_gcm_context gcm_ctx;
  mbedtls_gcm_init(&gcm_ctx);

  int ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, cek, cek_len * 8);
  if (ret == 0) {
    ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, ciphertext_len, iv, iv_len, aad,
                                   aad_len, tag, tag_len, ciphertext,
                                   plaintext);
  }

  mbedtls_gcm_free(&gcm_ctx);
  return ret == 0;
}

bool hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                 size_t data_len, uint8_t out[kSha256DigestSize]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr || out == nullptr || (key == nullptr && key_len != 0) ||
      (data == nullptr && data_len != 0)) {
    return false;
  }
  static const uint8_t kEmpty = 0;
  return mbedtls_md_hmac(info, key == nullptr ? &kEmpty : key, key_len,
                         data == nullptr ? &kEmpty : data, data_len,
                         out) == 0;
}

bool hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[kSha256DigestSize]) {
  // RFC 5869: PRK = HMAC-Hash(salt, IKM). An empty salt means HashLen zeros;
  // an empty HMAC key is zero-padded to the block size, which is equivalent.
  return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

bool hkdf_sha256_expand(const uint8_t prk[kSha256DigestSize],
                        const uint8_t *info, size_t info_len, uint8_t *okm,
                        size_t okm_len) {
  const mbedtls_md_info_t *info_md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info_md == nullptr || prk == nullptr || okm == nullptr ||
      (info == nullptr && info_len != 0) || okm_len == 0 ||
      okm_len > 255 * kSha256DigestSize) {
    return false;
  }

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  uint8_t t[kSha256DigestSize];
  size_t t_len = 0;
  size_t produced = 0;
  bool ok = mbedtls_md_setup(&ctx, info_md, 1) == 0;
  for (uint8_t counter = 1; ok && produced < okm_len; ++counter) {
    ok = mbedtls_md_hmac_starts(&ctx, prk, kSha256DigestSize) == 0 &&
         (t_len == 0 || mbedtls_md_hmac_update(&ctx, t, t_len) == 0) &&
         (info_len == 0 || mbedtls_md_hmac_update(&ctx, info, info_len) == 0) &&
         mbedtls_md_hmac_update(&ctx, &counter, 1) == 0 &&
         mbedtls_md_hmac_finish(&ctx, t) == 0;
    if (ok) {
      t_len = sizeof(t);
      const size_t n = (okm_len - produced) < t_len ? (okm_len - produced)
                                                     : t_len;
      std::memcpy(okm + produced, t, n);
      produced += n;
    }
  }
  mbedtls_md_free(&ctx);
  secure_zero(t, sizeof(t));
  if (!ok) {
    secure_zero(okm, okm_len);
  }
  return ok;
}

bool pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr || (password == nullptr && password_len != 0) ||
      salt == nullptr || salt_len == 0 || iterations == 0 || out == nullptr ||
      out_len == 0) {
    return false;
  }

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  bool ok = mbedtls_md_setup(&ctx, info, 1) == 0;
  static const uint8_t kEmpty = 0;
  const uint8_t *key = password == nullptr ? &kEmpty : password;
  if (ok) {
    ok = mbedtls_md_hmac_starts(&ctx, key, password_len) == 0;
  }

  size_t produced = 0;
  for (uint32_t block = 1; ok && produced < out_len; ++block) {
    uint8_t be[4];
    write_be32(be, block);
    uint8_t u[kSha256DigestSize];
    uint8_t acc[kSha256DigestSize];
    ok = mbedtls_md_hmac_reset(&ctx) == 0 &&
         mbedtls_md_hmac_update(&ctx, salt, salt_len) == 0 &&
         mbedtls_md_hmac_update(&ctx, be, sizeof(be)) == 0 &&
         mbedtls_md_hmac_finish(&ctx, u) == 0;
    if (ok) {
      std::memcpy(acc, u, sizeof(acc));
      for (uint32_t i = 1; ok && i < iterations; ++i) {
        ok = mbedtls_md_hmac_reset(&ctx) == 0 &&
             mbedtls_md_hmac_update(&ctx, u, sizeof(u)) == 0 &&
             mbedtls_md_hmac_finish(&ctx, u) == 0;
        if (ok) {
          for (size_t j = 0; j < sizeof(acc); ++j) {
            acc[j] ^= u[j];
          }
        }
      }
    }
    if (ok) {
      const size_t n = (out_len - produced) < sizeof(acc) ? (out_len - produced)
                                                          : sizeof(acc);
      std::memcpy(out + produced, acc, n);
      produced += n;
    }
    secure_zero(u, sizeof(u));
    secure_zero(acc, sizeof(acc));
  }
  mbedtls_md_free(&ctx);
  if (!ok) {
    secure_zero(out, out_len);
  }
  return ok;
}

bool decode_seed_hex(const char *hex, uint8_t *out, size_t out_capacity,
                     size_t *out_len) {
  if (hex == nullptr || out == nullptr || out_len == nullptr) {
    return false;
  }
  const size_t len = std::strlen(hex);
  if (len % 2 != 0 || len / 2 < kMinSeedBytes || len / 2 > out_capacity) {
    return false;
  }
  for (size_t i = 0; i < len; ++i) {
    const char c = hex[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }
  for (size_t i = 0; i < len / 2; ++i) {
    auto nibble = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
      if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
      return static_cast<uint8_t>(c - 'A' + 10);
    };
    out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) |
                                  nibble(hex[2 * i + 1]));
  }
  *out_len = len / 2;

  // Reject obviously degenerate seeds (all-zero, repeated byte, tiny alphabet).
  bool seen[256] = {false};
  size_t distinct = 0;
  for (size_t i = 0; i < *out_len; ++i) {
    if (!seen[out[i]]) {
      seen[out[i]] = true;
      ++distinct;
    }
  }
  if (distinct < kMinSeedDistinctBytes) {
    secure_zero(out, out_capacity);
    *out_len = 0;
    return false;
  }
  return true;
}

bool derive_p256_private_key(const uint8_t *seed, size_t seed_len,
                             const char *role, uint8_t priv_key[kEcPrivateKeySize]) {
  if (seed == nullptr || seed_len < kMinSeedBytes || role == nullptr ||
      priv_key == nullptr) {
    return false;
  }

  uint8_t prk[kSha256DigestSize];
  if (!hkdf_sha256_extract(
          reinterpret_cast<const uint8_t *>(kSeedSalt),
          std::strlen(kSeedSalt), seed, seed_len, prk)) {
    secure_zero(prk, sizeof(prk));
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  bool found = false;
  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  // Info = "esp32-tang/v1/" role 0x00 counter(1 byte). Rejection sampling with
  // a counter: candidates are uniform 256-bit values; keep the first with
  // 1 <= d < n. No modulo bias. A reject has probability about 2^-32.
  const std::string prefix = std::string(kSeedSalt) + "/" + role;
  for (int counter = 0; ret == 0 && counter < 256 && !found; ++counter) {
    std::string info = prefix;
    info.push_back('\0');
    info.push_back(static_cast<char>(counter));
    uint8_t okm[kEcPrivateKeySize];
    if (!hkdf_sha256_expand(prk, reinterpret_cast<const uint8_t *>(info.data()),
                            info.size(), okm, sizeof(okm))) {
      ret = -1;
    } else if (mbedtls_mpi_read_binary(&d, okm, sizeof(okm)) != 0) {
      ret = -1;
    } else if (mbedtls_mpi_cmp_int(&d, 1) >= 0 &&
               mbedtls_mpi_cmp_mpi(&d, &grp.N) < 0) {
      std::memcpy(priv_key, okm, sizeof(okm));
      found = true;
    }
    secure_zero(okm, sizeof(okm));
  }

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  secure_zero(prk, sizeof(prk));
  return ret == 0 && found;
}

bool derive_key_from_password(uint8_t *output_key, size_t key_len,
                              const char *password, size_t password_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iterations) {
  if (output_key == nullptr || password == nullptr ||
      key_len > kSha256DigestSize) {
    return false;
  }
  return pbkdf2_hmac_sha256(reinterpret_cast<const uint8_t *>(password),
                            password_len, salt, salt_len, iterations,
                            output_key, key_len);
}

bool generate_random_gcm_iv(TangRngContext *rng, uint8_t iv[kGcmIvSize]) {
  if (iv == nullptr || init_rng(rng) != 0) {
    return false;
  }

  return rng_callback(rng, iv, kGcmIvSize) == 0;
}

bool encrypt_local_data_gcm(uint8_t *ciphertext, const uint8_t *plaintext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *salt,
                            size_t salt_len, uint32_t iterations,
                            const uint8_t *iv, size_t iv_len, uint8_t *tag,
                            size_t tag_len) {
  if (ciphertext == nullptr || plaintext == nullptr || password == nullptr ||
      iv == nullptr || tag == nullptr) {
    return false;
  }

  uint8_t key[kAes128KeySize];
  if (!derive_key_from_password(key, sizeof(key), password, password_len, salt,
                                salt_len, iterations)) {
    return false;
  }

  mbedtls_gcm_context gcm_ctx;
  mbedtls_gcm_init(&gcm_ctx);

  int ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key,
                               sizeof(key) * 8);
  if (ret == 0) {
    ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, data_len, iv,
                                    iv_len, nullptr, 0, plaintext, ciphertext,
                                    tag_len, tag);
  }

  mbedtls_gcm_free(&gcm_ctx);
  secure_zero(key, sizeof(key));
  return ret == 0;
}

bool decrypt_local_data_gcm(uint8_t *plaintext, const uint8_t *ciphertext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *salt,
                            size_t salt_len, uint32_t iterations,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *tag, size_t tag_len) {
  if (plaintext == nullptr || ciphertext == nullptr || password == nullptr ||
      iv == nullptr || tag == nullptr) {
    return false;
  }

  uint8_t key[kAes128KeySize];
  if (!derive_key_from_password(key, sizeof(key), password, password_len, salt,
                                salt_len, iterations)) {
    return false;
  }

  mbedtls_gcm_context gcm_ctx;
  mbedtls_gcm_init(&gcm_ctx);

  int ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key,
                               sizeof(key) * 8);
  if (ret == 0) {
    ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, data_len, iv, iv_len, nullptr, 0,
                                   tag, tag_len, ciphertext, plaintext);
  }

  mbedtls_gcm_free(&gcm_ctx);
  secure_zero(key, sizeof(key));
  return ret == 0;
}

}  // namespace tang
