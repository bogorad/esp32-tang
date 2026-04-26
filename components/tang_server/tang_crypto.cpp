#include "tang_crypto.h"

#include <cstring>
#include <string>

#if defined(USE_ESP_IDF)
#include <mbedtls/esp_config.h>
#endif

#include <mbedtls/base64.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
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

int init_rng(TangRngContext *rng) {
  if (rng == nullptr) {
    return -1;
  }

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

  *rng_func = mbedtls_ctr_drbg_random;
  *rng_ctx = &rng->ctr_drbg;
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
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random,
                                  &rng->ctr_drbg);
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
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random,
                          &rng->ctr_drbg);
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
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, mbedtls_ctr_drbg_random,
                          &rng->ctr_drbg);
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
    ret = mbedtls_ecp_mul(&grp, &output, &d, &input, mbedtls_ctr_drbg_random,
                          &rng->ctr_drbg);
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
                               char *output, size_t output_size,
                               size_t *output_len) {
  if (pub_key == nullptr || output == nullptr || output_size == 0) {
    return false;
  }

  char x[48];
  char y[48];
  size_t x_len = 0;
  size_t y_len = 0;
  uint8_t digest[kSha256DigestSize];
  bool ok = base64_url_encode(pub_key, kEcPrivateKeySize, x, sizeof(x),
                              &x_len) &&
            base64_url_encode(pub_key + kEcPrivateKeySize, kEcPrivateKeySize, y,
                              sizeof(y), &y_len);
  if (ok) {
    const std::string canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" +
                                  std::string(x, x_len) + "\",\"y\":\"" +
                                  std::string(y, y_len) + "\"}";
    ok = sha256_digest(reinterpret_cast<const uint8_t *>(canonical.data()),
                       canonical.size(), digest);
  }
  if (ok) {
    ok = base64_url_encode(digest, sizeof(digest), output, output_size,
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
                             mbedtls_ctr_drbg_random, &rng->ctr_drbg);
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

bool derive_key_from_password(uint8_t *output_key, size_t key_len,
                              const char *password, size_t password_len) {
  if (output_key == nullptr || password == nullptr ||
      key_len > kSha256DigestSize) {
    return false;
  }

  mbedtls_sha256_context sha_ctx;
  uint8_t hash[kSha256DigestSize];

  mbedtls_sha256_init(&sha_ctx);
  int ret = mbedtls_sha256_starts(&sha_ctx, 0);
  if (ret == 0) {
    ret = mbedtls_sha256_update(
        &sha_ctx, reinterpret_cast<const uint8_t *>(password), password_len);
  }
  if (ret == 0) {
    ret = mbedtls_sha256_finish(&sha_ctx, hash);
  }
  mbedtls_sha256_free(&sha_ctx);

  if (ret == 0) {
    std::memcpy(output_key, hash, key_len);
  }
  secure_zero(hash, sizeof(hash));
  return ret == 0;
}

bool generate_random_gcm_iv(TangRngContext *rng, uint8_t iv[kGcmIvSize]) {
  if (iv == nullptr || init_rng(rng) != 0) {
    return false;
  }

  return mbedtls_ctr_drbg_random(&rng->ctr_drbg, iv, kGcmIvSize) == 0;
}

bool encrypt_local_data_gcm(uint8_t *ciphertext, const uint8_t *plaintext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *iv,
                            size_t iv_len, uint8_t *tag, size_t tag_len) {
  if (ciphertext == nullptr || plaintext == nullptr || password == nullptr ||
      iv == nullptr || tag == nullptr) {
    return false;
  }

  uint8_t key[kAes128KeySize];
  if (!derive_key_from_password(key, sizeof(key), password, password_len)) {
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
                            size_t password_len, const uint8_t *iv,
                            size_t iv_len, const uint8_t *tag,
                            size_t tag_len) {
  if (plaintext == nullptr || ciphertext == nullptr || password == nullptr ||
      iv == nullptr || tag == nullptr) {
    return false;
  }

  uint8_t key[kAes128KeySize];
  if (!derive_key_from_password(key, sizeof(key), password, password_len)) {
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
