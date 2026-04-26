#pragma once

#include <cstddef>
#include <cstdint>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace tang {

constexpr size_t kEcPrivateKeySize = 32;
constexpr size_t kEcPublicKeySize = 64;
constexpr size_t kAes128KeySize = 16;
constexpr size_t kGcmIvSize = 12;
constexpr size_t kGcmTagSize = 16;
constexpr size_t kSha256DigestSize = 32;

using TangRandomFunc = int (*)(void *ctx, unsigned char *output, size_t len);

struct TangRngContext {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  bool initialized;

  TangRngContext();
  TangRngContext(const TangRngContext &) = delete;
  TangRngContext &operator=(const TangRngContext &) = delete;
  ~TangRngContext();
};

int init_rng(TangRngContext *rng);
void cleanup_rng(TangRngContext *rng);
int get_rng_context(TangRngContext *rng, TangRandomFunc *rng_func, void **rng_ctx);

void secure_zero(void *ptr, size_t len);

bool base64_url_encode(const uint8_t *data, size_t data_len, char *output,
                       size_t output_size, size_t *output_len);
bool base64_url_decode(const char *input, size_t input_len, uint8_t *output,
                       size_t output_size, size_t *output_len);
bool sha256_digest(const uint8_t *data, size_t data_len,
                   uint8_t digest[kSha256DigestSize]);

bool generate_ec_keypair(TangRngContext *rng, uint8_t pub_key[kEcPublicKeySize],
                         uint8_t priv_key[kEcPrivateKeySize]);
bool compute_ec_public_key(TangRngContext *rng,
                           const uint8_t priv_key[kEcPrivateKeySize],
                           uint8_t pub_key[kEcPublicKeySize]);
bool compute_ecdh_shared_secret(TangRngContext *rng,
                                 const uint8_t peer_pub_key[kEcPublicKeySize],
                                 const uint8_t priv_key[kEcPrivateKeySize],
                                 uint8_t shared_secret[kEcPrivateKeySize]);
bool compute_ec_point_multiply(TangRngContext *rng,
                               const uint8_t peer_pub_key[kEcPublicKeySize],
                               const uint8_t priv_key[kEcPrivateKeySize],
                               uint8_t output_pub_key[kEcPublicKeySize]);
bool compute_ec_jwk_thumbprint(const uint8_t pub_key[kEcPublicKeySize],
                                char *output, size_t output_size,
                                size_t *output_len);
bool sign_es256(TangRngContext *rng, const uint8_t priv_key[kEcPrivateKeySize],
                const uint8_t *data, size_t data_len,
                uint8_t signature[kEcPublicKeySize]);

bool concat_kdf(uint8_t *output_key, size_t output_key_len_bytes,
                const uint8_t *shared_secret, size_t shared_secret_len,
                const char *alg_id, size_t alg_id_len);

bool jwe_gcm_decrypt(uint8_t *plaintext, const uint8_t *ciphertext,
                     size_t ciphertext_len, const uint8_t *cek, size_t cek_len,
                     const uint8_t *iv, size_t iv_len, const uint8_t *tag,
                     size_t tag_len, const uint8_t *aad, size_t aad_len);

bool derive_key_from_password(uint8_t *output_key, size_t key_len,
                              const char *password, size_t password_len);
bool generate_random_gcm_iv(TangRngContext *rng, uint8_t iv[kGcmIvSize]);
bool encrypt_local_data_gcm(uint8_t *ciphertext, const uint8_t *plaintext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *iv,
                            size_t iv_len, uint8_t *tag, size_t tag_len);
bool decrypt_local_data_gcm(uint8_t *plaintext, const uint8_t *ciphertext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *iv,
                            size_t iv_len, const uint8_t *tag,
                            size_t tag_len);

}  // namespace tang
