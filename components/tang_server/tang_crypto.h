#pragma once

#include <cstddef>
#include <cstdint>

#include <mutex>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace tang {

constexpr size_t kEcPrivateKeySize = 32;
constexpr size_t kEcPublicKeySize = 64;
constexpr size_t kAes128KeySize = 16;
constexpr size_t kGcmIvSize = 12;
constexpr size_t kGcmTagSize = 16;
constexpr size_t kSha256DigestSize = 32;

constexpr size_t kSha1DigestSize = 20;

enum class ThumbprintHash { kSha1, kSha256 };

using TangRandomFunc = int (*)(void *ctx, unsigned char *output, size_t len);

struct TangRngContext {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  bool initialized;
  std::mutex mutex;  // serializes ctr_drbg access across tasks

  TangRngContext();
  TangRngContext(const TangRngContext &) = delete;
  TangRngContext &operator=(const TangRngContext &) = delete;
  ~TangRngContext();
};

// Thread-safe random callback; ctx must be a TangRngContext initialized with
// init_rng().
int rng_callback(void *ctx, unsigned char *output, size_t len);
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
// RFC 7638 JWK thumbprint, base64url without padding. Clevis 17+ uses SHA-256
// for the JWE "kid"; older clients and tangd's own tools also use SHA-1.
bool compute_ec_jwk_thumbprint(const uint8_t pub_key[kEcPublicKeySize],
                               ThumbprintHash hash, char *output,
                               size_t output_size, size_t *output_len);
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

// HMAC-SHA256, HKDF-SHA256 (RFC 5869) and PBKDF2-HMAC-SHA256 (RFC 8018), built
// on mbedtls_md so they do not depend on optional mbedTLS HKDF/PKCS5 modules.
bool hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                 size_t data_len, uint8_t out[kSha256DigestSize]);
bool hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[kSha256DigestSize]);
bool hkdf_sha256_expand(const uint8_t prk[kSha256DigestSize],
                        const uint8_t *info, size_t info_len, uint8_t *okm,
                        size_t okm_len);
bool pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len);

// Seed-derived keys (unattended mode).
//
// A seed is a hex string. Its decoded bytes (at least kMinSeedBytes) are the
// HKDF input keying material. Salt is the fixed string kSeedSalt. For each key
// role ("signing", "exchange") the private scalar is
//   HKDF-Expand(PRK, kSeedSalt "/" role 0x00 counter, 32)
// with counter = 0, 1, 2, ... until the value is in [1, n-1] (rejection
// sampling, no modulo bias). The derivation is part of the on-wire identity of
// the server: changing it changes every key. Bump the "v1" label if it must
// change.
constexpr size_t kMinSeedBytes = 32;
constexpr size_t kMaxSeedBytes = 128;
constexpr size_t kMinSeedDistinctBytes = 8;
constexpr char kSeedSalt[] = "esp32-tang/v1";
constexpr char kSeedRoleSigning[] = "signing";
constexpr char kSeedRoleExchange[] = "exchange";

// Decode a hex seed (case-insensitive, even length, >= 64 hex chars, not
// degenerate). Returns false and leaves *out_len = 0 on any problem.
bool decode_seed_hex(const char *hex, uint8_t *out, size_t out_capacity,
                     size_t *out_len);
bool derive_p256_private_key(const uint8_t *seed, size_t seed_len,
                             const char *role,
                             uint8_t priv_key[kEcPrivateKeySize]);

// Password mode: PBKDF2-HMAC-SHA256 with a random per-record salt.
constexpr size_t kPasswordSaltSize = 16;
// Chosen for an ESP32: 20000 iterations is about 40000 SHA-256 compressions,
// which is roughly 0.3 to 1 s on a 240 MHz ESP32 (estimate, not measured on
// hardware). It slows offline guessing against a flash dump; it does not make
// a weak password strong.
constexpr uint32_t kPasswordPbkdf2Iterations = 20000;

bool derive_key_from_password(uint8_t *output_key, size_t key_len,
                              const char *password, size_t password_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iterations);
bool generate_random_gcm_iv(TangRngContext *rng, uint8_t iv[kGcmIvSize]);
bool encrypt_local_data_gcm(uint8_t *ciphertext, const uint8_t *plaintext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *salt,
                            size_t salt_len, uint32_t iterations,
                            const uint8_t *iv, size_t iv_len, uint8_t *tag,
                            size_t tag_len);
bool decrypt_local_data_gcm(uint8_t *plaintext, const uint8_t *ciphertext,
                            size_t data_len, const char *password,
                            size_t password_len, const uint8_t *salt,
                            size_t salt_len, uint32_t iterations,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *tag, size_t tag_len);

}  // namespace tang
