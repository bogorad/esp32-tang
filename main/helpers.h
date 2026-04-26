#ifndef HELPERS_H
#define HELPERS_H

#include <cstring>

#include "tang_crypto.h"

// Debug macros (duplicated from TangServer.h to fix include order)
#ifndef DEBUG_PRINTLN
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif

// --- Constants ---
extern const int GCM_TAG_SIZE;

// --- Helper Functions ---

inline tang::TangRngContext &shared_tang_rng() {
    static tang::TangRngContext rng;
    return rng;
}

/**
 * @brief Initialize the random number generator using ESP32's hardware RNG.
 * This is crucial for providing a strong entropy source.
 * @return 0 on success, negative on failure.
 */
inline int init_rng() {
    int ret = tang::init_rng(&shared_tang_rng());
    if (ret != 0) {
        DEBUG_PRINTF("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
    }
    return ret;
}

/**
 * @brief Cleanup RNG resources
 */
inline void cleanup_rng() {
    tang::cleanup_rng(&shared_tang_rng());
}

/**
 * @brief Get the random number generator function and context
 * @param rng_func Pointer to store the RNG function
 * @param rng_ctx Pointer to store the RNG context
 * @return 0 on success, negative on failure
 */
inline int get_rng_context(int (**rng_func)(void *, unsigned char *, size_t), void **rng_ctx) {
    return tang::get_rng_context(&shared_tang_rng(), rng_func, rng_ctx);
}

/**
 * @brief Prints a byte array as a hex string to the Serial console.
 */
void print_hex(const uint8_t* data, int len) {
#if defined(DEBUG_SERIAL) && DEBUG_SERIAL > 0
    for (int i = 0; i < len; ++i) {
        if (data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
    }
    Serial.println();
#endif
}

/**
 * @brief Base64URL encodes a byte array. This is a self-contained implementation.
 */
inline String base64_url_encode(const uint8_t* data, size_t len) {
    size_t output_size = ((len + 2) / 3) * 4 + 1;
    char* buffer = new char[output_size];
    size_t output_len = 0;
    if (!tang::base64_url_encode(data, len, buffer, output_size, &output_len)) {
        delete[] buffer;
        return String(); // Return empty string on failure
    }
    String encoded = String(buffer);
    delete[] buffer;
    return encoded;
}


/**
 * @brief Decodes a Base64URL string into a byte array.
 * This is a self-contained implementation to avoid dependency issues.
 * @return Decoded length on success, -1 on failure.
 */

inline int base64_url_decode(String b64_url, uint8_t* output, int max_len) {
    if (max_len < 0) {
        return -1;
    }

    size_t decoded_len = 0;
    if (!tang::base64_url_decode(b64_url.c_str(), b64_url.length(), output,
                                 static_cast<size_t>(max_len), &decoded_len)) {
        return -1;
    }
    return static_cast<int>(decoded_len);
}

/**
 * @brief Generates a new secp256r1 key pair using mbedTLS.
 * @param pub_key Buffer for the public key (64 bytes, X || Y).
 * @param priv_key Buffer for the private key (32 bytes).
 * @return true on success, false on failure.
 */
inline bool generate_ec_keypair(uint8_t* pub_key, uint8_t* priv_key) {
    bool ok = tang::generate_ec_keypair(&shared_tang_rng(), pub_key, priv_key);
    if (!ok) {
        DEBUG_PRINTLN("EC keypair generation failed");
    }
    return ok;
}

/**
 * @brief Computes a public key from a private key using mbedTLS.
 * @param priv_key The private key (32 bytes).
 * @param pub_key Buffer for the public key (64 bytes, X || Y).
 * @return true on success, false on failure.
 */
inline bool compute_ec_public_key(const uint8_t* priv_key, uint8_t* pub_key) {
    bool ok = tang::compute_ec_public_key(&shared_tang_rng(), priv_key, pub_key);
    if (!ok) {
        DEBUG_PRINTLN("EC public key computation failed");
    }
    return ok;
}

/**
 * @brief Computes an ECDH shared secret using mbedTLS.
 * @param eph_pub_key The ephemeral public key from the client (64 bytes, X || Y).
 * @param priv_key The server's private key (32 bytes).
 * @param shared_secret Buffer for the resulting shared secret (32 bytes).
 * @return true on success, false on failure.
 */
inline bool compute_ecdh_shared_secret(const uint8_t* eph_pub_key, const uint8_t* priv_key, uint8_t* shared_secret) {
    bool ok = tang::compute_ecdh_shared_secret(&shared_tang_rng(), eph_pub_key,
                                               priv_key, shared_secret);
    if (!ok) {
        DEBUG_PRINTLN("ECDH shared secret computation failed");
    }
    return ok;
}


/**
 * @brief Implements the Concat KDF using the mbedTLS C API.
 */
inline void concat_kdf(uint8_t* output_key, size_t output_key_len_bytes,
                       const uint8_t* shared_secret, size_t shared_secret_len,
                       const char* alg_id, size_t alg_id_len) {
    if (!tang::concat_kdf(output_key, output_key_len_bytes, shared_secret,
                          shared_secret_len, alg_id, alg_id_len)) {
        DEBUG_PRINTLN("Concat KDF failed");
    }
}

/**
 * @brief Decrypts data using AES-GCM with the mbedTLS C API.
 */
inline bool jwe_gcm_decrypt(uint8_t* ciphertext_buf, size_t ciphertext_len,
                            const uint8_t* cek, size_t cek_len,
                            const uint8_t* iv, size_t iv_len,
                            const uint8_t* tag, size_t tag_len,
                            const uint8_t* aad, size_t aad_len) {
    bool ok = tang::jwe_gcm_decrypt(ciphertext_buf, ciphertext_buf, ciphertext_len,
                                    cek, cek_len, iv, iv_len, tag, tag_len, aad,
                                    aad_len);
    if (!ok) {
        DEBUG_PRINTLN("JWE GCM decrypt failed");
    }
    return ok;
}

/**
 * @brief Derives a key from a password using SHA-256 with the mbedTLS C API.
 */
inline void derive_key_from_password(uint8_t* output_key, size_t key_len, const char* password) {
    if (!tang::derive_key_from_password(output_key, key_len, password,
                                        strlen(password))) {
        DEBUG_PRINTLN("Password key derivation failed");
    }
}

/**
 * @brief Encrypts or decrypts local data using AES-GCM with the mbedTLS C API.
 */
inline bool crypt_local_data_gcm(uint8_t* data, size_t data_len, const char* pw, bool encrypt, uint8_t* tag_buffer, uint8_t* iv_buffer) {
    if (iv_buffer == nullptr) {
        DEBUG_PRINTLN("GCM IV buffer missing");
        return false;
    }
    if (encrypt && !tang::generate_random_gcm_iv(&shared_tang_rng(), iv_buffer)) {
        DEBUG_PRINTLN("GCM IV generation failed");
        return false;
    }
    bool ok = encrypt
        ? tang::encrypt_local_data_gcm(data, data, data_len, pw, strlen(pw), iv_buffer,
                                      tang::kGcmIvSize, tag_buffer, GCM_TAG_SIZE)
        : tang::decrypt_local_data_gcm(data, data, data_len, pw, strlen(pw), iv_buffer,
                                      tang::kGcmIvSize, tag_buffer, GCM_TAG_SIZE);
    if (!ok) {
        DEBUG_PRINTLN("GCM operation failed");
    }
    return ok;
}

// deactivate_server() function moved to TangServer.h to avoid dependency issues

/**
 * @brief Clears sensitive key material from memory and deactivates the server.
 */
void deactivate_server() {
    is_active = false;
    activation_timestamp = 0;
    memset(tang_private_key, 0, sizeof(tang_private_key));
    memset(tang_public_key, 0, sizeof(tang_public_key));
    DEBUG_PRINTLN("Server DEACTIVATED. Tang keys cleared from memory.");
}

#endif // HELPERS_H
