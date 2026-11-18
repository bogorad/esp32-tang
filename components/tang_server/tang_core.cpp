#include "tang_core.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

TangResponse text_response(int status, const char *body) {
  TangResponse response;
  response.status = status;
  response.content_type = "text/plain";
  response.body = body;
  return response;
}

TangResponse json_response(const std::string &body) {
  TangResponse response;
  response.status = 200;
  response.content_type = "application/json";
  response.body = body;
  return response;
}

TangResponse json_response(int status, const std::string &body) {
  TangResponse response = json_response(body);
  response.status = status;
  return response;
}

bool encode_key_part(const uint8_t *data, std::string *out) {
  char encoded[48];
  size_t encoded_len = 0;
  if (!tang::base64_url_encode(data, tang::kEcPrivateKeySize, encoded,
                               sizeof(encoded), &encoded_len)) {
    return false;
  }

  out->assign(encoded, encoded_len);
  return true;
}

bool find_json_string(const std::string &json, const char *key,
                      std::string *out) {
  if (key == nullptr || out == nullptr) {
    return false;
  }

  const std::string needle = std::string("\"") + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return false;
  }

  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return false;
  }
  pos = json.find('"', pos + 1);
  if (pos == std::string::npos) {
    return false;
  }

  std::string value;
  for (++pos; pos < json.size(); ++pos) {
    const char ch = json[pos];
    if (ch == '\\') {
      if (pos + 1 >= json.size()) {
        return false;
      }
      value.push_back(json[++pos]);
      continue;
    }
    if (ch == '"') {
      *out = value;
      return true;
    }
    value.push_back(ch);
  }
  return false;
}

bool json_has_key(const std::string &json, const char *key) {
  if (key == nullptr) {
    return false;
  }

  const std::string needle = std::string("\"") + key + "\"";
  return json.find(needle) != std::string::npos;
}

bool json_key_ops_allows_derive_key(const std::string &json) {
  if (!json_has_key(json, "key_ops")) {
    return true;
  }

  const size_t key_ops_pos = json.find("\"key_ops\"");
  const size_t array_start = json.find('[', key_ops_pos);
  const size_t array_end = json.find(']', array_start);
  if (array_start == std::string::npos || array_end == std::string::npos) {
    return false;
  }

  return json.substr(array_start, array_end - array_start).find(
             "\"deriveKey\"") != std::string::npos;
}

bool decode_base64_url_string(const std::string &input, uint8_t *output,
                              size_t output_size, size_t *output_len) {
  return tang::base64_url_decode(input.c_str(), input.size(), output,
                                 output_size, output_len);
}

struct ParsedJwePassword {
  uint8_t epk[tang::kEcPublicKeySize]{0};
  uint8_t iv[tang::kGcmIvSize]{0};
  uint8_t tag[tang::kGcmTagSize]{0};
  uint8_t ciphertext[128]{0};
  size_t ciphertext_len{0};
};

// ParsedJwePassword holds only plain bytes, so it can be zeroed with
// secure_zero. The protected header is public data and is returned separately
// in a std::string (never memset a std::string).
bool parse_jwe_password(const std::string &body, ParsedJwePassword *out,
                        std::string *protected_header) {
  if (out == nullptr || protected_header == nullptr) {
    return false;
  }

  std::string x;
  std::string y;
  std::string iv;
  std::string tag;
  std::string ciphertext;
  if (!find_json_string(body, "protected", protected_header) ||
      !find_json_string(body, "x", &x) || !find_json_string(body, "y", &y) ||
      !find_json_string(body, "iv", &iv) ||
      !find_json_string(body, "ciphertext", &ciphertext) ||
      !find_json_string(body, "tag", &tag)) {
    return false;
  }

  size_t decoded_len = 0;
  if (!decode_base64_url_string(x, out->epk, tang::kEcPrivateKeySize,
                                &decoded_len) ||
      decoded_len != tang::kEcPrivateKeySize ||
      !decode_base64_url_string(y, out->epk + tang::kEcPrivateKeySize,
                                tang::kEcPrivateKeySize, &decoded_len) ||
      decoded_len != tang::kEcPrivateKeySize ||
      !decode_base64_url_string(iv, out->iv, sizeof(out->iv), &decoded_len) ||
      decoded_len != sizeof(out->iv) ||
      !decode_base64_url_string(tag, out->tag, sizeof(out->tag),
                                &decoded_len) ||
      decoded_len != sizeof(out->tag) ||
      !decode_base64_url_string(ciphertext, out->ciphertext,
                                sizeof(out->ciphertext),
                                &out->ciphertext_len)) {
    tang::secure_zero(out, sizeof(*out));
    return false;
  }

  return true;
}

struct ParsedRecoveryJwk {
  uint8_t public_key[tang::kEcPublicKeySize]{0};
};

bool parse_recovery_jwk(const std::string &body, ParsedRecoveryJwk *out,
                        const char **error) {
  if (out == nullptr) {
    return false;
  }

  std::string kty;
  std::string crv;
  std::string alg;
  std::string x;
  std::string y;
  if (!find_json_string(body, "kty", &kty) ||
      !find_json_string(body, "crv", &crv) ||
      !find_json_string(body, "x", &x) || !find_json_string(body, "y", &y)) {
    if (error != nullptr) {
      *error = "Recovery request must be an EC public JWK";
    }
    return false;
  }

  if (kty != "EC" || crv != "P-256") {
    if (error != nullptr) {
      *error = "Recovery request must use a P-256 EC key";
    }
    return false;
  }

  if (find_json_string(body, "alg", &alg) && alg != "ECMR") {
    if (error != nullptr) {
      *error = "Recovery request alg must be ECMR";
    }
    return false;
  }

  if (!json_key_ops_allows_derive_key(body)) {
    if (error != nullptr) {
      *error = "Recovery request key_ops must allow deriveKey";
    }
    return false;
  }

  size_t decoded_len = 0;
  if (!decode_base64_url_string(x, out->public_key, tang::kEcPrivateKeySize,
                                &decoded_len) ||
      decoded_len != tang::kEcPrivateKeySize ||
      !decode_base64_url_string(y, out->public_key + tang::kEcPrivateKeySize,
                                tang::kEcPrivateKeySize, &decoded_len) ||
      decoded_len != tang::kEcPrivateKeySize) {
    tang::secure_zero(out, sizeof(*out));
    if (error != nullptr) {
      *error = "Recovery request contains invalid EC coordinates";
    }
    return false;
  }

  return true;
}

bool decrypt_jwe_password(tang::TangRngContext *rng,
                          const uint8_t admin_private_key[tang::kEcPrivateKeySize],
                          const std::string &body, std::string *password,
                          int *error_status, const char **error_body) {
  ParsedJwePassword parsed;
  std::string protected_header;
  uint8_t shared_secret[tang::kEcPrivateKeySize]{0};
  uint8_t cek[tang::kAes128KeySize]{0};
  uint8_t plaintext[sizeof(parsed.ciphertext) + 1]{0};
  bool ok = false;

  if (!parse_jwe_password(body, &parsed, &protected_header)) {
    if (error_status != nullptr) {
      *error_status = 400;
    }
    if (error_body != nullptr) {
      *error_body = "Bad Request: Invalid JWE";
    }
    goto cleanup;
  }

  if (!tang::compute_ecdh_shared_secret(rng, parsed.epk, admin_private_key,
                                        shared_secret)) {
    if (error_status != nullptr) {
      *error_status = 500;
    }
    if (error_body != nullptr) {
      *error_body = "Activation ECDH failed";
    }
    goto cleanup;
  }

  if (!tang::concat_kdf(cek, sizeof(cek), shared_secret,
                        sizeof(shared_secret), "A128GCM",
                        std::strlen("A128GCM"))) {
    if (error_status != nullptr) {
      *error_status = 500;
    }
    if (error_body != nullptr) {
      *error_body = "Activation KDF failed";
    }
    goto cleanup;
  }

  if (!tang::jwe_gcm_decrypt(
          plaintext, parsed.ciphertext, parsed.ciphertext_len, cek,
          sizeof(cek), parsed.iv, sizeof(parsed.iv), parsed.tag,
          sizeof(parsed.tag),
          reinterpret_cast<const uint8_t *>(protected_header.data()),
          protected_header.size())) {
    if (error_status != nullptr) {
      *error_status = 401;
    }
    if (error_body != nullptr) {
      *error_body = "JWE decryption failed: invalid message or tag";
    }
    goto cleanup;
  }

  plaintext[parsed.ciphertext_len] = '\0';
  password->assign(reinterpret_cast<const char *>(plaintext),
                   parsed.ciphertext_len);
  ok = true;

cleanup:
  tang::secure_zero(&parsed, sizeof(parsed));
  tang::secure_zero(shared_secret, sizeof(shared_secret));
  tang::secure_zero(cek, sizeof(cek));
  tang::secure_zero(plaintext, sizeof(plaintext));
  return ok;
}

bool base64_url_encode_string(const uint8_t *data, size_t data_len,
                              std::string *out) {
  if ((data == nullptr && data_len != 0) || out == nullptr) {
    return false;
  }

  const size_t output_size = ((data_len + 2) / 3) * 4 + 1;
  std::string encoded(output_size, '\0');
  size_t encoded_len = 0;
  if (!tang::base64_url_encode(data, data_len, &encoded[0], encoded.size(),
                               &encoded_len)) {
    return false;
  }

  encoded.resize(encoded_len);
  *out = encoded;
  return true;
}

bool base64_url_encode_string(const std::string &data, std::string *out) {
  return base64_url_encode_string(
      reinterpret_cast<const uint8_t *>(data.data()), data.size(), out);
}

bool compute_key_id(const uint8_t public_key[tang::kEcPublicKeySize],
                    tang::ThumbprintHash hash, std::string *kid) {
  char encoded[48];
  size_t encoded_len = 0;
  if (!tang::compute_ec_jwk_thumbprint(public_key, hash, encoded,
                                       sizeof(encoded), &encoded_len)) {
    return false;
  }

  kid->assign(encoded, encoded_len);
  return true;
}

// True when `kid` is the SHA-256 or SHA-1 RFC 7638 thumbprint of the key.
// Clevis 17+ sends SHA-256; tangd also accepts SHA-1.
bool kid_matches(const uint8_t public_key[tang::kEcPublicKeySize],
                 const std::string &kid) {
  std::string candidate;
  return (compute_key_id(public_key, tang::ThumbprintHash::kSha256,
                         &candidate) && candidate == kid) ||
         (compute_key_id(public_key, tang::ThumbprintHash::kSha1,
                         &candidate) && candidate == kid);
}

bool public_jwk(const uint8_t public_key[tang::kEcPublicKeySize],
                const char *alg, const char *key_ops, bool include_kid,
                std::string *out, std::string *kid_out) {
  std::string x;
  std::string y;
  std::string kid;
  if (!encode_key_part(public_key, &x) ||
      !encode_key_part(public_key + tang::kEcPrivateKeySize, &y)) {
    return false;
  }

  if (include_kid &&
      !compute_key_id(public_key, tang::ThumbprintHash::kSha256, &kid)) {
    return false;
  }

  std::string key = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x +
                    "\",\"y\":\"" + y + "\"";
  if (include_kid) {
    key += ",\"kid\":\"";
    key += kid;
    key += "\"";
  }
  if (key_ops != nullptr) {
    key += ",\"key_ops\":";
    key += key_ops;
  }
  if (alg != nullptr) {
    key += ",\"alg\":\"";
    key += alg;
    key += "\"";
  }
  key += "}";

  if (kid_out != nullptr) {
    *kid_out = kid;
  }
  *out = key;
  return true;
}

TangResponse public_key_response(const uint8_t public_key[tang::kEcPublicKeySize],
                                 bool wrap_in_keys_array, const char *alg) {
  std::string key;
  if (!public_jwk(public_key, alg,
                  wrap_in_keys_array ? "[\"deriveKey\"]" : nullptr,
                  wrap_in_keys_array, &key, nullptr)) {
    return text_response(500, "Failed to encode public key");
  }

  if (wrap_in_keys_array) {
    return json_response("{\"keys\":[" + key + "]}");
  }

  return json_response(key);
}

TangResponse recovery_key_response(
    tang::TangRngContext *rng,
    const uint8_t exchange_private_key[tang::kEcPrivateKeySize],
    const uint8_t request_public_key[tang::kEcPublicKeySize]) {
  uint8_t response_public_key[tang::kEcPublicKeySize]{0};
  if (!tang::compute_ec_point_multiply(rng, request_public_key,
                                       exchange_private_key,
                                       response_public_key)) {
    tang::secure_zero(response_public_key, sizeof(response_public_key));
    return json_response(400,
                         "{\"error\":\"invalid_recovery_key\","
                         "\"message\":\"Recovery request key is invalid\"}");
  }

  std::string key;
  const bool ok = public_jwk(response_public_key, "ECMR",
                             "[\"deriveKey\"]", false, &key, nullptr);
  tang::secure_zero(response_public_key, sizeof(response_public_key));
  if (!ok) {
    return text_response(500, "Failed to encode recovery key");
  }

  TangResponse response = json_response(key);
  response.content_type = "application/jwk+json";
  return response;
}

// One signature on an advertisement. `priv` is the signing private key.
struct AdvSigner {
  uint8_t pub[tang::kEcPublicKeySize];
  uint8_t priv[tang::kEcPrivateKeySize];
};

// Build the signed /adv response. The payload advertises the current signing
// and exchange keys only. With one signer the JWS is flattened; with several
// (tangd signs /adv/<thp> with all current keys plus the key named by <thp>)
// it is the general JSON serialization with a `signatures` array.
TangResponse signed_advertisement_response(
    tang::TangRngContext *rng, const AdvSigner *signers, size_t signer_count,
    const uint8_t signing_public_key[tang::kEcPublicKeySize],
    const uint8_t exchange_public_key[tang::kEcPublicKeySize]) {
  std::string signing_jwk;
  std::string exchange_jwk;
  if (signer_count == 0 ||
      !public_jwk(signing_public_key, "ES256", "[\"verify\"]", true,
                  &signing_jwk, nullptr) ||
      !public_jwk(exchange_public_key, "ECMR", "[\"deriveKey\"]", true,
                  &exchange_jwk, nullptr)) {
    return text_response(500, "Failed to encode advertisement keys");
  }

  const std::string payload = "{\"keys\":[" + signing_jwk + "," +
                              exchange_jwk + "]}";
  std::string payload_b64;
  if (!base64_url_encode_string(payload, &payload_b64)) {
    return text_response(500, "Failed to encode advertisement JWS");
  }

  std::string signatures;
  for (size_t i = 0; i < signer_count; ++i) {
    std::string kid;
    if (!compute_key_id(signers[i].pub, tang::ThumbprintHash::kSha256, &kid)) {
      return text_response(500, "Failed to compute signing key id");
    }
    const std::string protected_header =
        "{\"alg\":\"ES256\",\"cty\":\"jwk-set+json\",\"kid\":\"" + kid + "\"}";
    std::string protected_b64;
    if (!base64_url_encode_string(protected_header, &protected_b64)) {
      return text_response(500, "Failed to encode advertisement JWS");
    }

    const std::string signing_input = protected_b64 + "." + payload_b64;
    uint8_t signature[tang::kEcPublicKeySize];
    if (!tang::sign_es256(
            rng, signers[i].priv,
            reinterpret_cast<const uint8_t *>(signing_input.data()),
            signing_input.size(), signature)) {
      tang::secure_zero(signature, sizeof(signature));
      return text_response(500, "Failed to sign advertisement JWS");
    }
    std::string signature_b64;
    const bool ok = base64_url_encode_string(signature, sizeof(signature),
                                             &signature_b64);
    tang::secure_zero(signature, sizeof(signature));
    if (!ok) {
      return text_response(500, "Failed to encode advertisement signature");
    }

    if (signer_count == 1) {
      return json_response("{\"payload\":\"" + payload_b64 +
                           "\",\"protected\":\"" + protected_b64 +
                           "\",\"signature\":\"" + signature_b64 + "\"}");
    }
    if (i != 0) {
      signatures += ",";
    }
    signatures += "{\"protected\":\"" + protected_b64 + "\",\"signature\":\"" +
                  signature_b64 + "\"}";
  }

  return json_response("{\"payload\":\"" + payload_b64 + "\",\"signatures\":[" +
                       signatures + "]}");
}

bool is_thumbprint_text(const std::string &s) {
  if (s.empty() || s.size() > 64) {
    return false;
  }
  for (char c : s) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') || c == '-' || c == '_')) {
      return false;
    }
  }
  return true;
}

}  // namespace

TangServerCore::TangServerCore(TangStorage *storage, TangClock *clock,
                               TangLogger *logger)
    : storage_(storage),
      clock_(clock),
      logger_(logger),
      ready_(false),
      unattended_(false),
      active_(false),
      key_lifetime_ms_(kDefaultKeyLifetimeMs),
      activation_ms_(0),
      failed_attempts_(0),
      next_attempt_ms_(0),
      record_{},
      signing_{},
      exchange_{} {}

TangResponse TangServerCore::fail(int status, const char *body) {
  if (logger_ != nullptr) {
    std::string line = "Request rejected (" + std::to_string(status) +
                       "): " + body;
    logger_->warn(line.c_str());
  }
  return text_response(status, body);
}

TangResponse TangServerCore::fail_json(int status, const char *error,
                                       const char *message) {
  if (logger_ != nullptr) {
    std::string line = "Request rejected (" + std::to_string(status) + ") " +
                       error + ": " + message;
    logger_->warn(line.c_str());
  }
  return json_response(status, std::string("{\"error\":\"") + error +
                                   "\",\"message\":\"" + message + "\"}");
}

bool TangServerCore::setup(const char *initial_password) {
  TangConfig config;
  config.initial_password = initial_password;
  return setup(config);
}

bool TangServerCore::setup(const TangConfig &config) {
  if (clock_ == nullptr || logger_ == nullptr) {
    return false;
  }
  if (!config.unattended && storage_ == nullptr) {
    logger_->error("Password mode needs a storage backend");
    return false;
  }
  if (config.unattended) {
    return setup_unattended(config);
  }
  return setup_password(config);
}

bool TangServerCore::derive_keypairs(const char *seed_hex, KeyPair *signing,
                                     KeyPair *exchange) {
  uint8_t seed[tang::kMaxSeedBytes];
  size_t seed_len = 0;
  if (!tang::decode_seed_hex(seed_hex, seed, sizeof(seed), &seed_len)) {
    tang::secure_zero(seed, sizeof(seed));
    logger_->error(
        "Seed is invalid: need hex, at least 64 hex chars, not degenerate");
    return false;
  }

  bool ok =
      tang::derive_p256_private_key(seed, seed_len, tang::kSeedRoleSigning,
                                    signing->priv) &&
      tang::compute_ec_public_key(&rng_, signing->priv, signing->pub) &&
      tang::derive_p256_private_key(seed, seed_len, tang::kSeedRoleExchange,
                                    exchange->priv) &&
      tang::compute_ec_public_key(&rng_, exchange->priv, exchange->pub);
  tang::secure_zero(seed, sizeof(seed));
  if (!ok) {
    tang::secure_zero(signing, sizeof(*signing));
    tang::secure_zero(exchange, sizeof(*exchange));
    logger_->error("Seed key derivation failed");
  }
  return ok;
}

bool TangServerCore::setup_unattended(const TangConfig &config) {
  if (config.seed_hex == nullptr || config.seed_hex[0] == '\0') {
    logger_->error("Unattended mode needs a seed");
    return false;
  }

  KeyPair signing{};
  KeyPair exchange{};
  std::vector<KeyPair> old_signing;
  std::vector<KeyPair> old_exchange;
  bool ok = derive_keypairs(config.seed_hex, &signing, &exchange);
  for (size_t i = 0; ok && i < config.old_seeds_hex.size(); ++i) {
    if (config.old_seeds_hex[i] == config.seed_hex) {
      logger_->error("An old seed equals the current seed");
      ok = false;
      break;
    }
    KeyPair os{};
    KeyPair oe{};
    ok = derive_keypairs(config.old_seeds_hex[i].c_str(), &os, &oe);
    if (ok) {
      for (const KeyPair &prev : old_exchange) {
        if (std::memcmp(prev.pub, oe.pub, sizeof(oe.pub)) == 0) {
          logger_->error("Two old seeds are identical");
          ok = false;
        }
      }
    }
    if (ok) {
      old_signing.push_back(os);
      old_exchange.push_back(oe);
    }
    tang::secure_zero(&os, sizeof(os));
    tang::secure_zero(&oe, sizeof(oe));
  }

  if (!ok) {
    tang::secure_zero(&signing, sizeof(signing));
    tang::secure_zero(&exchange, sizeof(exchange));
    for (KeyPair &k : old_signing) tang::secure_zero(&k, sizeof(k));
    for (KeyPair &k : old_exchange) tang::secure_zero(&k, sizeof(k));
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    signing_ = signing;
    exchange_ = exchange;
    old_signing_ = old_signing;
    old_exchange_ = old_exchange;
    unattended_ = true;
    active_ = true;
    ready_ = true;
  }
  tang::secure_zero(&signing, sizeof(signing));
  tang::secure_zero(&exchange, sizeof(exchange));
  for (KeyPair &k : old_signing) tang::secure_zero(&k, sizeof(k));
  for (KeyPair &k : old_exchange) tang::secure_zero(&k, sizeof(k));
  logger_->debug("Unattended mode: keys derived from seed; server active.");
  return true;
}

bool TangServerCore::setup_password(const TangConfig &config) {
  const bool have_password =
      config.initial_password != nullptr && config.initial_password[0] != '\0';

  uint32_t stored_token = 0;
  TangStorageStatus token_status = storage_->read_reset_token(&stored_token);
  if (token_status == TangStorageStatus::kError) {
    logger_->error("Cannot read reset token from storage; staying inactive");
    return false;
  }

  uint8_t blob[kTangRecordEncodedSize + 64];
  size_t blob_len = 0;
  TangStorageStatus state_status =
      storage_->read_state(blob, sizeof(blob), &blob_len);
  if (state_status == TangStorageStatus::kError) {
    logger_->error("Cannot read stored state; staying inactive");
    return false;
  }

  if (token_status == TangStorageStatus::kOk &&
      stored_token != config.reset_token) {
    if (!have_password) {
      logger_->error(
          "reset_token changed but no initial_password is set; storage left "
          "untouched, staying inactive");
      return false;
    }
    logger_->warn("reset_token changed: wiping stored identity and creating a "
                  "new one");
    if (!storage_->wipe()) {
      logger_->error("Wipe failed; staying inactive");
      return false;
    }
    state_status = TangStorageStatus::kEmpty;
    token_status = TangStorageStatus::kEmpty;  // wipe() cleared it
  }

  if (state_status == TangStorageStatus::kEmpty) {
    if (token_status == TangStorageStatus::kOk) {
      // A token exists, so this device was initialized before. Empty state now
      // means lost or unreadable data (e.g. a storage read error), not a first
      // boot. Never create a new identity silently.
      logger_->error(
          "Reset token is stored but the key record is missing; refusing to "
          "create a new identity. Change reset_token (with initial_password) "
          "to start over deliberately.");
      return false;
    }
    if (!have_password) {
      logger_->error(
          "No stored record and no initial_password; staying inactive");
      return false;
    }
    if (!initialize_storage(config.initial_password, config.reset_token)) {
      return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    key_lifetime_ms_ = config.key_lifetime_ms;
    return ready_;
  }

  TangStoredState stored{};
  const TangDecodeStatus decoded = tang_decode_state(blob, blob_len, &stored);
  if (decoded != TangDecodeStatus::kOk) {
    // Never generate new keys over a record we cannot read: that would change
    // the server identity and break every Clevis binding.
    std::string line = std::string("Stored record is not usable: ") +
                       tang_decode_status_name(decoded) +
                       ". Staying inactive. Change reset_token (with "
                       "initial_password) to start over.";
    logger_->error(line.c_str());
    return false;
  }

  KeyPair signing{};
  std::memcpy(signing.priv, stored.admin_private_key, sizeof(signing.priv));
  if (!tang::compute_ec_public_key(&rng_, signing.priv, signing.pub)) {
    logger_->error("Stored admin key is invalid; staying inactive");
    tang::secure_zero(&stored, sizeof(stored));
    tang::secure_zero(&signing, sizeof(signing));
    return false;
  }

  if (token_status == TangStorageStatus::kEmpty &&
      !storage_->write_reset_token(config.reset_token)) {
    logger_->warn("Could not record reset token (will retry next boot)");
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    signing_ = signing;
    record_ = stored.record;
    key_lifetime_ms_ = config.key_lifetime_ms;
    unattended_ = false;
    active_ = false;
    ready_ = true;
  }
  tang::secure_zero(&stored, sizeof(stored));
  tang::secure_zero(&signing, sizeof(signing));
  logger_->debug("Password mode: stored record loaded; waiting for activation.");
  return true;
}

bool TangServerCore::initialize_storage(const char *initial_password,
                                        uint32_t reset_token) {
  KeyPair admin{};
  KeyPair tang_key{};
  TangStoredState state{};
  bool ok = tang::generate_ec_keypair(&rng_, admin.pub, admin.priv) &&
            tang::generate_ec_keypair(&rng_, tang_key.pub, tang_key.priv);
  tang::TangRandomFunc rng_func = nullptr;
  void *rng_ctx = nullptr;
  if (ok) {
    ok = tang::get_rng_context(&rng_, &rng_func, &rng_ctx) == 0 &&
         rng_func(rng_ctx, state.record.iv, sizeof(state.record.iv)) == 0 &&
         rng_func(rng_ctx, state.record.salt, sizeof(state.record.salt)) == 0;
  }
  if (ok) {
    state.record.iterations = tang::kPasswordPbkdf2Iterations;
    std::memcpy(state.admin_private_key, admin.priv,
                sizeof(state.admin_private_key));
    ok = tang::encrypt_local_data_gcm(
        state.record.ciphertext, tang_key.priv, sizeof(tang_key.priv),
        initial_password, std::strlen(initial_password), state.record.salt,
        sizeof(state.record.salt), state.record.iterations, state.record.iv,
        sizeof(state.record.iv), state.record.tag, sizeof(state.record.tag));
  }
  if (ok) {
    uint8_t blob[kTangRecordEncodedSize];
    tang_encode_state(state, blob);
    ok = storage_->write_state(blob, sizeof(blob)) &&
         storage_->write_reset_token(reset_token);
    if (!ok) {
      logger_->error("Writing the new record to storage failed");
    }
  } else {
    logger_->error("Key generation or encryption failed during first setup");
  }

  if (ok) {
    std::lock_guard<std::mutex> lock(mutex_);
    signing_ = admin;
    record_ = state.record;
    unattended_ = false;
    active_ = false;
    ready_ = true;
  }
  tang::secure_zero(&admin, sizeof(admin));
  tang::secure_zero(&tang_key, sizeof(tang_key));
  tang::secure_zero(&state, sizeof(state));
  if (ok) {
    logger_->debug("Password mode: new identity created and stored.");
  }
  return ok;
}

bool TangServerCore::loop() {
  if (clock_ == nullptr) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (!active_ || unattended_) {
    return false;
  }
  if (clock_->millis() - activation_ms_ >= key_lifetime_ms_) {
    if (logger_ != nullptr) {
      logger_->debug("Key lifetime expired. Deactivating server automatically.");
    }
    deactivate_locked();
    return true;
  }
  return false;
}

TangResponse TangServerCore::handle_request(const TangRequest &raw_request) {
  // Normalize once, before routing, so every adapter gets the same behavior.
  TangRequest request = raw_request;
  request.path = normalize_tang_path(raw_request.path);

  bool unattended;
  bool ready;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    unattended = unattended_;
    ready = ready_;
  }

  if (!ready) {
    return fail(503, "Tang server not ready (see device log)");
  }

  if (request.path == "/adv" || request.path.rfind("/adv/", 0) == 0) {
    if (request.method != "GET") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_adv(request.path);
  }

  if (request.path == "/pub" || request.path == "/activate" ||
      request.path == "/deactivate") {
    if (unattended) {
      // Password-mode endpoints do not exist in unattended mode.
      return text_response(404, "Not found");
    }
    const bool is_get = request.path == "/pub";
    if (request.method != (is_get ? "GET" : "POST")) {
      return text_response(405, "Method Not Allowed");
    }
    if (is_get) {
      return handle_pub();
    }
    return request.path == "/activate" ? handle_activate(request)
                                       : handle_deactivate(request);
  }

  if (request.path == "/rec" || request.path.rfind("/rec/", 0) == 0) {
    if (request.method != "POST") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_recovery(request);
  }

  return text_response(404, "Not found");
}

bool TangServerCore::is_active() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return active_;
}

bool TangServerCore::is_ready() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return ready_;
}

bool TangServerCore::is_unattended() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return unattended_;
}

TangResponse TangServerCore::handle_adv(const std::string &path) {
  std::string thp;
  // `path` is normalized: "/adv" or "/adv/<thp>".
  if (path != "/adv") {
    thp = path.substr(5);
    if (!is_thumbprint_text(thp)) {
      return text_response(404, "Not found");
    }
  }

  AdvSigner signers[2];
  size_t signer_count = 0;
  uint8_t signing_pub[tang::kEcPublicKeySize];
  uint8_t exchange_pub[tang::kEcPublicKeySize];
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_) {
      return fail(403, "Server not active");
    }
    std::memcpy(signing_pub, signing_.pub, sizeof(signing_pub));
    std::memcpy(exchange_pub, exchange_.pub, sizeof(exchange_pub));
    std::memcpy(signers[0].pub, signing_.pub, sizeof(signers[0].pub));
    std::memcpy(signers[0].priv, signing_.priv, sizeof(signers[0].priv));
    signer_count = 1;

    // /adv/<thp>: like tangd, sign with the current key and, if <thp> names a
    // rotated (hidden) signing key, with that key as well. The payload still
    // lists only the current keys.
    if (!thp.empty() && !kid_matches(signing_.pub, thp)) {
      bool found = false;
      for (const KeyPair &old : old_signing_) {
        if (kid_matches(old.pub, thp)) {
          std::memcpy(signers[1].pub, old.pub, sizeof(signers[1].pub));
          std::memcpy(signers[1].priv, old.priv, sizeof(signers[1].priv));
          signer_count = 2;
          found = true;
          break;
        }
      }
      if (!found) {
        return fail(404, "Unknown signing key thumbprint");
      }
    }
  }

  if (logger_ != nullptr) {
    logger_->debug("Received request for /adv");
  }
  TangResponse response = signed_advertisement_response(
      &rng_, signers, signer_count, signing_pub, exchange_pub);
  tang::secure_zero(signers, sizeof(signers));
  return response;
}

TangResponse TangServerCore::handle_pub() {
  uint8_t pub[tang::kEcPublicKeySize];
  {
    std::lock_guard<std::mutex> lock(mutex_);
    std::memcpy(pub, signing_.pub, sizeof(pub));
  }
  if (logger_ != nullptr) {
    logger_->debug("Received request for /pub");
  }
  return public_key_response(pub, false, "ECDH-ES");
}

void TangServerCore::note_password_failure_locked() {
  if (failed_attempts_ < 31) {
    ++failed_attempts_;
  }
  uint64_t delay = 1000;
  for (uint32_t i = 1; i < failed_attempts_ && delay < kMaxBackoffMs; ++i) {
    delay *= 2;
  }
  if (delay > kMaxBackoffMs) {
    delay = kMaxBackoffMs;
  }
  next_attempt_ms_ = clock_->millis() + delay;
}

// Check `password` against the stored record. On success, writes the Tang
// exchange private key to `key_out`. Runs PBKDF2 without holding the mutex so
// that loop() and other requests are not blocked for the duration.
static bool unlock_record(const TangEncryptedKeyRecord &record,
                          const std::string &password,
                          uint8_t key_out[tang::kEcPrivateKeySize]) {
  return tang::decrypt_local_data_gcm(
      key_out, record.ciphertext, sizeof(record.ciphertext), password.c_str(),
      password.size(), record.salt, sizeof(record.salt), record.iterations,
      record.iv, sizeof(record.iv), record.tag, sizeof(record.tag));
}

TangResponse TangServerCore::handle_activate(const TangRequest &request) {
  TangEncryptedKeyRecord record;
  uint8_t admin_priv[tang::kEcPrivateKeySize];
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_) {
      return fail(400, "Already active");
    }
    if (clock_->millis() < next_attempt_ms_) {
      return fail(429, "Too many failed attempts; retry later");
    }
    record = record_;
    std::memcpy(admin_priv, signing_.priv, sizeof(admin_priv));
  }

  if (request.body.empty()) {
    tang::secure_zero(admin_priv, sizeof(admin_priv));
    return fail(400, "Bad Request: Missing body");
  }

  std::string password;
  int error_status = 400;
  const char *error_body = "Bad Request: Invalid JWE";
  const bool decrypted = decrypt_jwe_password(&rng_, admin_priv, request.body,
                                              &password, &error_status,
                                              &error_body);
  tang::secure_zero(admin_priv, sizeof(admin_priv));
  if (!decrypted) {
    return fail(error_status, error_body);
  }

  uint8_t key[tang::kEcPrivateKeySize];
  uint8_t pub[tang::kEcPublicKeySize];
  const bool ok = unlock_record(record, password, key) &&
                  tang::compute_ec_public_key(&rng_, key, pub);
  password.assign(password.size(), '\0');
  password.clear();

  if (!ok) {
    tang::secure_zero(key, sizeof(key));
    {
      std::lock_guard<std::mutex> lock(mutex_);
      note_password_failure_locked();
    }
    return fail(401, "Activation failed: invalid password for stored key");
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    std::memcpy(exchange_.priv, key, sizeof(exchange_.priv));
    std::memcpy(exchange_.pub, pub, sizeof(exchange_.pub));
    active_ = true;
    activation_ms_ = clock_->millis();
    failed_attempts_ = 0;
    next_attempt_ms_ = 0;
  }
  tang::secure_zero(key, sizeof(key));

  if (logger_ != nullptr) {
    logger_->debug("Server activated.");
  }
  return text_response(200, "Server activated successfully");
}

TangResponse TangServerCore::handle_deactivate(const TangRequest &request) {
  // The caller must prove the current password. Nothing is re-wrapped or
  // written: the stored record stays byte-for-byte unchanged.
  TangEncryptedKeyRecord record;
  uint8_t admin_priv[tang::kEcPrivateKeySize];
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_) {
      return fail(400, "Already inactive");
    }
    if (clock_->millis() < next_attempt_ms_) {
      return fail(429, "Too many failed attempts; retry later");
    }
    record = record_;
    std::memcpy(admin_priv, signing_.priv, sizeof(admin_priv));
  }

  if (request.body.empty()) {
    tang::secure_zero(admin_priv, sizeof(admin_priv));
    return fail(400, "Bad Request: Missing body");
  }

  std::string password;
  int error_status = 400;
  const char *error_body = "Bad Request: Invalid JWE";
  const bool decrypted = decrypt_jwe_password(&rng_, admin_priv, request.body,
                                              &password, &error_status,
                                              &error_body);
  tang::secure_zero(admin_priv, sizeof(admin_priv));
  if (!decrypted) {
    return fail(error_status, error_body);
  }

  uint8_t key[tang::kEcPrivateKeySize];
  const bool ok = unlock_record(record, password, key);
  tang::secure_zero(key, sizeof(key));
  password.assign(password.size(), '\0');
  password.clear();

  std::lock_guard<std::mutex> lock(mutex_);
  if (!ok) {
    note_password_failure_locked();
    return fail(401, "Deactivation failed: invalid password for stored key");
  }
  failed_attempts_ = 0;
  next_attempt_ms_ = 0;
  deactivate_locked();
  if (logger_ != nullptr) {
    logger_->debug("Server deactivated on request.");
  }
  return text_response(200, "Server deactivated");
}

TangResponse TangServerCore::handle_recovery(const TangRequest &request) {
  // `request.path` is normalized: "/rec" or "/rec/<kid>".
  if (request.path == "/rec") {
    return fail_json(400, "missing_kid", "Recovery requires /rec/{kid}");
  }

  const std::string kid = request.path.substr(5);
  if (!is_thumbprint_text(kid)) {
    return fail_json(400, "invalid_kid", "Recovery key id is invalid");
  }

  // Find the exchange key: the current one (when active) or a rotated one.
  // Accept the SHA-256 (Clevis 17+) and SHA-1 (older) thumbprint.
  uint8_t key[tang::kEcPrivateKeySize];
  bool found = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_) {
      return fail(403, "Server not active");
    }
    if (kid_matches(exchange_.pub, kid)) {
      std::memcpy(key, exchange_.priv, sizeof(key));
      found = true;
    }
    for (size_t i = 0; !found && i < old_exchange_.size(); ++i) {
      if (kid_matches(old_exchange_[i].pub, kid)) {
        std::memcpy(key, old_exchange_[i].priv, sizeof(key));
        found = true;
      }
    }
  }
  if (!found) {
    return fail_json(404, "unknown_kid", "Recovery key id is not active");
  }

  if (request.body.empty()) {
    tang::secure_zero(key, sizeof(key));
    return fail_json(400, "missing_body", "Recovery request body is required");
  }

  ParsedRecoveryJwk parsed;
  const char *parse_error = "Recovery request is invalid";
  if (!parse_recovery_jwk(request.body, &parsed, &parse_error)) {
    tang::secure_zero(key, sizeof(key));
    return fail_json(400, "invalid_recovery_request", parse_error);
  }

  TangResponse response = recovery_key_response(&rng_, key, parsed.public_key);
  tang::secure_zero(key, sizeof(key));
  tang::secure_zero(&parsed, sizeof(parsed));
  if (response.status != 200 && logger_ != nullptr) {
    logger_->warn("Recovery request rejected: invalid client key");
  }
  return response;
}

void TangServerCore::deactivate_locked() {
  tang::secure_zero(&exchange_, sizeof(exchange_));
  active_ = false;
  activation_ms_ = 0;
}
