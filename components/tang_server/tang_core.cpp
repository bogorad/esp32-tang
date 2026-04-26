#include "tang_core.h"

#include <cstring>
#include <string>

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

bool is_known_tang_path(const std::string &path) {
  return path == "/adv" || path.rfind("/adv/", 0) == 0 ||
         path == "/pub" || path == "/activate" || path == "/deactivate" ||
         path == "/rec" ||
         path.rfind("/rec/", 0) == 0;
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
  std::string protected_header;
};

bool parse_jwe_password(const std::string &body, ParsedJwePassword *out) {
  if (out == nullptr) {
    return false;
  }

  std::string x;
  std::string y;
  std::string iv;
  std::string tag;
  std::string ciphertext;
  if (!find_json_string(body, "protected", &out->protected_header) ||
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
  uint8_t shared_secret[tang::kEcPrivateKeySize]{0};
  uint8_t cek[tang::kAes128KeySize]{0};
  uint8_t plaintext[sizeof(parsed.ciphertext) + 1]{0};
  bool ok = false;

  if (!parse_jwe_password(body, &parsed)) {
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
          reinterpret_cast<const uint8_t *>(parsed.protected_header.data()),
          parsed.protected_header.size())) {
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
                    std::string *kid) {
  char encoded[48];
  size_t encoded_len = 0;
  if (!tang::compute_ec_jwk_thumbprint(public_key, encoded, sizeof(encoded),
                                       &encoded_len)) {
    return false;
  }

  kid->assign(encoded, encoded_len);
  return true;
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

  if (include_kid && !compute_key_id(public_key, &kid)) {
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

TangResponse signed_advertisement_response(
    tang::TangRngContext *rng,
    const uint8_t signing_public_key[tang::kEcPublicKeySize],
    const uint8_t signing_private_key[tang::kEcPrivateKeySize],
    const uint8_t exchange_public_key[tang::kEcPublicKeySize]) {
  std::string signing_jwk;
  std::string exchange_jwk;
  std::string signing_kid;
  if (!public_jwk(signing_public_key, "ES256", "[\"verify\"]", true,
                  &signing_jwk, &signing_kid) ||
      !public_jwk(exchange_public_key, "ECMR", "[\"deriveKey\"]", true,
                  &exchange_jwk, nullptr)) {
    return text_response(500, "Failed to encode advertisement keys");
  }

  const std::string payload = "{\"keys\":[" + signing_jwk + "," +
                              exchange_jwk + "]}";
  const std::string protected_header =
      "{\"alg\":\"ES256\",\"cty\":\"jwk-set+json\",\"kid\":\"" + signing_kid +
      "\"}";

  std::string payload_b64;
  std::string protected_b64;
  if (!base64_url_encode_string(payload, &payload_b64) ||
      !base64_url_encode_string(protected_header, &protected_b64)) {
    return text_response(500, "Failed to encode advertisement JWS");
  }

  const std::string signing_input = protected_b64 + "." + payload_b64;
  uint8_t signature[tang::kEcPublicKeySize];
  if (!tang::sign_es256(
          rng, signing_private_key,
          reinterpret_cast<const uint8_t *>(signing_input.data()),
          signing_input.size(), signature)) {
    tang::secure_zero(signature, sizeof(signature));
    return text_response(500, "Failed to sign advertisement JWS");
  }

  std::string signature_b64;
  bool ok = base64_url_encode_string(signature, sizeof(signature),
                                     &signature_b64);
  tang::secure_zero(signature, sizeof(signature));
  if (!ok) {
    return text_response(500, "Failed to encode advertisement signature");
  }

  return json_response("{\"payload\":\"" + payload_b64 +
                       "\",\"protected\":\"" + protected_b64 +
                       "\",\"signature\":\"" + signature_b64 + "\"}");
}

}  // namespace

TangServerCore::TangServerCore(TangStorage *storage, TangClock *clock,
                               TangLogger *logger)
    : storage_(storage),
      clock_(clock),
      logger_(logger),
      initialized_(false),
      active_(false),
      activation_timestamp_(0),
      tang_private_key_{0},
      tang_public_key_{0},
      admin_private_key_{0},
      admin_public_key_{0} {}

bool TangServerCore::setup(const char *initial_password) {
  if (storage_ == nullptr || clock_ == nullptr || initial_password == nullptr) {
    return false;
  }

  if (storage_->is_initialized()) {
    initialized_ = load_admin_key();
    return initialized_;
  }

  initialized_ = initialize_storage(initial_password);
  return initialized_;
}

void TangServerCore::loop() {
  if (!active_ || clock_ == nullptr) {
    return;
  }

  if (clock_->millis() - activation_timestamp_ > kDefaultKeyLifetimeMs) {
    if (logger_ != nullptr) {
      logger_->debug("Key lifetime expired. Deactivating server automatically.");
    }
    deactivate_server();
  }
}

TangResponse TangServerCore::handle_request(const TangRequest &request) {
  if (request.path == "/adv" || request.path.rfind("/adv/", 0) == 0) {
    if (request.method != "GET") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_adv();
  }

  if (request.path == "/pub") {
    if (request.method != "GET") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_pub();
  }

  if (request.path == "/activate") {
    if (request.method != "POST") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_activate(request);
  }

  if (request.path == "/deactivate") {
    if (request.method != "GET" && request.method != "POST") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_deactivate(request);
  }

  if (request.path == "/rec" || request.path.rfind("/rec/", 0) == 0) {
    if (request.method != "POST") {
      return text_response(405, "Method Not Allowed");
    }
    return handle_recovery(request);
  }

  if (is_known_tang_path(request.path)) {
    return text_response(405, "Method Not Allowed");
  }

  return text_response(404, "Not found");
}

bool TangServerCore::is_active() const { return active_; }

TangResponse TangServerCore::handle_adv() {
  if (!active_) {
    return text_response(403, "Server not active");
  }

  if (logger_ != nullptr) {
    logger_->debug("Received request for /adv");
  }
  return signed_advertisement_response(&rng_, admin_public_key_,
                                       admin_private_key_, tang_public_key_);
}

TangResponse TangServerCore::handle_pub() {
  if (!initialized_) {
    return text_response(500, "Server not initialized");
  }

  if (logger_ != nullptr) {
    logger_->debug("Received request for /pub");
  }
  return public_key_response(admin_public_key_, false, "ECDH-ES");
}

TangResponse TangServerCore::handle_activate(const TangRequest &request) {
  if (active_) {
    return text_response(400, "Already active");
  }

  if (request.body.empty()) {
    return text_response(400, "Bad Request: Missing body");
  }

  std::string password;
  int error_status = 400;
  const char *error_body = "Bad Request: Invalid JWE";
  if (!decrypt_jwe_password(&rng_, admin_private_key_, request.body, &password,
                            &error_status, &error_body)) {
    return text_response(error_status, error_body);
  }

  TangEncryptedKeyRecord record = {};
  uint8_t decrypted_key[tang::kEcPrivateKeySize]{0};
  const bool ok =
      storage_->load_tang_key_record(&record) &&
      tang::decrypt_local_data_gcm(
          decrypted_key, record.ciphertext, sizeof(record.ciphertext),
          password.c_str(), password.size(), record.iv, sizeof(record.iv),
          record.tag, sizeof(record.tag)) &&
      tang::compute_ec_public_key(&rng_, decrypted_key, tang_public_key_);
  if (ok) {
    std::memcpy(tang_private_key_, decrypted_key, sizeof(tang_private_key_));
    active_ = true;
    activation_timestamp_ = clock_->millis();
  }

  tang::secure_zero(decrypted_key, sizeof(decrypted_key));
  password.assign(password.size(), '\0');
  if (!ok) {
    return text_response(401,
                         "Activation failed: invalid password for stored key");
  }

  if (logger_ != nullptr) {
    logger_->debug("Server activated.");
  }
  return text_response(200, "Server activated successfully");
}

TangResponse TangServerCore::handle_deactivate(const TangRequest &request) {
  if (request.method == "GET") {
    deactivate_server();
    return text_response(200, "Server deactivated");
  }

  if (!active_) {
    return text_response(400, "Already inactive");
  }

  if (request.body.empty()) {
    return text_response(400, "Bad Request: Missing body");
  }

  std::string password;
  int error_status = 400;
  const char *error_body = "Bad Request: Invalid JWE";
  if (!decrypt_jwe_password(&rng_, admin_private_key_, request.body, &password,
                            &error_status, &error_body)) {
    return text_response(error_status, error_body);
  }

  TangEncryptedKeyRecord record = {};
  record.version = 1;
  uint8_t key_to_save[tang::kEcPrivateKeySize]{0};
  std::memcpy(key_to_save, tang_private_key_, sizeof(key_to_save));
  bool ok = tang::generate_random_gcm_iv(&rng_, record.iv);
  if (ok) {
    ok = tang::encrypt_local_data_gcm(
        record.ciphertext, key_to_save, sizeof(key_to_save), password.c_str(),
        password.size(), record.iv, sizeof(record.iv), record.tag,
        sizeof(record.tag));
  }
  if (ok) {
    ok = storage_->save_tang_key_record(record);
  }

  tang::secure_zero(key_to_save, sizeof(key_to_save));
  password.assign(password.size(), '\0');
  if (!ok) {
    return text_response(500, "Failed to encrypt Tang key");
  }

  deactivate_server();
  return text_response(200, "Key saved and server deactivated");
}

TangResponse TangServerCore::handle_recovery(const TangRequest &request) {
  if (!active_) {
    return text_response(403, "Server not active");
  }

  constexpr const char *kRecoveryPrefix = "/rec/";
  if (request.path == "/rec") {
    return json_response(400,
                         "{\"error\":\"missing_kid\","
                         "\"message\":\"Recovery requires /rec/{kid}\"}");
  }

  const std::string kid = request.path.substr(std::strlen(kRecoveryPrefix));
  if (kid.empty() || kid.find('/') != std::string::npos) {
    return json_response(400,
                         "{\"error\":\"invalid_kid\","
                         "\"message\":\"Recovery key id is invalid\"}");
  }

  std::string active_kid;
  if (!compute_key_id(tang_public_key_, &active_kid)) {
    return json_response(500,
                         "{\"error\":\"kid_unavailable\","
                         "\"message\":\"Failed to compute active key id\"}");
  }

  if (kid != active_kid) {
    return json_response(404,
                         "{\"error\":\"unknown_kid\","
                         "\"message\":\"Recovery key id is not active\"}");
  }

  if (request.body.empty()) {
    return json_response(400,
                         "{\"error\":\"missing_body\","
                         "\"message\":\"Recovery request body is required\"}");
  }

  ParsedRecoveryJwk parsed;
  const char *parse_error = "Recovery request is invalid";
  if (!parse_recovery_jwk(request.body, &parsed, &parse_error)) {
    return json_response(400,
                         "{\"error\":\"invalid_recovery_request\","
                         "\"message\":\"" +
                             std::string(parse_error) + "\"}");
  }

  TangResponse response =
      recovery_key_response(&rng_, tang_private_key_, parsed.public_key);
  tang::secure_zero(&parsed, sizeof(parsed));
  return response;
}

void TangServerCore::deactivate_server() {
  tang::secure_zero(tang_private_key_, sizeof(tang_private_key_));
  tang::secure_zero(tang_public_key_, sizeof(tang_public_key_));
  active_ = false;
  activation_timestamp_ = 0;
}

bool TangServerCore::load_admin_key() {
  if (!storage_->load_admin_private_key(admin_private_key_)) {
    return false;
  }

  return tang::compute_ec_public_key(&rng_, admin_private_key_,
                                     admin_public_key_);
}

bool TangServerCore::initialize_storage(const char *initial_password) {
  uint8_t generated_tang_private_key[tang::kEcPrivateKeySize] = {0};
  uint8_t generated_tang_public_key[tang::kEcPublicKeySize] = {0};
  TangEncryptedKeyRecord record = {};
  record.version = 1;

  tang::TangRandomFunc rng_func = nullptr;
  void *rng_ctx = nullptr;
  bool ok = tang::generate_ec_keypair(&rng_, admin_public_key_,
                                      admin_private_key_);
  if (ok) {
    ok = tang::generate_ec_keypair(&rng_, generated_tang_public_key,
                                   generated_tang_private_key);
  }
  if (ok) {
    ok = tang::get_rng_context(&rng_, &rng_func, &rng_ctx) == 0 &&
         rng_func(rng_ctx, record.iv, sizeof(record.iv)) == 0;
  }
  if (ok) {
    ok = tang::encrypt_local_data_gcm(
        record.ciphertext, generated_tang_private_key,
        sizeof(generated_tang_private_key), initial_password,
        std::strlen(initial_password), record.iv, sizeof(record.iv), record.tag,
        sizeof(record.tag));
  }
  if (ok) {
    ok = storage_->save_admin_private_key(admin_private_key_) &&
         storage_->save_tang_key_record(record) && storage_->mark_initialized();
  }

  tang::secure_zero(generated_tang_private_key,
                    sizeof(generated_tang_private_key));
  tang::secure_zero(generated_tang_public_key,
                    sizeof(generated_tang_public_key));
  if (!ok) {
    tang::secure_zero(admin_private_key_, sizeof(admin_private_key_));
    tang::secure_zero(admin_public_key_, sizeof(admin_public_key_));
  }
  return ok;
}
