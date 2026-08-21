#include "tang_http_handler.h"

#ifdef USE_ESP32
#include <esp_http_server.h>
#endif

#include <cstring>
#include <string>
#include <type_traits>

#include "tang_server.h"
#include "tang_core.h"
#include "esphome/core/hal.h"
#include "esphome/core/preferences.h"

namespace esphome {
namespace tang_server {

namespace {

constexpr size_t kMaxTangBodySize = 4096;
constexpr uint32_t kTangStorageMagic = 0x54414E47;
constexpr uint8_t kTangStorageVersion = 1;
constexpr uint32_t kTangPreferenceKey = 0x54414E31;

// Keep the ESPHome adapter consistent with the standalone EEPROM backend: the
// admin key and encrypted Tang record must survive an OTA update or power loss.
// ESPHome preferences do not provide confidentiality by themselves; deployments
// that need resistance to flash extraction must also enable platform storage
// encryption.
struct PersistentTangState {
  uint32_t magic{kTangStorageMagic};
  uint8_t format_version{kTangStorageVersion};
  uint8_t initialized{0};
  uint8_t record_saved{0};
  uint8_t reserved{0};
  uint8_t admin_private_key[32]{0};
  TangEncryptedKeyRecord record{};
};

static_assert(std::is_trivially_copyable<PersistentTangState>::value,
              "Tang preference state must be trivially copyable");

class PreferencesTangStorage : public TangStorage {
 public:
  bool is_initialized() override {
    return ensure_loaded_() && state_.initialized == 1;
  }

  bool load_admin_private_key(uint8_t out[32]) override {
    if (!ensure_loaded_() || state_.initialized != 1 || out == nullptr) {
      return false;
    }
    std::memcpy(out, state_.admin_private_key, sizeof(state_.admin_private_key));
    return true;
  }

  bool save_admin_private_key(const uint8_t key[32]) override {
    if (!ensure_loaded_() || key == nullptr) {
      return false;
    }
    std::memcpy(state_.admin_private_key, key, sizeof(state_.admin_private_key));
    return persist_();
  }

  bool load_tang_key_record(TangEncryptedKeyRecord *out) override {
    if (!ensure_loaded_() || state_.initialized != 1 ||
        state_.record_saved != 1 || out == nullptr) {
      return false;
    }
    *out = state_.record;
    return true;
  }

  bool save_tang_key_record(const TangEncryptedKeyRecord &record) override {
    if (!ensure_loaded_()) {
      return false;
    }
    state_.record = record;
    state_.record_saved = 1;
    return persist_();
  }

  bool mark_initialized() override {
    if (!ensure_loaded_() || state_.record_saved != 1) {
      return false;
    }
    state_.initialized = 1;
    return persist_();
  }

  bool wipe() override {
    if (!ensure_loaded_()) {
      return false;
    }
    state_ = PersistentTangState{};
    return persist_();
  }

 private:
  bool ensure_loaded_() {
    if (loaded_) {
      return available_;
    }
    loaded_ = true;
    if (global_preferences == nullptr) {
      return false;
    }

    preference_ = global_preferences->make_preference<PersistentTangState>(
        kTangPreferenceKey, true);
    available_ = true;

    PersistentTangState saved{};
    // Ignore incomplete or incompatible records. A fresh initialization can
    // then replace them when initial_password is supplied.
    if (preference_.load(&saved) && saved.magic == kTangStorageMagic &&
        saved.format_version == kTangStorageVersion &&
        saved.initialized <= 1 && saved.record_saved <= 1 &&
        (!saved.record_saved || saved.record.version == 1)) {
      state_ = saved;
    }
    return true;
  }

  bool persist_() {
    return available_ && preference_.save(&state_) &&
           global_preferences->sync();
  }

  bool loaded_{false};
  bool available_{false};
  PersistentTangState state_{};
  ESPPreferenceObject preference_{};
};

class EspHomeTangClock : public TangClock {
 public:
  uint32_t millis() const override { return esphome::millis(); }
};

class NoopTangLogger : public TangLogger {
 public:
  void debug(const char *message) override { (void)message; }
  void warn(const char *message) override { (void)message; }
};

template<typename T> std::string to_std_string(const T &value) { return std::string(value.c_str()); }

std::string request_path(AsyncWebServerRequest *request) {
#ifdef USE_ESP32
  char url_buf[AsyncWebServerRequest::URL_BUF_SIZE];
  const auto url = request->url_to(url_buf);
#else
  const auto &url = request->url();
#endif
  return to_std_string(url);
}

bool is_tang_path(const std::string &path) {
  return path == "/pub" || path.rfind("/pub/", 0) == 0 || path == "/adv" ||
         path.rfind("/adv/", 0) == 0 || path == "/activate" ||
         path.rfind("/activate/", 0) == 0 || path == "/deactivate" ||
         path.rfind("/deactivate/", 0) == 0 || path == "/rec" ||
         path.rfind("/rec/", 0) == 0;
}

bool is_buffered_body_path(const std::string &path) {
  return path == "/activate" || path == "/deactivate" || path == "/rec" ||
         path.rfind("/rec/", 0) == 0;
}

bool is_success_status(int status) { return status >= 200 && status < 300; }

const char *method_to_string(AsyncWebServerRequest *request) {
  const auto method = request->method();
  if (method == HTTP_GET) {
    return "GET";
  }
  if (method == HTTP_POST) {
    return "POST";
  }
  if (method == HTTP_PUT) {
    return "PUT";
  }
  if (method == HTTP_PATCH) {
    return "PATCH";
  }
  if (method == HTTP_DELETE) {
    return "DELETE";
  }
  if (method == HTTP_OPTIONS) {
    return "OPTIONS";
  }
  return "";
}

bool is_post_request(AsyncWebServerRequest *request) { return request->method() == HTTP_POST; }

#ifdef USE_ESP32
std::string http_status(int code) {
  switch (code) {
    case 200:
      return "200 OK";
    case 400:
      return "400 Bad Request";
    case 403:
      return "403 Forbidden";
    case 404:
      return "404 Not Found";
    case 405:
      return "405 Method Not Allowed";
    case 409:
      return "409 Conflict";
    case 413:
      return "413 Payload Too Large";
    case 500:
      return "500 Internal Server Error";
    case 501:
      return "501 Not Implemented";
    default:
      return std::to_string(code);
  }
}
#endif

void send_body(AsyncWebServerRequest *request, int status, const char *content_type, const char *body) {
#ifdef USE_ESP32
  const std::string status_text = http_status(status);
  httpd_resp_set_status(*request, status_text.c_str());
  httpd_resp_set_type(*request, content_type);
  httpd_resp_send(*request, body, HTTPD_RESP_USE_STRLEN);
#else
  request->send(status, content_type, body);
#endif
}

void send_text(AsyncWebServerRequest *request, int status, const char *body) {
  send_body(request, status, "text/plain", body);
}

void send_response(AsyncWebServerRequest *request, const TangResponse &response) {
  send_body(request, response.status, response.content_type.c_str(), response.body.c_str());
}

}  // namespace

struct TangHttpHandler::CoreContext {
  CoreContext(const std::string &initial_password, uint32_t key_lifetime,
              bool reset_storage)
      : core(&storage, &clock, &logger),
        ready(false) {
    core.set_key_lifetime(key_lifetime);
    if (reset_storage && !storage.wipe()) {
      return;
    }
    ready = core.setup(initial_password.empty() ? nullptr
                                                 : initial_password.c_str());
  }

  PreferencesTangStorage storage;
  EspHomeTangClock clock;
  NoopTangLogger logger;
  TangServerCore core;
  bool ready;
};

TangHttpHandler::TangHttpHandler(TangServerComponent *parent)
    : parent_(parent),
      core_context_(new CoreContext(
          parent == nullptr ? "" : parent->initial_password(),
          parent == nullptr ? TangServerCore::kDefaultKeyLifetimeMs
                            : parent->key_lifetime(),
          parent != nullptr && parent->reset_storage())) {}

TangHttpHandler::~TangHttpHandler() = default;

void TangHttpHandler::loop() {
  if (core_context_ == nullptr || !core_context_->ready) {
    return;
  }
  const bool was_active = core_context_->core.is_active();
  core_context_->core.loop();
  if (was_active && !core_context_->core.is_active() && parent_ != nullptr) {
    parent_->fire_deactivate();
  }
}

bool TangHttpHandler::canHandle(AsyncWebServerRequest *request) const {
  return is_tang_path(request_path(request));
}

void TangHttpHandler::handleRequest(AsyncWebServerRequest *request) {
  if (core_context_ == nullptr || !core_context_->ready) {
    send_text(request, 500, "Tang server core unavailable");
    return;
  }

  TangRequest tang_request;
  tang_request.method = method_to_string(request);
  tang_request.path = request_path(request);
  if (is_post_request(request) && is_buffered_body_path(tang_request.path)) {
    if (request->contentLength() == 0) {
      tang_request.body.clear();
    } else {
      auto buffer_it = body_buffers_.find(request);
      if (request->contentLength() > kMaxTangBodySize ||
          (buffer_it != body_buffers_.end() && buffer_it->second.too_large)) {
        body_buffers_.erase(request);
        send_text(request, 413, "Payload Too Large");
        return;
      }
      if (buffer_it == body_buffers_.end() || buffer_it->second.malformed ||
          !buffer_it->second.complete ||
          buffer_it->second.body.size() != request->contentLength()) {
        body_buffers_.erase(request);
        send_text(request, 400, "Bad Request: Malformed body");
        return;
      }
      tang_request.body.swap(buffer_it->second.body);
      body_buffers_.erase(buffer_it);
    }
  } else if (request->contentLength() > 0) {
    tang_request.body = "<streamed body present>";
  }

  const TangResponse response = core_context_->core.handle_request(tang_request);
  parent_->fire_request(tang_request.path, tang_request.method, response.status);
  if (tang_request.path == "/activate") {
    parent_->fire_activate(is_success_status(response.status));
  } else if (tang_request.path == "/deactivate" && is_success_status(response.status)) {
    parent_->fire_deactivate();
  } else if (tang_request.path == "/rec" || tang_request.path.rfind("/rec/", 0) == 0) {
    parent_->fire_recovery(is_success_status(response.status));
  }
  send_response(request, response);
}

void TangHttpHandler::handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index,
                                 size_t total) {
  const std::string path = request_path(request);
  if (!is_post_request(request) || !is_buffered_body_path(path)) {
    return;
  }

  // ESPHome's ESP-IDF server consumes the socket before handleRequest() and
  // delivers each chunk here. Keep request-local state until handleRequest()
  // validates and erases it; attempting a second socket read loses the body.
  auto inserted = body_buffers_.try_emplace(request);
  BodyBuffer &buffer = inserted.first->second;
  if (inserted.second) {
    buffer.expected_size = total;
  }
  if (total > kMaxTangBodySize || index + len > kMaxTangBodySize) {
    buffer.too_large = true;
    buffer.body.clear();
    return;
  }
  if ((data == nullptr && len > 0) || index != buffer.body.size() ||
      index + len > total || buffer.expected_size != total) {
    buffer.malformed = true;
    buffer.body.clear();
    return;
  }

  buffer.body.append(reinterpret_cast<const char *>(data), len);
  buffer.complete = index + len == total;
}

bool TangHttpHandler::isRequestHandlerTrivial() const { return false; }

}  // namespace tang_server
}  // namespace esphome
