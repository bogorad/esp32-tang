#include "tang_http_handler.h"

#ifdef USE_ESP32
#include <esp_http_server.h>
#include <esp_timer.h>
#endif

#include <cstring>
#include <string>

#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "esphome/core/preferences.h"
#include "tang_core.h"
#include "tang_server.h"

namespace esphome {
namespace tang_server {

static const char *const TAG = "tang_server";

namespace {

// Preference keys are new on purpose: records from other firmware versions are
// never read through them.
constexpr uint32_t kStatePreferenceKey = 0x54414E32;  // "TAN2"
constexpr uint32_t kTokenPreferenceKey = 0x54414E33;  // "TAN3"

struct StatePreference {
  uint16_t length;  // 0 = empty
  uint8_t data[kTangRecordEncodedSize];
};

struct TokenPreference {
  uint32_t present;  // 1 = token valid
  uint32_t token;
};

// Persistent storage for password mode. Created lazily: unattended mode never
// touches preferences. ESPHome preferences are not encrypted; enable flash
// encryption if flash extraction is in your threat model.
class PreferencesTangStorage : public TangStorage {
 public:
  TangStorageStatus read_state(uint8_t *buf, size_t cap, size_t *len) override {
    if (!ensure_()) {
      return TangStorageStatus::kError;
    }
    StatePreference slot{};
    if (!state_pref_.load(&slot) || slot.length == 0) {
      return TangStorageStatus::kEmpty;  // missing or erased
    }
    if (slot.length > sizeof(slot.data) || slot.length > cap) {
      ESP_LOGE(TAG, "Stored state length %u is not plausible", slot.length);
      return TangStorageStatus::kError;
    }
    std::memcpy(buf, slot.data, slot.length);
    *len = slot.length;
    return TangStorageStatus::kOk;
  }

  bool write_state(const uint8_t *buf, size_t len) override {
    if (!ensure_() || len == 0 || len > sizeof(StatePreference::data)) {
      return false;
    }
    StatePreference slot{};
    slot.length = static_cast<uint16_t>(len);
    std::memcpy(slot.data, buf, len);
    return state_pref_.save(&slot) && global_preferences->sync();
  }

  TangStorageStatus read_reset_token(uint32_t *token) override {
    if (!ensure_()) {
      return TangStorageStatus::kError;
    }
    TokenPreference slot{};
    if (!token_pref_.load(&slot) || slot.present != 1) {
      return TangStorageStatus::kEmpty;
    }
    *token = slot.token;
    return TangStorageStatus::kOk;
  }

  bool write_reset_token(uint32_t token) override {
    if (!ensure_()) {
      return false;
    }
    TokenPreference slot{1, token};
    return token_pref_.save(&slot) && global_preferences->sync();
  }

  bool wipe() override {
    if (!ensure_()) {
      return false;
    }
    StatePreference empty_state{};
    TokenPreference empty_token{};
    return state_pref_.save(&empty_state) && token_pref_.save(&empty_token) && global_preferences->sync();
  }

 private:
  bool ensure_() {
    if (ready_) {
      return true;
    }
    if (global_preferences == nullptr) {
      ESP_LOGE(TAG, "ESPHome preferences are not available");
      return false;
    }
    state_pref_ = global_preferences->make_preference<StatePreference>(kStatePreferenceKey, true);
    token_pref_ = global_preferences->make_preference<TokenPreference>(kTokenPreferenceKey, true);
    ready_ = true;
    return true;
  }

  bool ready_{false};
  ESPPreferenceObject state_pref_;
  ESPPreferenceObject token_pref_;
};

// Monotonic, 64-bit milliseconds since boot. A 32-bit counter would wrap
// after 49.7 days and break key expiry.
class EspHomeTangClock : public TangClock {
 public:
  uint64_t millis() const override {
#ifdef USE_ESP32
    return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
#else
    // Extend the 32-bit counter. loop() keeps this called far more often than
    // every 49 days.
    std::lock_guard<std::mutex> lock(mutex_);
    const uint32_t now = esphome::millis();
    if (now < last_) {
      ++wraps_;
    }
    last_ = now;
    return (static_cast<uint64_t>(wraps_) << 32) | now;
#endif
  }

 private:
#ifndef USE_ESP32
  mutable std::mutex mutex_;
  mutable uint32_t last_{0};
  mutable uint32_t wraps_{0};
#endif
};

class EspHomeTangLogger : public TangLogger {
 public:
  void debug(const char *message) override { ESP_LOGD(TAG, "%s", message); }
  void warn(const char *message) override { ESP_LOGW(TAG, "%s", message); }
  void error(const char *message) override { ESP_LOGE(TAG, "%s", message); }
};

template<typename T> std::string to_std_string(const T &value) { return std::string(value.c_str()); }

// Used where url()/url_to() yields a plain C string; unused on some targets.
[[maybe_unused]] std::string to_std_string(const char *value) { return value == nullptr ? "" : std::string(value); }

std::string request_path(AsyncWebServerRequest *request) {
#ifdef USE_ESP32
  char url_buf[AsyncWebServerRequest::URL_BUF_SIZE];
  const auto url = request->url_to(url_buf);
#else
  const auto &url = request->url();
#endif
  return normalize_tang_path(to_std_string(url));
}

bool is_tang_path(const std::string &path) {
  return path == "/pub" || path.rfind("/pub/", 0) == 0 || path == "/adv" || path.rfind("/adv/", 0) == 0 ||
         path == "/activate" || path.rfind("/activate/", 0) == 0 || path == "/deactivate" ||
         path.rfind("/deactivate/", 0) == 0 || path == "/rec" || path.rfind("/rec/", 0) == 0;
}

bool is_buffered_body_path(const std::string &path) {
  return path == "/activate" || path == "/deactivate" || path == "/rec" || path.rfind("/rec/", 0) == 0;
}

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
    case 401:
      return "401 Unauthorized";
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
    case 429:
      return "429 Too Many Requests";
    case 500:
      return "500 Internal Server Error";
    case 501:
      return "501 Not Implemented";
    case 503:
      return "503 Service Unavailable";
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
  ESP_LOGW(TAG, "Rejecting request (%d): %s", status, body);
  send_body(request, status, "text/plain", body);
}

void send_response(AsyncWebServerRequest *request, const TangResponse &response) {
  send_body(request, response.status, response.content_type.c_str(), response.body.c_str());
}

#ifdef USE_ESP32
// Fallback for ESPHome versions that do not deliver request bodies through
// handleBody(): read the body from the socket. Only used when handleBody()
// never ran for this request, so the socket has not been consumed.
// Newer ESPHome (checked: 2026.10.2) calls handleBody() for every content type
// except application/x-www-form-urlencoded and multipart, and consumes the
// body itself for those. For form-urlencoded the recv below returns 0, so the
// request fails fast with the hint above instead of blocking.
bool read_body_from_socket(AsyncWebServerRequest *request, std::string *body) {
  const size_t total = request->contentLength();
  body->clear();
  body->reserve(total);
  char chunk[256];
  size_t remaining = total;
  while (remaining > 0) {
    const size_t want = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
    const int received = httpd_req_recv(*request, chunk, want);
    if (received <= 0) {
      body->clear();
      return false;
    }
    body->append(chunk, static_cast<size_t>(received));
    remaining -= static_cast<size_t>(received);
  }
  return true;
}
#endif

}  // namespace

struct TangHttpHandler::CoreContext {
  explicit CoreContext(TangServerComponent *parent) : core(&storage, &clock, &logger) {
    TangConfig config;
    config.unattended = parent->unattended();
    if (config.unattended) {
      config.seed_hex = parent->seed().c_str();
      config.old_seeds_hex = parent->old_seeds();
    } else {
      config.initial_password = parent->initial_password().empty() ? nullptr : parent->initial_password().c_str();
      config.reset_token = parent->reset_token();
      config.key_lifetime_ms = parent->key_lifetime_ms();
    }
    ready = core.setup(config);
  }

  PreferencesTangStorage storage;
  EspHomeTangClock clock;
  EspHomeTangLogger logger;
  TangServerCore core;
  bool ready{false};
};

TangHttpHandler::TangHttpHandler(TangServerComponent *parent)
    : parent_(parent), core_context_(new CoreContext(parent)) {}

TangHttpHandler::~TangHttpHandler() = default;

bool TangHttpHandler::ready() const { return core_context_ != nullptr && core_context_->ready; }

bool TangHttpHandler::active() const { return ready() && core_context_->core.is_active(); }

bool TangHttpHandler::signing_thumbprint(std::string *out) const {
  return ready() && core_context_->core.signing_thumbprint(out);
}

bool TangHttpHandler::loop() { return ready() && core_context_->core.loop(); }

bool TangHttpHandler::canHandle(AsyncWebServerRequest *request) const { return is_tang_path(request_path(request)); }

void TangHttpHandler::handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index,
                                 size_t total) {
  if (!is_post_request(request) || !is_buffered_body_path(request_path(request))) {
    return;
  }
  std::lock_guard<std::mutex> lock(this->body_mutex_);
  // Index 0 restarts the buffer, so an aborted upload cannot leak into the
  // next request that happens to reuse this request object's address.
  this->bodies_[request].on_chunk(data, len, index, total);
}

void TangHttpHandler::handleRequest(AsyncWebServerRequest *request) {
  if (core_context_ == nullptr) {
    send_text(request, 500, "Tang server core unavailable");
    return;
  }

  TangRequest tang_request;
  tang_request.method = method_to_string(request);
  tang_request.path = request_path(request);

  if (is_post_request(request) && is_buffered_body_path(tang_request.path)) {
    const size_t content_length = request->contentLength();
    bool have_buffer = false;
    TangBodyBuffer::Status status = TangBodyBuffer::Status::kOk;
    {
      std::lock_guard<std::mutex> lock(this->body_mutex_);
      auto it = this->bodies_.find(request);
      if (it != this->bodies_.end()) {
        have_buffer = true;
        if (content_length > 0) {
          status = it->second.status(content_length);
          if (status == TangBodyBuffer::Status::kOk) {
            tang_request.body = it->second.take();
          }
        }
        this->bodies_.erase(it);  // never leave state behind for the next request
      }
    }

    if (content_length > kTangMaxBodySize) {
      send_text(request, 413, "Payload Too Large");
      return;
    }
    if (content_length > 0) {
      if (have_buffer) {
        if (status == TangBodyBuffer::Status::kTooLarge) {
          send_text(request, 413, "Payload Too Large");
          return;
        }
        if (status != TangBodyBuffer::Status::kOk) {
          send_text(request, 400, "Bad Request: Malformed body");
          return;
        }
      } else {
#ifdef USE_ESP32
        if (!read_body_from_socket(request, &tang_request.body)) {
          send_text(request, 400,
                    "Bad Request: Failed to read body (send Content-Type: application/json or application/jwk+json, not form-urlencoded)");
          return;
        }
#else
        send_text(request, 400, "Bad Request: Body not received");
        return;
#endif
      }
    }
  } else {
    std::lock_guard<std::mutex> lock(this->body_mutex_);
    this->bodies_.erase(request);
  }

  const TangResponse response = core_context_->core.handle_request(tang_request);
  // Sensors and automations run on the main loop, not on this (httpd) task.
  parent_->post_request_event(tang_request.path, tang_request.method, response.status);
  send_response(request, response);
}

bool TangHttpHandler::isRequestHandlerTrivial() const { return false; }

}  // namespace tang_server
}  // namespace esphome
