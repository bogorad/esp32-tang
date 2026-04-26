#include "tang_http_handler.h"

#ifdef USE_ESP32
#include <esp_http_server.h>
#endif

#include <cstring>
#include <string>

#include "tang_server.h"
#include "tang_core.h"

namespace esphome {
namespace tang_server {

namespace {

constexpr size_t kMaxTangBodySize = 4096;

struct BodyBuffer {
  std::string body;
  size_t expected_size{0};
  bool complete{false};
  bool malformed{false};
  bool too_large{false};
};

class InMemoryTangStorage : public TangStorage {
 public:
  bool is_initialized() override { return initialized_; }

  bool load_admin_private_key(uint8_t out[32]) override {
    if (!initialized_) {
      return false;
    }
    std::memcpy(out, admin_private_key_, sizeof(admin_private_key_));
    return true;
  }

  bool save_admin_private_key(const uint8_t key[32]) override {
    std::memcpy(admin_private_key_, key, sizeof(admin_private_key_));
    return true;
  }

  bool load_tang_key_record(TangEncryptedKeyRecord *out) override {
    if (!record_saved_ || out == nullptr) {
      return false;
    }
    *out = record_;
    return true;
  }

  bool save_tang_key_record(const TangEncryptedKeyRecord &record) override {
    record_ = record;
    record_saved_ = true;
    return true;
  }

  bool mark_initialized() override {
    initialized_ = true;
    return true;
  }

  bool wipe() override {
    initialized_ = false;
    record_saved_ = false;
    std::memset(admin_private_key_, 0, sizeof(admin_private_key_));
    std::memset(&record_, 0, sizeof(record_));
    return true;
  }

 private:
  bool initialized_{false};
  bool record_saved_{false};
  uint8_t admin_private_key_[32]{0};
  TangEncryptedKeyRecord record_{};
};

class StaticTangClock : public TangClock {
 public:
  uint32_t millis() const override { return 0; }
};

class NoopTangLogger : public TangLogger {
 public:
  void debug(const char *message) override { (void)message; }
  void warn(const char *message) override { (void)message; }
};

template<typename T> std::string to_std_string(const T &value) { return std::string(value.c_str()); }

std::string to_std_string(const char *value) { return value == nullptr ? "" : std::string(value); }

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

#ifdef USE_ESP32
bool collect_body(AsyncWebServerRequest *request, std::string *body) {
  if (body == nullptr) {
    return false;
  }

  const size_t total = request->contentLength();
  if (total > kMaxTangBodySize) {
    send_text(request, 413, "Payload Too Large");
    return false;
  }

  body->clear();
  body->reserve(total);

  char chunk[256];
  size_t remaining = total;
  while (remaining > 0) {
    const size_t chunk_size = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
    const int received = httpd_req_recv(*request, chunk, chunk_size);
    if (received <= 0) {
      body->clear();
      send_text(request, 400, "Bad Request: Failed to read body");
      return false;
    }
    body->append(chunk, received);
    remaining -= static_cast<size_t>(received);
  }

  return true;
}
#else
BodyBuffer *body_buffer(AsyncWebServerRequest *request) {
  return static_cast<BodyBuffer *>(request->_tempObject);
}

BodyBuffer *ensure_body_buffer(AsyncWebServerRequest *request, size_t total) {
  BodyBuffer *buffer = body_buffer(request);
  if (buffer == nullptr) {
    buffer = new BodyBuffer();
    request->_tempObject = buffer;
  }

  if (buffer->expected_size == 0) {
    buffer->expected_size = total;
  }
  return buffer;
}

void clear_body_buffer(AsyncWebServerRequest *request) {
  BodyBuffer *buffer = body_buffer(request);
  delete buffer;
  request->_tempObject = nullptr;
}
#endif

}  // namespace

struct TangHttpHandler::CoreContext {
  explicit CoreContext(const std::string &initial_password)
      : core(&storage, &clock, &logger),
        ready(core.setup(initial_password.c_str())) {}

  InMemoryTangStorage storage;
  StaticTangClock clock;
  NoopTangLogger logger;
  TangServerCore core;
  bool ready;
};

TangHttpHandler::TangHttpHandler(TangServerComponent *parent)
    : parent_(parent),
      core_context_(new CoreContext(parent == nullptr ? "" : parent->initial_password())) {}

TangHttpHandler::~TangHttpHandler() = default;

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
#ifdef USE_ESP32
    if (!collect_body(request, &tang_request.body)) {
      return;
    }
#else
    if (request->contentLength() == 0) {
      tang_request.body.clear();
    } else {
      BodyBuffer *buffer = body_buffer(request);
      if (request->contentLength() > kMaxTangBodySize || (buffer != nullptr && buffer->too_large)) {
        clear_body_buffer(request);
        send_text(request, 413, "Payload Too Large");
        return;
      }
      if (buffer == nullptr || buffer->malformed || !buffer->complete ||
          buffer->body.size() != request->contentLength()) {
        clear_body_buffer(request);
        send_text(request, 400, "Bad Request: Malformed body");
        return;
      }
      tang_request.body.swap(buffer->body);
      clear_body_buffer(request);
    }
#endif
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
#ifdef USE_ESP32
  (void)request;
  (void)data;
  (void)len;
  (void)index;
  (void)total;
#else
  const std::string path = request_path(request);
  if (!is_post_request(request) || !is_buffered_body_path(path)) {
    return;
  }

  BodyBuffer *buffer = ensure_body_buffer(request, total);
  if (total > kMaxTangBodySize || index + len > kMaxTangBodySize) {
    buffer->too_large = true;
    buffer->body.clear();
    return;
  }
  if ((data == nullptr && len > 0) || index != buffer->body.size() || index + len > total ||
      buffer->expected_size != total) {
    buffer->malformed = true;
    buffer->body.clear();
    return;
  }

  buffer->body.append(reinterpret_cast<const char *>(data), len);
  buffer->complete = index + len == total;
#endif
}

bool TangHttpHandler::isRequestHandlerTrivial() const { return false; }

}  // namespace tang_server
}  // namespace esphome
