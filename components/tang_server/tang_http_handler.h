#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

#include "esphome/components/web_server_base/web_server_base.h"

namespace esphome {
namespace tang_server {

class TangServerComponent;

class TangHttpHandler : public AsyncWebHandler {
 public:
  explicit TangHttpHandler(TangServerComponent *parent);
  ~TangHttpHandler() override;

  void loop();
  bool canHandle(AsyncWebServerRequest *request) const override;
  void handleRequest(AsyncWebServerRequest *request) override;
  void handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len,
                  size_t index, size_t total) override;
  bool isRequestHandlerTrivial() const override;

 protected:
  struct BodyBuffer {
    std::string body;
    size_t expected_size{0};
    bool complete{false};
    bool malformed{false};
    bool too_large{false};
  };

  struct CoreContext;

  TangServerComponent *parent_;
  std::unique_ptr<CoreContext> core_context_;
  // ESPHome's ESP-IDF request type has no per-request scratch pointer, unlike
  // the Arduino request adapter, so buffered POST bodies are keyed by request.
  std::unordered_map<AsyncWebServerRequest *, BodyBuffer> body_buffers_;
};

}  // namespace tang_server
}  // namespace esphome
