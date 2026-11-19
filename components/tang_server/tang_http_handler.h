#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "esphome/components/web_server_base/web_server_base.h"
#include "tang_body_buffer.h"

namespace esphome {
namespace tang_server {

class TangServerComponent;

class TangHttpHandler : public AsyncWebHandler {
 public:
  explicit TangHttpHandler(TangServerComponent *parent);
  ~TangHttpHandler() override;

  // Main loop. Returns true when the key expired during this call.
  bool loop();
  bool ready() const;
  bool active() const;
  // False when the core is not ready.
  bool signing_thumbprint(std::string *out) const;

  bool canHandle(AsyncWebServerRequest *request) const override;
  void handleRequest(AsyncWebServerRequest *request) override;
  void handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len,
                  size_t index, size_t total) override;
  bool isRequestHandlerTrivial() const override;

 protected:
  struct CoreContext;

  TangServerComponent *parent_;
  std::unique_ptr<CoreContext> core_context_;

  // Request bodies delivered through handleBody(), keyed by request object.
  // ESPHome builds the request on the stack, so addresses are reused; each
  // TangBodyBuffer restarts at chunk index 0 and entries are erased when the
  // request completes.
  std::mutex body_mutex_;
  std::unordered_map<AsyncWebServerRequest *, TangBodyBuffer> bodies_;
};

}  // namespace tang_server
}  // namespace esphome
