#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "esphome/components/web_server_base/web_server_base.h"

namespace esphome {
namespace tang_server {

class TangServerComponent;

class TangHttpHandler : public AsyncWebHandler {
 public:
  explicit TangHttpHandler(TangServerComponent *parent);
  ~TangHttpHandler() override;

  bool canHandle(AsyncWebServerRequest *request) const override;
  void handleRequest(AsyncWebServerRequest *request) override;
  void handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t len,
                  size_t index, size_t total) override;
  bool isRequestHandlerTrivial() const override;

 protected:
  struct CoreContext;

  TangServerComponent *parent_;
  std::unique_ptr<CoreContext> core_context_;
};

}  // namespace tang_server
}  // namespace esphome
