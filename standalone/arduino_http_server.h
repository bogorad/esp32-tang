#pragma once

#include <WebServer.h>

#include <cstdint>

#include "tang_core.h"

class TangArduinoHttpServer {
 public:
  explicit TangArduinoHttpServer(TangServerCore *core, uint16_t port = 80);

  void begin();
  void loop();

 private:
  static const char *method_to_string(HTTPMethod method);

  void register_routes();
  void handle_current_request();
  void handle_reboot();

  TangServerCore *core_;
  WebServer server_;
};
