#include "arduino_http_server.h"

#include <Arduino.h>

#include "tang_request.h"
#include "tang_response.h"

TangArduinoHttpServer::TangArduinoHttpServer(TangServerCore *core,
                                             uint16_t port)
    : core_(core), server_(port) {}

void TangArduinoHttpServer::begin() {
  register_routes();
  server_.begin();
}

void TangArduinoHttpServer::loop() { server_.handleClient(); }

const char *TangArduinoHttpServer::method_to_string(HTTPMethod method) {
  switch (method) {
    case HTTP_GET:
      return "GET";
    case HTTP_POST:
      return "POST";
    case HTTP_PUT:
      return "PUT";
    case HTTP_PATCH:
      return "PATCH";
    case HTTP_DELETE:
      return "DELETE";
    case HTTP_OPTIONS:
      return "OPTIONS";
    default:
      return "";
  }
}

void TangArduinoHttpServer::register_routes() {
  server_.on("/adv", HTTP_GET,
             [this]() { handle_current_request(); });
  server_.on("/rec", HTTP_POST,
             [this]() { handle_current_request(); });
  server_.on("/pub", HTTP_GET,
             [this]() { handle_current_request(); });
  server_.on("/activate", HTTP_POST,
             [this]() { handle_current_request(); });
  server_.on("/deactivate", HTTP_GET,
             [this]() { handle_current_request(); });
  server_.on("/deactivate", HTTP_POST,
             [this]() { handle_current_request(); });
  server_.on("/reboot", HTTP_GET, [this]() { handle_reboot(); });
  server_.onNotFound([this]() { handle_current_request(); });
}

void TangArduinoHttpServer::handle_current_request() {
  if (core_ == nullptr) {
    server_.send(500, "text/plain", "Server core unavailable");
    return;
  }

  TangRequest request;
  request.method = method_to_string(server_.method());
  request.path = server_.uri().c_str();
  if (server_.hasArg("plain")) {
    request.body = server_.arg("plain").c_str();
  }

  TangResponse response = core_->handle_request(request);
  server_.send(response.status, response.content_type.c_str(),
               response.body.c_str());
}

void TangArduinoHttpServer::handle_reboot() {
  server_.send(200, "text/plain", "Rebooting...");
  delay(1000);
  ESP.restart();
}
