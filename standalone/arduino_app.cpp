#include "arduino_app.h"

#include <Arduino.h>
#include <WiFi.h>

#include <cstdint>
#include <cstring>

#include "arduino_http_server.h"
#include "eeprom_tang_storage.h"
#include "sdkconfig.h"
#include "tang_platform.h"

namespace {

constexpr const char *kWifiSsid = CONFIG_WIFI_SSID;
constexpr const char *kWifiPassword = CONFIG_WIFI_PASSWORD;
constexpr const char *kInitialTangPassword = CONFIG_INITIAL_TANG_PASSWORD;
constexpr const char *kSetupApName = "Tang-Server-Setup";

class ArduinoTangClock : public TangClock {
 public:
  uint32_t millis() const override { return ::millis(); }
};

class ArduinoTangLogger : public TangLogger {
 public:
  void debug(const char *message) override { Serial.println(message); }
  void warn(const char *message) override { Serial.println(message); }
};

EEPROMTangStorage storage;
ArduinoTangClock clock;
ArduinoTangLogger logger;
TangServerCore core(&storage, &clock, &logger);
TangArduinoHttpServer http_server(&core);

}  // namespace

void TangStandaloneApp::setup() {
  Serial.begin(115200);
  Serial.println("\n\nESP32 Tang Server Starting...");
  if (!core.setup(kInitialTangPassword)) {
    Serial.println("ERROR: Failed to initialize Tang core.");
  }
  startSTAMode();
  http_server.begin();
  Serial.println("HTTP server listening on port 80.");
}

void TangStandaloneApp::loop() {
  handle_serial_commands();
  handle_wifi_fallback();
  core.loop();
  http_server.loop();
}

void TangStandaloneApp::handle_serial_commands() {
  if (Serial.available() <= 0) {
    return;
  }

  String command = Serial.readStringUntil('\n');
  command.trim();
  if (!command.equalsIgnoreCase("NUKE")) {
    return;
  }

  Serial.println("!!! NUKE command received! Wiping configuration...");
  if (wipe_configuration()) {
    Serial.println("Configuration wiped. Restarting device.");
  } else {
    Serial.println("ERROR: Failed to wipe configuration!");
  }
  delay(1000);
  ESP.restart();
}

bool TangStandaloneApp::wipe_configuration() {
  return storage.wipe();
}

void TangStandaloneApp::handle_wifi_fallback() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  if (millis() - mode_switch_timestamp_ > kWifiModeDurationMs) {
    if (current_wifi_mode_ == TANG_WIFI_STA) {
      startAPMode();
    } else {
      startSTAMode();
    }
  }

  if (current_wifi_mode_ == TANG_WIFI_STA && (millis() % 2000) < 50) {
    Serial.print(".");
  }
}

void TangStandaloneApp::startAPMode() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP(kSetupApName, nullptr);
  Serial.printf("\nStarting Access Point '%s'.\n", kSetupApName);
  Serial.printf("AP IP address: %s\n", WiFi.softAPIP().toString().c_str());
  current_wifi_mode_ = TANG_WIFI_AP;
  mode_switch_timestamp_ = millis();
}

void TangStandaloneApp::startSTAMode() {
  WiFi.mode(WIFI_STA);
  if (strlen(kWifiSsid) > 0) {
    WiFi.begin(kWifiSsid, kWifiPassword);
    Serial.printf("\nConnecting to SSID: %s ", kWifiSsid);
  } else {
    Serial.println("\nNo WiFi SSID configured. Skipping connection attempt.");
  }
  current_wifi_mode_ = TANG_WIFI_STA;
  mode_switch_timestamp_ = millis();
}
