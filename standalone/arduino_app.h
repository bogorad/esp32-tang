#pragma once

class TangStandaloneApp {
 public:
  void setup();
  void loop();

 private:
  enum WifiMode {
    TANG_WIFI_STA,
    TANG_WIFI_AP,
  };

  void handle_serial_commands();
  void handle_wifi_fallback();
  bool wipe_configuration();
  void startAPMode();
  void startSTAMode();

  static constexpr unsigned long kWifiModeDurationMs = 60000;

  WifiMode current_wifi_mode_ = TANG_WIFI_STA;
  unsigned long mode_switch_timestamp_ = 0;
};
