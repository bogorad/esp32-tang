#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "esphome/core/automation.h"
#include "esphome/core/component.h"

namespace esphome {
namespace binary_sensor {
class BinarySensor;
}
namespace sensor {
class Sensor;
}
namespace text_sensor {
class TextSensor;
}
namespace tang_server {

class TangHttpHandler;

class TangServerComponent : public Component {
 public:
  void setup() override;
  void loop() override;
  float get_setup_priority() const override;

  void set_unattended(bool value);
  void set_seed(const std::string &value);
  void add_old_seed(const std::string &value);
  void set_initial_password(const std::string &value);
  void set_key_lifetime_ms(uint64_t ms);
  void set_reset_token(uint32_t token);
  void set_notify_requests(bool value);
  void set_active_binary_sensor(binary_sensor::BinarySensor *sensor);
  void set_request_count_sensor(sensor::Sensor *sensor);
  void set_activation_count_sensor(sensor::Sensor *sensor);
  void set_recovery_count_sensor(sensor::Sensor *sensor);
  void set_last_status_sensor(sensor::Sensor *sensor);
  void set_last_path_text_sensor(text_sensor::TextSensor *sensor);
  void set_last_method_text_sensor(text_sensor::TextSensor *sensor);
  void set_last_error_text_sensor(text_sensor::TextSensor *sensor);
  void set_signing_thumbprint_text_sensor(text_sensor::TextSensor *sensor);

  bool unattended() const;
  const std::string &seed() const;
  const std::vector<std::string> &old_seeds() const;
  const std::string &initial_password() const;
  uint64_t key_lifetime_ms() const;
  uint32_t reset_token() const;

  template<typename F> void add_on_request_callback(F &&callback) {
    this->request_callback_.add(std::forward<F>(callback));
  }
  template<typename F> void add_on_activate_callback(F &&callback) {
    this->activate_callback_.add(std::forward<F>(callback));
  }
  template<typename F> void add_on_deactivate_callback(F &&callback) {
    this->deactivate_callback_.add(std::forward<F>(callback));
  }
  template<typename F> void add_on_recovery_callback(F &&callback) {
    this->recovery_callback_.add(std::forward<F>(callback));
  }

  // Thread-safe. Called from the httpd task after a request was handled; the
  // sensors and automations run later on the main loop (see loop()).
  void post_request_event(const std::string &path, const std::string &method, int status);

 protected:
  struct RequestEvent {
    std::string path;
    std::string method;
    int status;
  };

  // Main loop only.
  void fire_request(const std::string &path, const std::string &method, int status);
  void fire_activate(bool success);
  void fire_deactivate();
  void fire_recovery(bool success);
  void process_event_(const RequestEvent &event);

  bool unattended_{false};
  std::string seed_;
  std::vector<std::string> old_seeds_;
  std::string initial_password_;
  uint64_t key_lifetime_ms_{3600000};
  uint32_t reset_token_{0};
  bool notify_requests_{false};
  TangHttpHandler *handler_{nullptr};

  uint32_t request_count_{0};
  uint32_t activation_count_{0};
  uint32_t recovery_count_{0};
  binary_sensor::BinarySensor *active_binary_sensor_{nullptr};
  sensor::Sensor *request_count_sensor_{nullptr};
  sensor::Sensor *activation_count_sensor_{nullptr};
  sensor::Sensor *recovery_count_sensor_{nullptr};
  sensor::Sensor *last_status_sensor_{nullptr};
  text_sensor::TextSensor *last_path_text_sensor_{nullptr};
  text_sensor::TextSensor *last_method_text_sensor_{nullptr};
  text_sensor::TextSensor *last_error_text_sensor_{nullptr};
  text_sensor::TextSensor *signing_thumbprint_text_sensor_{nullptr};
  CallbackManager<void(std::string, std::string, int)> request_callback_;
  CallbackManager<void(bool)> activate_callback_;
  CallbackManager<void()> deactivate_callback_;
  CallbackManager<void(bool)> recovery_callback_;

  std::mutex event_mutex_;
  std::deque<RequestEvent> events_;
};

}  // namespace tang_server
}  // namespace esphome
